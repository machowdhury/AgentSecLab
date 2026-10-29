"""Server-side CTF state: key, attempt records and the one-time consumption ledger.

All of it lives in one host directory (0700): files are 0600, written atomically, read without following symlinks, bounded in
size and count. No path ever contains caller input except an id that has already matched a strict regex.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from pathlib import Path

from agentsec.loan_desk import verify_bridge as vb

ATTEMPT_ID = re.compile(r"^[A-Za-z0-9_-]{32}$")      # secrets.token_urlsafe(24): 192 bits
MAX_ATTEMPTS = 200
MAX_ATTEMPT_BYTES = 32 * 1024
MAX_LEDGER_BYTES = 1024 * 1024
MAX_LEDGER_ENTRIES = 500                 # ~1.1 KB per line, so 500 lines stay under MAX_LEDGER_BYTES; in practice <= one line per challenge
KEY_ENV, DIR_ENV = "AGENTSEC_CTF_KEY_FILE", "AGENTSEC_CTF_STATE_DIR"   # key file default: <state>/ctf.key


class StoreError(Exception):
    """Generic and secret-free: callers map it to a generic 5xx and never echo str(exc) to a client."""


def new_attempt_id() -> str:
    return secrets.token_urlsafe(24)


def state_dir() -> Path:
    base = os.environ.get(DIR_ENV)
    return Path(base) if base else Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "agentsec" / "ctf"


def _secure_dir(path: Path) -> None:
    if path.is_symlink():
        raise StoreError("state path is a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise StoreError("state path is not a directory")
    os.chmod(path, 0o700)


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"agentsec.ctf.keyid" + key).hexdigest()[:8]


class CtfStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root else state_dir()
        _secure_dir(self.root)
        self.attempts_dir = self.root / "attempts"
        _secure_dir(self.attempts_dir)
        self.ledger_path = self.root / "ledger.jsonl"
        self.key = self._load_key()

    # ---- key (never logged, never returned)
    def _load_key(self) -> bytes:
        path = Path(os.environ.get(KEY_ENV) or self.root / "ctf.key")
        if path.is_symlink():
            raise StoreError("key path is a symlink")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            # complete temp file first, then an atomic link: no reader ever sees an empty or short key; a racing creator loses cleanly
            tmp = path.with_name(f".key-{secrets.token_hex(8)}.tmp")
            tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(tfd, "w", encoding="ascii") as fh:
                fh.write(secrets.token_bytes(32).hex() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass
            finally:
                os.unlink(tmp)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 256:
                raise StoreError("key file is not a small regular file")
            if st.st_mode & 0o077:
                os.fchmod(fd, 0o600)
            raw = os.read(fd, 256).decode("ascii", "replace").strip()
        finally:
            os.close(fd)
        try:
            if len(raw) != 64:
                raise ValueError
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise StoreError("key file is malformed") from exc

    # ---- attempts
    def _attempt_path(self, attempt_id: str) -> Path:
        if not isinstance(attempt_id, str) or not ATTEMPT_ID.match(attempt_id):
            raise StoreError("bad attempt id")
        return self.attempts_dir / f"{attempt_id}.json"

    def load(self, attempt_id: str) -> dict | None:
        try:
            rec = vb.read_json_safe(self._attempt_path(attempt_id), MAX_ATTEMPT_BYTES)
        except StoreError:
            return None
        return rec if rec and rec.get("attempt_id") == attempt_id else None

    def save(self, rec: dict) -> None:
        if len(json.dumps(rec, indent=1)) > MAX_ATTEMPT_BYTES:
            raise StoreError("attempt record too large")
        vb.write_json_atomic(self._attempt_path(rec["attempt_id"]), rec, mode=0o600)

    def all_attempts(self) -> list[dict]:
        try:
            paths = sorted(p for p in self.attempts_dir.iterdir() if p.suffix == ".json" and ATTEMPT_ID.match(p.stem))
        except OSError:
            return []
        recs = (vb.read_json_safe(p, MAX_ATTEMPT_BYTES) for p in paths)
        return [r for p, r in zip(paths, recs) if r and r.get("attempt_id") == p.stem]

    def make_room(self, now: int = 0, ttl: int = 3600) -> bool:
        """Bounded count. Prunes records that can never score again, oldest first: RESET, FAILED, VERIFIED but never redeemed, expired
        NEW/RUNNING, and redeemed records that awarded 0. Scoring records (at most one per challenge) are never pruned."""
        recs = self.all_attempts()
        if len(recs) < MAX_ATTEMPTS:
            return True

        def prunable(r):
            st = r.get("state")
            return (st in ("RESET", "FAILED") or (st == "VERIFIED" and not r.get("redeemed")) or (st in ("NEW", "RUNNING") and now and now - r.get("created_at", 0) > ttl)
                    or (r.get("redeemed") and r.get("awarded") == 0))

        for rec in sorted((r for r in recs if prunable(r)), key=lambda r: r.get("created_at", 0)):
            try:
                self._attempt_path(rec["attempt_id"]).unlink()
            except (OSError, StoreError):
                continue
            recs.remove(rec)
            if len(recs) < MAX_ATTEMPTS:
                return True
        return False

    # ---- ledger: append-only, flock-serialised, hash-chained, MAC'd per line
    def _entry_mac(self, body: dict) -> str:
        return vb.sign(self.key, {"typ": "agentsec.ctf.ledger", **body})["mac"]

    @property
    def head_path(self) -> Path:
        return self.root / "ledger.head"

    def _write_head(self, count: int, last: str) -> None:
        vb.write_json_atomic(self.head_path, vb.sign(self.key, {"typ": "agentsec.ctf.head", "count": count, "last": last}), mode=0o600)

    def _head_ok(self, entries: list[dict]) -> bool:
        """The MAC'd head (count + last chain hash) pins the ledger: truncation or rollback of whole lines changes it."""
        head = vb.read_json_safe(self.head_path, 2048)
        want = (len(entries), entries[-1]["mac"] if entries else "0" * 64)
        if head is None:
            return not entries          # no head is only legitimate while no valid line exists
        return (vb.verify(self.key, head) and head.get("typ") == "agentsec.ctf.head" and (head.get("count"), head.get("last")) == want)

    def read_ledger(self) -> tuple[list[dict], bool]:
        """(entries whose MAC and chain verify, intact). A bad line is dropped and intact becomes False."""
        entries, chain_ok = self._read()
        return entries, chain_ok and self._head_ok(entries)

    def _read(self) -> tuple[list[dict], bool]:
        """Chain-only read (no head check)."""
        try:
            fd = os.open(self.ledger_path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return [], True
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return [], False
            data = os.read(fd, MAX_LEDGER_BYTES + 1)
        finally:
            os.close(fd)
        entries, intact, prev = [], len(data) <= MAX_LEDGER_BYTES, "0" * 64
        for line in data[:MAX_LEDGER_BYTES].decode("utf-8", "replace").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                intact = False
                continue
            mac = e.pop("mac", None) if isinstance(e, dict) else None
            if not isinstance(mac, str) or e.get("prev") != prev or not hmac.compare_digest(self._entry_mac(e), mac):
                intact = False
                continue
            prev = mac
            entries.append({**e, "mac": mac})
        return entries, intact

    def consume(self, receipt: dict, *, now: int) -> tuple[str, dict | None]:
        """Atomically spend a receipt: ('OK', entry) | ('REPLAY', None) | ('FULL', None). Check and append share one flock."""
        fd = os.open(self.ledger_path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            entries, chain_ok = self._read()
            if chain_ok and entries and not self._head_ok(entries):
                # crash between append and head write leaves the head exactly one entry behind a fully valid chain: heal it here, under the lock
                head = vb.read_json_safe(self.head_path, 2048)
                behind = (head is None and len(entries) == 1) or (
                    head is not None and vb.verify(self.key, head) and head.get("typ") == "agentsec.ctf.head" and head.get("count") == len(entries) - 1
                    and head.get("last") == (entries[-2]["mac"] if len(entries) > 1 else "0" * 64))
                if behind:
                    self._write_head(len(entries), entries[-1]["mac"])
            if not (chain_ok and self._head_ok(entries)):
                return "CORRUPT", None
            if len(entries) >= MAX_LEDGER_ENTRIES:
                return "FULL", None
            if any(e["receipt"]["nonce"] == receipt["nonce"] or e["receipt"]["attempt_id"] == receipt["attempt_id"] for e in entries):
                return "REPLAY", next(e for e in entries if e["receipt"]["nonce"] == receipt["nonce"] or e["receipt"]["attempt_id"] == receipt["attempt_id"])
            first = not any(e["receipt"]["challenge_id"] == receipt["challenge_id"] and e["receipt"]["participant"] == receipt["participant"]
                            for e in entries)
            if not first:        # history only: the attempt is marked redeemed in its record; nothing to append, so the ledger stays small
                return "OK", {"awarded": 0, "seq": None}
            body = {"seq": len(entries) + 1, "prev": entries[-1]["mac"] if entries else "0" * 64, "consumed_at": now,
                    "receipt": receipt, "awarded": receipt["points"]}
            entry = {**body, "mac": self._entry_mac(body)}
            end = os.fstat(fd).st_size
            lead = b"\n" if end and os.pread(fd, 1, end - 1) != b"\n" else b""   # a crash that lost only the final newline must not glue two entries onto one line
            os.write(fd, lead + (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode())
            os.fsync(fd)
            self._write_head(len(entries) + 1, entry["mac"])
            return "OK", entry
        finally:
            os.close(fd)   # closing releases the flock
