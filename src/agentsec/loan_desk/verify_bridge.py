"""Verification bridge between AcmeBank (container) and the trusted host-side verifier. Standard library only.

Trust model (v2, Batch 6). No new endpoint, no Docker socket in any container, no credential in any browser or container.

  container --(unsigned request file)--> artifacts/loan_desk/requests/<run_id>.json      container-WRITABLE
  host verifier (docker exec splunk search, fixed read-only bounded searches)
           --(receipt file)-----------> artifacts/loan_desk/receipts/<run_id>.splunk.json   container READ-ONLY mount

The container can ask; only the host can answer. Authenticity of an answer is a filesystem boundary: `receipts/` is
bind-mounted read-only into the lab containers, so nothing running there can create or alter a receipt. AcmeBank
refuses to show SPLUNK_VERIFIED unless it can see that `receipts/` is not writable from its own process.
The HMAC key lives on the host outside every mounted path (see `state_dir`); containers never see it. Receipts
carry an HMAC so a receipt at rest can be checked on the host (`scripts/loan_desk_verifier.py --check`).

Two different integrities, never conflated:
  * RECEIPT integrity: this receipt was written by the host verifier and is unchanged.
  * EVIDENCE integrity: the events themselves are true. A receipt only says "the events AcmeBank reported for this
    run are the events Splunk indexed". If AcmeBank itself were compromised it could emit false events and still earn a
    truthful receipt for them. See docs/reviews/batch6/VERIFIER_SECURITY.md.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import tempfile
import time
from pathlib import Path

RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
NONCE = re.compile(r"^[0-9a-f]{8,64}$")
MAX_REQUEST_AGE_S = 600
HEARTBEAT_FRESH_S = 20
PENDING_TIMEOUT_S = 150
PER_RUN_MIN_INTERVAL_S = 10
GLOBAL_PER_HOUR = 120
MAX_FILE_BYTES = 4096
DIR_NAME = "loan_desk"
REQUESTS, RECEIPTS = "requests", "receipts"
ISOLATION_ENV = "AGENTSEC_RECEIPTS_ISOLATION"  # "off" is for tests that run the verifier in-process; compose never sets it


def bridge_dir(artifacts_dir: Path | str) -> Path:
    return Path(artifacts_dir) / DIR_NAME


# ------------------------------------------------------------------ file primitives (shared)

def write_json_atomic(path: Path, doc: dict, mode: int = 0o644) -> None:
    """Unique temp file in the same directory, fsync, rename. Concurrent writers never share a temp name."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, indent=1) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json_safe(path: Path, max_bytes: int = MAX_FILE_BYTES) -> dict | None:
    """Regular files only (no symlinks, FIFOs or devices), bounded size, JSON object or None. Never raises."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        with os.fdopen(fd, "rb", closefd=False) as fh:
            doc = json.loads(fh.read(max_bytes + 1).decode("utf-8"))
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)


def valid_request(doc: object, run_id: str) -> dict | None:
    """Strict shape check. Returns the request normalised, or None. Any extra or mistyped field rejects it."""
    if not isinstance(doc, dict) or set(doc) != {"run_id", "requested_at", "nonce"}:
        return None
    at, nonce = doc["requested_at"], doc["nonce"]
    if doc["run_id"] != run_id or not RUN_ID.match(run_id):
        return None
    if isinstance(at, bool) or not isinstance(at, (int, float)) or not math.isfinite(at):
        return None
    if not isinstance(nonce, str) or not NONCE.match(nonce):
        return None
    return {"run_id": run_id, "requested_at": float(at), "nonce": nonce}


# ------------------------------------------------------------------ host side: key and receipts

def state_dir() -> Path:
    """Host-only directory (0700) for the key, lock, pidfile and log. Never inside a mounted path."""
    base = os.environ.get("AGENTSEC_VERIFIER_STATE_DIR")
    root = Path(base) if base else Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "agentsec" / DIR_NAME
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


def load_or_create_key(state: Path) -> bytes:
    path = state / "receipt.key"
    try:
        raw = path.read_text(encoding="utf-8").strip()
        if len(raw) == 64:
            return bytes.fromhex(raw)
    except (OSError, ValueError):
        pass
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key.hex() + "\n")
    return key


def sign(key: bytes, payload: dict) -> dict:
    body = {k: v for k, v in payload.items() if k != "mac"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "mac": hmac.new(key, canon, hashlib.sha256).hexdigest()}


def verify(key: bytes | None, doc: object) -> bool:
    if key is None or not isinstance(doc, dict) or not isinstance(doc.get("mac"), str):
        return False
    return hmac.compare_digest(sign(key, doc)["mac"], doc["mac"])


def digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ------------------------------------------------------------------ container side

def receipts_isolated(d: Path) -> bool:
    """True only when receipts/ exists and this process cannot write to it (a read-only mount, or no permission)."""
    r = d / RECEIPTS
    return r.is_dir() and not os.access(r, os.W_OK)


def _isolation_required() -> bool:
    return os.environ.get(ISOLATION_ENV, "enforce") != "off"


def heartbeat_state(d: Path, now: float | None = None) -> str:
    now = now or time.time()
    hb = read_json_safe(d / RECEIPTS / "verifier.json")
    if hb is None:
        return "NOT_INSTALLED"
    if _isolation_required() and not receipts_isolated(d):
        return "OFFLINE"
    at = hb.get("last_seen")
    if hb.get("state") != "running" or isinstance(at, bool) or not isinstance(at, (int, float)):
        return "OFFLINE"
    return "ONLINE" if 0 <= now - at <= HEARTBEAT_FRESH_S else "OFFLINE"


def request_verification(d: Path, run_id: str, now: float | None = None) -> tuple[str, dict]:
    """Write a request. Returns (code, detail): REQUESTED, RATE_LIMITED, NOT_INSTALLED, BAD_RUN."""
    now = now or time.time()
    if not RUN_ID.match(run_id):
        return "BAD_RUN", {}
    if not (d / RECEIPTS).is_dir():
        return "NOT_INSTALLED", {}
    reqs = d / REQUESTS
    prev = read_json_safe(reqs / f"{run_id}.json")
    if prev and isinstance(prev.get("requested_at"), (int, float)) and now - prev["requested_at"] < PER_RUN_MIN_INTERVAL_S:
        return "RATE_LIMITED", {"retry_after_s": PER_RUN_MIN_INTERVAL_S}
    try:
        recent = sum(1 for p in reqs.glob("*.json") if now - p.stat().st_mtime < 3600)
    except OSError:
        recent = 0
    if recent >= GLOBAL_PER_HOUR:
        return "RATE_LIMITED", {"retry_after_s": 60}
    doc = {"run_id": run_id, "requested_at": now, "nonce": secrets.token_hex(8)}
    write_json_atomic(reqs / f"{run_id}.json", doc)
    return "REQUESTED", {"nonce": doc["nonce"]}


def splunk_status(d: Path, run_id: str, local_count: int, now: float | None = None) -> dict:
    """The only place a SPLUNK_* status is decided on the AcmeBank side."""
    now = now or time.time()
    hb = heartbeat_state(d, now)
    base = {"verifier": hb}
    if _isolation_required() and (d / RECEIPTS).is_dir() and not receipts_isolated(d):
        return {**base, "status": "NOT_VERIFIED",
                "detail": "The receipts directory is writable from this container, so a receipt could be forged. "
                          "Mount artifacts/loan_desk/receipts read-only."}
    req = valid_request(read_json_safe(d / REQUESTS / f"{run_id}.json"), run_id)
    res = read_json_safe(d / RECEIPTS / f"{run_id}.splunk.json")
    if res is not None:
        if res.get("run_id") != run_id or not isinstance(res.get("nonce"), str):
            return {**base, "status": "INVALID_RECORD", "detail": "A receipt did not match this run and was ignored."}
        if req is not None and res["nonce"] == req["nonce"]:
            info = {"indexed_events": res.get("indexed_events"), "local_events": res.get("local_events"),
                    "checked_at": res.get("checked_at"), "problems": res.get("problems", [])}
            if res.get("error"):
                return {**base, **info, "status": "VERIFICATION_FAILED", "detail": f"The host check could not complete: {res['error']}"}
            if res.get("reconciled") is not True:
                return {**base, **info, "status": "SPLUNK_MISMATCH"}
            if res.get("local_events") != local_count:
                return {**base, **info, "status": "STALE", "detail": "The run has more or fewer events than when it was checked."}
            return {**base, **info, "status": "SPLUNK_VERIFIED"}
        if req is None:
            return {**base, "status": "NOT_VERIFIED", "detail": "The receipt answers no current request from this lab."}
        # a newer request is waiting: an older answer must not be shown as the current state
    if req is not None:
        age = now - req["requested_at"]
        if age <= PENDING_TIMEOUT_S and hb == "ONLINE":
            return {**base, "status": "PENDING", "detail": "Waiting for the host verifier."}
        return {**base, "status": "TIMED_OUT" if hb == "ONLINE" else "VERIFIER_OFFLINE",
                "detail": "The host verifier did not answer in time." if hb == "ONLINE" else "The host verifier is not running."}
    if hb in ("NOT_INSTALLED", "OFFLINE"):
        return {**base, "status": "NOT_VERIFIED", "detail": "No host verifier is running, so nothing can confirm indexing."}
    return {**base, "status": "NOT_VERIFIED", "detail": "Not requested yet."}


# ------------------------------------------------------------------ notebook searches (fixed templates; see search.py)

SEARCH_SUBDIR = "search"
SEARCH_ID = re.compile(r"^[0-9a-f]{16}$")
MAX_SEARCH_FILE_BYTES = 256 * 1024
SEARCH_PER_RUN_PER_MIN = 20
SEARCH_GLOBAL_PER_HOUR = 300
SEARCH_PENDING_TIMEOUT_S = 60


def valid_search_request(doc: object, search_id: str) -> dict | None:
    """Strict shape only; the verifier re-validates the template and parameters itself and builds the SPL itself."""
    if not isinstance(doc, dict) or not {"run_id", "search_id", "template", "params", "requested_at"} <= set(doc) <= {"run_id", "search_id", "template", "params", "requested_at", "compare_run_id"}:
        return None
    other = doc.get("compare_run_id")
    if other is not None and (not isinstance(other, str) or not RUN_ID.match(other)):
        return None
    at = doc["requested_at"]
    if doc["search_id"] != search_id or not SEARCH_ID.match(search_id) or not isinstance(doc["run_id"], str) or not RUN_ID.match(doc["run_id"]):
        return None
    if not isinstance(doc["template"], str) or len(doc["template"]) > 64 or not isinstance(doc["params"], dict) or len(doc["params"]) > 8:
        return None
    if isinstance(at, bool) or not isinstance(at, (int, float)) or not math.isfinite(at):
        return None
    return {"run_id": doc["run_id"], "search_id": search_id, "template": doc["template"], "params": doc["params"], "requested_at": float(at), "compare_run_id": other}


def request_search(d: Path, run_id: str, template: str, params: dict, now: float | None = None, compare_run: str | None = None) -> tuple[str, dict]:
    """Write one search request. Returns (code, detail): REQUESTED, RATE_LIMITED, NOT_INSTALLED, BAD_RUN."""
    now = now or time.time()
    if not RUN_ID.match(run_id):
        return "BAD_RUN", {}
    if not (d / RECEIPTS).is_dir():
        return "NOT_INSTALLED", {}
    sdir = d / REQUESTS / SEARCH_SUBDIR
    try:
        files = [(p, p.stat().st_mtime) for p in sdir.glob("*.json")] if sdir.is_dir() else []
    except OSError:
        files = []
    if sum(1 for _, m in files if now - m < 3600) >= SEARCH_GLOBAL_PER_HOUR:
        return "RATE_LIMITED", {"retry_after_s": 60}
    mine = sum(1 for p, m in files if now - m < 60 and (read_json_safe(p) or {}).get("run_id") == run_id)
    if mine >= SEARCH_PER_RUN_PER_MIN:
        return "RATE_LIMITED", {"retry_after_s": 10}
    search_id = secrets.token_hex(8)
    doc = {"run_id": run_id, "search_id": search_id, "template": template, "params": params, "requested_at": now}
    if compare_run:
        doc["compare_run_id"] = compare_run
    write_json_atomic(sdir / f"{search_id}.json", doc)
    return "REQUESTED", {"search_id": search_id}


def search_status(d: Path, run_id: str, search_id: str, now: float | None = None) -> dict:
    """State of one search as the AcmeBank side may report it. Receipts are trusted only because receipts/ is a read-only mount here."""
    now = now or time.time()
    if not SEARCH_ID.match(search_id) or not RUN_ID.match(run_id):
        return {"status": "UNKNOWN_SEARCH"}
    hb = heartbeat_state(d, now)
    if _isolation_required() and (d / RECEIPTS).is_dir() and not receipts_isolated(d):
        return {"status": "UNAVAILABLE", "verifier": hb, "detail": "The receipts directory is writable from this container, so a search result could be forged. Mount artifacts/loan_desk/receipts read-only."}
    req = valid_search_request(read_json_safe(d / REQUESTS / SEARCH_SUBDIR / f"{search_id}.json"), search_id)
    if req is None or req["run_id"] != run_id:
        return {"status": "UNKNOWN_SEARCH"}
    res = read_json_safe(d / RECEIPTS / SEARCH_SUBDIR / f"{search_id}.json", MAX_SEARCH_FILE_BYTES)
    if res is not None and res.get("run_id") == run_id and res.get("search_id") == search_id:
        keep = ("template", "params", "spl", "ok", "columns", "rows", "truncated", "row_cap", "duration_ms", "error", "checked_at", "backend", "compare_run_id")
        return {"status": "READY" if res.get("ok") else "FAILED", "verifier": hb, **{k: res[k] for k in keep if k in res}}
    if hb == "ONLINE" and now - req["requested_at"] <= SEARCH_PENDING_TIMEOUT_S:
        return {"status": "PENDING", "verifier": hb}
    return {"status": "TIMED_OUT" if hb == "ONLINE" else "VERIFIER_OFFLINE", "verifier": hb,
            "detail": "The host verifier did not answer in time." if hb == "ONLINE" else "The host verifier is not running."}
