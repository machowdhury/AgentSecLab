"""Verification bridge between AcmeBank (container) and the trusted host-side verifier. Standard library only.

Design (no new endpoint, no Docker socket in any container, no credential in any browser or container):
  AcmeBank  --signed request file-->  artifacts/loan_desk/requests/<run_id>.json
  host verifier (docker exec splunk search, read-only, fixed bounded searches)  --signed result file-->  <run_id>.splunk.json
  AcmeBank shows SPLUNK_VERIFIED only for a result whose MAC verifies, whose nonce answers the latest request and
  whose run_id matches. Anything else is an explicit non-verified state. Integrity rests on a key file in the shared
  directory: it stops forgery by anything that cannot read it (the model, its tools, a browser); it does not defend
  against a process that can read the artifacts directory (see docs/reviews/batch4/VERIFICATION_BRIDGE.md).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path

RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_REQUEST_AGE_S = 600
HEARTBEAT_FRESH_S = 20
PENDING_TIMEOUT_S = 150
PER_RUN_MIN_INTERVAL_S = 10
GLOBAL_PER_HOUR = 120
DIR_NAME = "loan_desk"


def bridge_dir(artifacts_dir: Path | str) -> Path:
    return Path(artifacts_dir) / DIR_NAME


def read_key(d: Path) -> bytes | None:
    try:
        raw = (d / ".bridge.key").read_text(encoding="utf-8").strip()
        return bytes.fromhex(raw) if len(raw) == 64 else None
    except (OSError, ValueError):
        return None


def ensure_key(d: Path) -> bytes:
    """Host verifier only: create the key once. 0644 so the container user can read it on a bind mount."""
    d.mkdir(parents=True, exist_ok=True)
    key = read_key(d)
    if key is None:
        key = secrets.token_bytes(32)
        tmp = d / ".bridge.key.tmp"
        tmp.write_text(key.hex() + "\n", encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, d / ".bridge.key")
    return key


def sign(key: bytes, payload: dict) -> dict:
    body = {k: v for k, v in payload.items() if k != "mac"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "mac": hmac.new(key, canon, hashlib.sha256).hexdigest()}


def verify(key: bytes | None, doc: object) -> bool:
    if key is None or not isinstance(doc, dict) or not isinstance(doc.get("mac"), str):
        return False
    return hmac.compare_digest(sign(key, doc)["mac"], doc["mac"])


def _write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path) -> dict | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- AcmeBank side

def heartbeat_state(d: Path, now: float | None = None) -> str:
    key, now = read_key(d), now or time.time()
    hb = _read_json(d / "verifier.json")
    if key is None or hb is None:
        return "NOT_INSTALLED"
    if not verify(key, hb) or not isinstance(hb.get("last_seen"), (int, float)):
        return "OFFLINE"
    return "ONLINE" if 0 <= now - hb["last_seen"] <= HEARTBEAT_FRESH_S else "OFFLINE"


def request_verification(d: Path, run_id: str, now: float | None = None) -> tuple[str, dict]:
    """Write a signed request. Returns (code, detail): code in REQUESTED, RATE_LIMITED, NOT_INSTALLED, BAD_RUN."""
    now = now or time.time()
    if not RUN_ID.match(run_id):
        return "BAD_RUN", {}
    key = read_key(d)
    if key is None:
        return "NOT_INSTALLED", {}
    reqs = d / "requests"
    prev = _read_json(reqs / f"{run_id}.json")
    if prev and now - float(prev.get("requested_at", 0)) < PER_RUN_MIN_INTERVAL_S:
        return "RATE_LIMITED", {"retry_after_s": PER_RUN_MIN_INTERVAL_S}
    recent = 0
    try:
        recent = sum(1 for p in reqs.glob("*.json") if now - p.stat().st_mtime < 3600)
    except OSError:
        pass
    if recent >= GLOBAL_PER_HOUR:
        return "RATE_LIMITED", {"retry_after_s": 60}
    doc = sign(key, {"run_id": run_id, "requested_at": now, "nonce": secrets.token_hex(8)})
    _write_json(reqs / f"{run_id}.json", doc)
    return "REQUESTED", {"nonce": doc["nonce"]}


def splunk_status(d: Path, run_id: str, local_count: int, now: float | None = None) -> dict:
    """The only place a SPLUNK_* status is decided on the AcmeBank side."""
    now, key = now or time.time(), read_key(d)
    hb = heartbeat_state(d, now)
    req = _read_json(d / "requests" / f"{run_id}.json")
    res = _read_json(d / f"{run_id}.splunk.json")
    base = {"verifier": hb}
    req_ok = req is not None and verify(key, req)
    if res is not None:
        if not verify(key, res) or res.get("run_id") != run_id:
            return {**base, "status": "INVALID_RECORD", "detail": "A reconciliation record failed authentication and was ignored."}
        if req_ok and res.get("nonce") == req.get("nonce"):
            info = {"indexed_events": res.get("indexed_events"), "local_events": res.get("local_events"),
                    "checked_at": res.get("checked_at"), "problems": res.get("problems", [])}
            if res.get("error"):
                return {**base, **info, "status": "VERIFICATION_FAILED", "detail": f"The host check could not complete: {res['error']}"}
            if res.get("reconciled") is not True:
                return {**base, **info, "status": "SPLUNK_MISMATCH"}
            if res.get("local_events") != local_count:
                return {**base, **info, "status": "STALE", "detail": "The run has more or fewer events than when it was checked."}
            return {**base, **info, "status": "SPLUNK_VERIFIED"}
        if not req_ok:
            return {**base, "status": "NOT_VERIFIED", "detail": "The record answers no current request from this lab."}
        # an authentic newer request is waiting: an older answer must not be shown as the current state
    if req is not None and verify(key, req):
        age = now - float(req.get("requested_at", 0))
        if age <= PENDING_TIMEOUT_S and hb == "ONLINE":
            return {**base, "status": "PENDING", "detail": "Waiting for the host verifier."}
        return {**base, "status": "TIMED_OUT" if hb == "ONLINE" else "VERIFIER_OFFLINE",
                "detail": "The host verifier did not answer in time." if hb == "ONLINE" else "The host verifier is not running."}
    if hb in ("NOT_INSTALLED", "OFFLINE"):
        return {**base, "status": "NOT_VERIFIED", "detail": "No host verifier is running, so nothing can confirm indexing."}
    return {**base, "status": "NOT_VERIFIED", "detail": "Not requested yet."}
