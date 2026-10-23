"""Host-side Loan Desk evidence verifier. Runs on the host (not in a container). Standard library only.

Least privilege: it (1) reads request files that pass a strict shape check, (2) fetches that run's own events from
AcmeBank, (3) runs the fixed, run-id-bound, read-only Splunk searches in reconcile.py through the existing
`docker exec splunk search` mechanism, (4) writes a receipt into receipts/ (a read-only mount inside the lab
containers). It opens no port and holds no Splunk credential. Requests are untrusted input: a bad one is quarantined
and logged, never fatal. Only one verifier runs per state directory (an exclusive lock).
"""

from __future__ import annotations

import collections
import json
import os
import signal
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from agentsec.loan_desk import verify_bridge as vb
from agentsec.loan_desk import search as srch
from agentsec.loan_desk.reconcile import wait_and_reconcile

VERSION = "2"
MAX_SEEN = 1024
MAX_QUARANTINE = 50
SCOPE = "consistency between the events AcmeBank reported for this run and the events Splunk indexed; not proof the events are true"


def log(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}", flush=True)


def fetch_events(origin: str, run_id: str, timeout: int = 10) -> list[dict] | None:
    try:
        with urllib.request.urlopen(f"{origin}/api/v1/loan-desk/runs/{run_id}/events.ndjson", timeout=timeout) as r:
            return [json.loads(x) for x in r.read().decode().splitlines() if x.strip()]
    except urllib.error.HTTPError as exc:
        return None if exc.code == 404 else []
    except (urllib.error.URLError, OSError, ValueError):
        return []


def heartbeat(d: Path, key: bytes, pid: int, now: float | None = None, state: str = "running") -> None:
    vb.write_json_atomic(d / vb.RECEIPTS / "verifier.json",
                         vb.sign(key, {"pid": pid, "version": VERSION, "state": state, "last_seen": now or time.time()}))


def quarantine(d: Path, path: Path, reason: str) -> None:
    """Move a request we will not process out of the way (bounded), so it cannot be retried every 2 s forever."""
    q = d / "rejected"
    try:
        q.mkdir(exist_ok=True)
        if len(list(q.iterdir())) < MAX_QUARANTINE:
            os.replace(path, q / f"{int(time.time())}-{path.name}")
        else:
            path.unlink()
    except OSError:
        pass
    log(f"rejected request {path.name}: {reason}")


def _answer(req: dict, events: list[dict] | None, reconcile: Callable, now: float) -> dict:
    run_id = req["run_id"]
    if events is None:
        out = {"reconciled": False, "problems": ["unknown_run"], "local_events": 0, "indexed_events": 0}
    elif not events:
        out = {"reconciled": False, "problems": ["local_events_unavailable"], "local_events": 0, "indexed_events": 0,
               "error": "AcmeBank did not return the run's events"}
    else:
        try:
            out = reconcile(run_id, events, timeout_s=45)
        except Exception as exc:  # noqa: BLE001 - any failure is reported, never turned into success
            out = {"reconciled": False, "problems": ["verifier_error"], "local_events": len(events), "indexed_events": 0,
                   "error": type(exc).__name__}
    keep = ("reconciled", "problems", "local_events", "indexed_events", "distinct_sequences", "checked_at", "method", "error")
    doc = {k: out[k] for k in keep if k in out}
    if doc.get("error") and "splunk" in str(doc["error"]).lower():
        doc["reconciled"] = False
    doc.update(run_id=run_id, nonce=req["nonce"], request_digest=vb.digest(req), answered_at=now, verifier_version=VERSION,
               scope=SCOPE, evidence_digest_local=vb.digest(out.get("by_event_local")),
               evidence_digest_indexed=vb.digest(out.get("by_event_indexed")))
    return doc


def process_once(d: Path, key: bytes, *, origin: str, now: float | None = None,
                 fetch: Callable = fetch_events, reconcile: Callable = wait_and_reconcile,
                 seen: "collections.OrderedDict | None" = None, budget: dict | None = None) -> list[str]:
    """Handle every pending, valid, fresh request. Never raises for a bad request. Returns the run ids it answered."""
    now = now or time.time()
    seen = seen if seen is not None else collections.OrderedDict()
    budget = budget if budget is not None else {"window_start": now, "count": 0}
    if now - budget["window_start"] > 60:
        budget.update(window_start=now, count=0)
    answered = []
    rdir = d / vb.REQUESTS
    try:
        paths = sorted(rdir.glob("*.json")) if rdir.is_dir() else []
    except OSError:
        return answered
    for path in paths:
        try:
            run_id = path.stem
            req = vb.valid_request(vb.read_json_safe(path), run_id)
            if req is None:
                quarantine(d, path, "malformed, oversized, not a regular file, or run id mismatch")
                continue
            age = now - req["requested_at"]
            if age < 0 or age > vb.MAX_REQUEST_AGE_S:
                continue
            res = vb.read_json_safe(d / vb.RECEIPTS / f"{run_id}.splunk.json")
            if res and res.get("nonce") == req["nonce"]:
                continue  # already answered
            if req["nonce"] in seen or budget["count"] >= 30:
                continue  # bounded: at most 30 searches a minute, one per request
            seen[req["nonce"]] = now
            while len(seen) > MAX_SEEN:
                seen.popitem(last=False)
            budget["count"] += 1
            doc = _answer(req, fetch(origin, run_id), reconcile, now)
            vb.write_json_atomic(d / vb.RECEIPTS / f"{run_id}.splunk.json", vb.sign(key, doc))
            answered.append(run_id)
        except Exception as exc:  # noqa: BLE001 - one bad request must never end the loop
            log(f"error handling {path.name}: {type(exc).__name__}")
    return answered


def acquire_single_instance(state: Path):
    """Exclusive lock for this state directory. Returns the open lock file, or None when another verifier holds it."""
    import fcntl
    fh = open(state / "verifier.lock", "a+")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def process_searches(d: Path, key: bytes, *, backend=None, now: float | None = None, budget: dict | None = None, tick: Callable[[], None] | None = None) -> list[str]:
    """Answer pending notebook searches. The request is untrusted: template and params are re-validated and the SPL is built here."""
    now = now or time.time()
    backend = backend or srch.DockerExecBackend()
    budget = budget if budget is not None else {"window_start": now, "count": 0}
    if now - budget["window_start"] > 60:
        budget.update(window_start=now, count=0)
    sdir, out = d / vb.REQUESTS / vb.SEARCH_SUBDIR, d / vb.RECEIPTS / vb.SEARCH_SUBDIR
    try:
        paths = sorted(sdir.glob("*.json")) if sdir.is_dir() else []
    except OSError:
        return []
    answered = []
    for path in paths:
        try:
            req = vb.valid_search_request(vb.read_json_safe(path), path.stem)
            if req is None:
                quarantine(d, path, "malformed search request")
                continue
            age = now - req["requested_at"]
            if age < 0 or age > vb.SEARCH_PENDING_TIMEOUT_S * 2 or (out / path.name).exists():
                continue
            if budget["count"] >= 60:
                continue  # bounded: at most 60 notebook searches a minute
            budget["count"] += 1
            if tick:
                tick()  # a 30 s search must not let the heartbeat go stale
            doc = {"run_id": req["run_id"], "search_id": req["search_id"], "template": req["template"], "checked_at": now, "compare_run_id": req["compare_run_id"],
                   "backend": backend.name, "row_cap": srch.MAX_ROWS}
            try:
                tpl = srch.get_template(req["template"])
                spl, clean = tpl.build(req["run_id"], req["params"], req["compare_run_id"])
            except srch.SearchError as exc:
                doc.update(ok=False, error="refused", detail=str(exc)[:200], params={}, spl="")
            else:
                oc = backend.run(spl, timeout_s=srch.SEARCH_TIMEOUT_S, max_rows=srch.MAX_ROWS)
                doc.update(params=clean, spl=spl, ok=oc.ok, columns=oc.columns, rows=oc.rows, truncated=oc.truncated, error=oc.error, duration_ms=oc.duration_ms)
            vb.write_json_atomic(out / path.name, vb.sign(key, doc))
            answered.append(path.stem)
        except Exception as exc:  # noqa: BLE001 - one bad request must never end the loop
            log(f"error handling search {path.name}: {type(exc).__name__}")
    return answered


def run_forever(d: Path, *, origin: str, state: Path, interval: float = 2.0) -> int:
    lock = acquire_single_instance(state)
    if lock is None:
        log("another verifier already holds the lock; exiting")
        return 0
    pid = os.getpid()
    (state / "verifier.pid").write_text(str(pid), encoding="utf-8")
    key = vb.load_or_create_key(state)
    (d / vb.RECEIPTS).mkdir(parents=True, exist_ok=True)
    (d / vb.REQUESTS).mkdir(parents=True, exist_ok=True)
    stop = {"now": False}
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.update(now=True))
    seen, budget, sbudget = collections.OrderedDict(), {"window_start": time.time(), "count": 0}, {"window_start": time.time(), "count": 0}
    log(f"verifier {VERSION} started pid={pid}")
    while not stop["now"]:
        try:
            heartbeat(d, key, pid)
            process_once(d, key, origin=origin, seen=seen, budget=budget)
            process_searches(d, key, budget=sbudget, tick=lambda: heartbeat(d, key, pid))
        except Exception as exc:  # noqa: BLE001
            log(f"loop error {type(exc).__name__}; continuing")
        t = 0.0
        while t < interval and not stop["now"]:
            time.sleep(0.2)
            t += 0.2
    try:
        heartbeat(d, key, pid, state="stopped")
        (state / "verifier.pid").unlink()
    except OSError:
        pass
    log("verifier stopped cleanly")
    return 0


def check_receipt(path: Path, key: bytes) -> tuple[bool, str]:
    """Host-side audit of a receipt at rest: HMAC and shape. Says nothing about whether the events are true."""
    doc = vb.read_json_safe(path, max_bytes=65536)
    if doc is None:
        return False, "unreadable or not a regular JSON file"
    if not vb.verify(key, doc):
        return False, "MAC does not verify (not written by this host's verifier, or modified)"
    return True, f"receipt authentic; reconciled={doc.get('reconciled')}; scope: {doc.get('scope')}"
