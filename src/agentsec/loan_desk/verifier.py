"""Host-side verifier loop. Runs on the host (not in a container). Standard library only.

Least privilege: it only (1) reads signed request files, (2) fetches that run's own events from AcmeBank, (3) runs
the fixed, run-id-bound, read-only Splunk searches in reconcile.py through the existing `docker exec splunk search`
mechanism, (4) writes a signed result. It opens no port and accepts no input except request files whose MAC verifies.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from agentsec.loan_desk import verify_bridge as vb
from agentsec.loan_desk.reconcile import wait_and_reconcile

VERSION = "1"


def fetch_events(origin: str, run_id: str, timeout: int = 10) -> list[dict] | None:
    try:
        with urllib.request.urlopen(f"{origin}/api/v1/loan-desk/runs/{run_id}/events.ndjson", timeout=timeout) as r:
            return [json.loads(x) for x in r.read().decode().splitlines() if x.strip()]
    except urllib.error.HTTPError as exc:
        return None if exc.code == 404 else []
    except (urllib.error.URLError, OSError, ValueError):
        return []


def heartbeat(d: Path, key: bytes, pid: int, now: float | None = None) -> None:
    vb._write_json(d / "verifier.json", vb.sign(key, {"pid": pid, "version": VERSION, "last_seen": now or time.time()}))


def process_once(d: Path, key: bytes, *, origin: str, now: float | None = None,
                 fetch: Callable = fetch_events, reconcile: Callable = wait_and_reconcile,
                 seen: dict | None = None, budget: dict | None = None) -> list[str]:
    """Handle every pending, authentic, fresh request. Returns the run ids it answered."""
    now = now or time.time()
    seen = seen if seen is not None else {}
    budget = budget if budget is not None else {"window_start": now, "count": 0}
    if now - budget["window_start"] > 60:
        budget.update(window_start=now, count=0)
    answered = []
    for path in sorted((d / "requests").glob("*.json")) if (d / "requests").is_dir() else []:
        req = vb._read_json(path)
        run_id = path.stem
        if not vb.RUN_ID.match(run_id) or not vb.verify(key, req) or req.get("run_id") != run_id:
            continue  # unauthenticated or mismatched: ignored, never answered
        age = now - float(req.get("requested_at", 0))
        if age < 0 or age > vb.MAX_REQUEST_AGE_S:
            continue
        res = vb._read_json(d / f"{run_id}.splunk.json")
        if res and res.get("nonce") == req["nonce"]:
            continue  # already answered
        if seen.get(req["nonce"]) or budget["count"] >= 30:
            continue  # bounded: at most 30 searches a minute, one per request
        seen[req["nonce"]] = now
        budget["count"] += 1
        events = fetch(origin, run_id)
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
        doc.update(run_id=run_id, nonce=req["nonce"], answered_at=now)
        vb._write_json(d / f"{run_id}.splunk.json", vb.sign(key, doc))
        answered.append(run_id)
    return answered


def run_forever(d: Path, *, origin: str, pid: int, interval: float = 2.0) -> None:  # pragma: no cover - loop
    key = vb.ensure_key(d)
    seen: dict = {}
    budget = {"window_start": time.time(), "count": 0}
    while True:
        heartbeat(d, key, pid)
        process_once(d, key, origin=origin, seen=seen, budget=budget)
        time.sleep(interval)
