#!/usr/bin/env python3
"""Launch every LIVE Attack Service specimen once and reconcile each run against Splunk (read-only searches).

Evidence source for the Batch 5 coverage matrix: a lab is VERIFIED LIVE here only if the launch succeeded AND Splunk
holds the events the launch reported. Nothing is retried, no config changes. Uses the lab's own public /api/launch.
"""
from __future__ import annotations
import argparse, json, sys, time, urllib.error, urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.experiment_context import EXPERIMENT_DEFINITIONS as DEFS  # noqa: E402
from agentsec.loan_desk.reconcile import BASE, run_spl  # noqa: E402

def post(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=240) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {"error": "unparseable"}
    except Exception as e:  # noqa: BLE001
        return 0, {"error": type(e).__name__}

def find(o, keys):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in keys and isinstance(v, (str, int)): return v
            r = find(v, keys)
            if r is not None: return r
    elif isinstance(o, list):
        for v in o:
            r = find(v, keys)
            if r is not None: return r

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--attack", default="http://127.0.0.1:5001"); ap.add_argument("--out", required=True)
    a = ap.parse_args(); rows = []
    for d in DEFS:
        t = time.time()
        st, body = post(f"{a.attack}/api/launch", {"lab_id": d.lab_id, "specimen_id": d.specimen_id, "mode": d.mode, "execution": "live"})
        run = find(body, {"run_id", "agentsec.run.id"})
        row = {"lab": d.lab_id, "specimen": d.specimen_id, "mode": d.mode, "http": st, "seconds": round(time.time() - t, 1), "run_id": run,
               "evidence_state": find(body, {"evidence_state"}), "reported_events": find(body, {"event_count", "events_emitted", "local_events", "events"}),
               "error": find(body, {"error", "error_class", "detail"}) if st != 200 else None}
        rows.append(row); print(row, flush=True)
    time.sleep(20)
    for r in rows:
        if not r["run_id"]: continue
        try:
            q = run_spl(BASE.replace("earliest=-24h", "earliest=-2h").format(run=r["run_id"]) + " | stats count AS indexed dc(agentsec.sequence) AS seqs")
            r["indexed"] = int(q[0]["indexed"]) if q else 0; r["distinct_sequences"] = int(q[0]["seqs"]) if q else 0
        except Exception as e:  # noqa: BLE001
            r["indexed_error"] = str(e)[:80]
        print(r["lab"], r["mode"], r.get("indexed"), flush=True)
    Path(a.out).write_text(json.dumps(rows, indent=1) + "\n")
main()
