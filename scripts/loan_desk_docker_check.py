#!/usr/bin/env python3
"""Before/after check against the DOCKER AcmeBank (real model, real collector, real Splunk), N runs per cell.

Every run is reconciled against Splunk (read-only, host docker exec). Nothing is simulated.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.loan_desk.reconcile import wait_and_reconcile  # noqa: E402
from agentsec.mission_loan_desk import ATTACK_NOTES, DEFAULT_APPLICATION, NORMAL_NOTES  # noqa: E402


def run_one(origin: str, notes: str, posture: str) -> dict:
    body = {**DEFAULT_APPLICATION, "notes": notes, "posture": posture}
    r = requests.post(f"{origin}/api/v1/loan-desk/applications", json=body, timeout=15)
    r.raise_for_status()
    rid = r.json()["run_id"]
    t0 = time.monotonic()
    while time.monotonic() - t0 < 240:
        v = requests.get(f"{origin}/api/v1/loan-desk/runs/{rid}", timeout=15).json()
        if v["status"] != "RUNNING":
            return v
        time.sleep(1)
    raise TimeoutError(rid)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--origin", default="http://127.0.0.1:5000")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out", default="docs/reviews/batch3/docker_before_after.json")
    a = ap.parse_args()
    res = {"origin": a.origin, "runs_per_cell": a.runs, "cells": {}}
    status = requests.get(f"{a.origin}/api/v1/loan-desk/status", timeout=10).json()
    res["model"] = status["identity"]
    all_ok = True
    for posture in ("baseline", "hardened"):
        for kind, notes in (("attack", ATTACK_NOTES), ("benign", NORMAL_NOTES)):
            rows = []
            for _ in range(a.runs):
                v = run_one(a.origin, notes, posture)
                events = [json.loads(x) for x in requests.get(f"{a.origin}/api/v1/loan-desk/runs/{v['run_id']}/events.ndjson", timeout=15).text.splitlines()]
                rec = wait_and_reconcile(v["run_id"], events, timeout_s=120)
                all_ok &= rec["reconciled"]
                rows.append({"run_id": v["run_id"], "status": v["status"], "harm": bool(v["queue_harm"]["tickets_with_applicant_text"]),
                             "note": v["tickets"][0]["note"][:80] if v["tickets"] else None,
                             "security": v["outcomes"]["security"]["outcome"], "local": rec["local_events"], "indexed": rec["indexed_events"],
                             "reconciled": rec["reconciled"], "problems": rec["problems"]})
                print(posture, kind, rows[-1]["status"], "HARM" if rows[-1]["harm"] else "-", f"{rec['indexed_events']}/{rec['local_events']}", flush=True)
            res["cells"][f"{posture}/{kind}"] = {"runs": len(rows), "completed": sum(r["status"] == "COMPLETED" for r in rows),
                                                 "harm": sum(r["harm"] for r in rows), "reconciled": sum(r["reconciled"] for r in rows), "rows": rows}
    res["all_runs_reconciled"] = all_ok
    (ROOT / a.out).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    for k, c in res["cells"].items():
        print(f"{k:18} completed {c['completed']}/{c['runs']} harm {c['harm']} reconciled {c['reconciled']}/{c['runs']}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
