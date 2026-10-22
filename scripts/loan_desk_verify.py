#!/usr/bin/env python3
"""Host-side Splunk reconciliation for Loan Desk runs. Read-only against Splunk.

  python scripts/loan_desk_verify.py <run_id> [<run_id> ...] [--origin http://127.0.0.1:5000]

Manual, read-only reconciliation printout. It writes nothing. The page's "Verify with Splunk" button uses the
signed bridge instead (scripts/loan_desk_verifier.sh), so a record can only come from the running verifier.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agentsec.loan_desk.reconcile import UUID, wait_and_reconcile  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_ids", nargs="+")
    ap.add_argument("--origin", default="http://127.0.0.1:5000")
    ap.add_argument("--timeout", type=int, default=150)
    a = ap.parse_args()
    bad = 0
    for rid in a.run_ids:
        if not UUID.match(rid):
            print(f"skip {rid}: not a run id", file=sys.stderr)
            bad += 1
            continue
        r = requests.get(f"{a.origin}/api/v1/loan-desk/runs/{rid}/events.ndjson", timeout=10)
        r.raise_for_status()
        local = [json.loads(x) for x in r.text.splitlines() if x.strip()]
        res = wait_and_reconcile(rid, local, timeout_s=a.timeout)
        print(json.dumps(res, indent=2))
        bad += 0 if res["reconciled"] else 1
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
