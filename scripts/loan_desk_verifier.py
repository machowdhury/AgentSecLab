#!/usr/bin/env python3
"""Host-side Loan Desk evidence verifier (see src/agentsec/loan_desk/verifier.py). Needs only python3 and docker.

  loan_desk_verifier.py [--artifacts DIR] [--origin URL]     run the verifier (one per state directory)
  loan_desk_verifier.py --check RECEIPT                      audit a receipt at rest with the host key (read-only)
"""

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.loan_desk import verify_bridge as vb  # noqa: E402
from agentsec.loan_desk.verifier import check_receipt, run_forever  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--artifacts", default=str(ROOT / "artifacts"))
ap.add_argument("--origin", default=os.environ.get("ACMEBANK_ORIGIN", "http://127.0.0.1:5000"))
ap.add_argument("--check", metavar="RECEIPT")
a = ap.parse_args()
state = vb.state_dir()
if a.check:
    ok, msg = check_receipt(Path(a.check), vb.load_or_create_key(state))
    print(("AUTHENTIC: " if ok else "NOT AUTHENTIC: ") + msg)
    raise SystemExit(0 if ok else 1)
raise SystemExit(run_forever(vb.bridge_dir(a.artifacts), origin=a.origin.rstrip("/"), state=state))
