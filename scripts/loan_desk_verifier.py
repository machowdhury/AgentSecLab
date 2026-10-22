#!/usr/bin/env python3
"""Host-side Loan Desk evidence verifier (see src/agentsec/loan_desk/verifier.py). Needs only python3 and docker."""

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.loan_desk.verifier import run_forever  # noqa: E402
from agentsec.loan_desk.verify_bridge import bridge_dir  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--artifacts", default=str(ROOT / "artifacts"))
ap.add_argument("--origin", default=os.environ.get("ACMEBANK_ORIGIN", "http://127.0.0.1:5000"))
a = ap.parse_args()
run_forever(bridge_dir(a.artifacts), origin=a.origin.rstrip("/"), pid=os.getpid())
