#!/usr/bin/env python3
"""Run the repo's run-bound hunts against specimen/loan-desk runs and store normalized results.

Used for a before/after comparison around a props.conf change. Read-only against Splunk (host docker exec).
Normalization: every field value is split on newlines, de-duplicated and sorted, so a duplicated multivalue and a
single value compare equal; the raw duplicate count is recorded separately.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.loan_desk.reconcile import run_spl  # noqa: E402


def norm_rows(rows: list[dict]) -> list[list[tuple[str, tuple[str, ...]]]]:
    out = []
    for r in rows:
        out.append(sorted((k, tuple(sorted(set(v.split("\n"))))) for k, v in r.items()))
    return sorted(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-ids", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    res = {}
    files = sorted(glob.glob(str(ROOT / "learning/level_1/*/searches/*.spl")))
    for f in files:
        text = Path(f).read_text(encoding="utf-8")
        if "__RUN_ID__" not in text:
            continue
        for rid in a.run_ids:
            key = f"{Path(f).parent.parent.name}/{Path(f).name}@{rid[:8]}"
            spl = re.sub(r"^\s*(//|#).*$", "", text.replace("__RUN_ID__", f'"{rid}"'), flags=re.M).strip()
            if spl.startswith("search "):
                spl = spl[7:]
            try:
                rows = run_spl(spl)
                n = norm_rows(rows)
                raw_multi = sum(1 for r in rows for v in r.values() if "\n" in v)
                res[key] = {"rows": len(rows), "norm_sha": hashlib.sha256(json.dumps(n).encode()).hexdigest()[:16],
                            "raw_multivalue_cells": raw_multi}
            except Exception as exc:  # noqa: BLE001
                res[key] = {"error": str(exc)[:120]}
            print(key, res[key], flush=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
