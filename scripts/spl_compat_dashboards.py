#!/usr/bin/env python3
"""Read-only KV_MODE study of dashboard panel searches. Static risk scan for all; emulated execution for a bounded set.

Emulation = run as-is vs with every field de-duplicated right after the base search (see spl_compat_unbound.py).
Tokens are bound to --run (run/scan ids) or to '*' / empty for filters. Nothing in Splunk is changed.
"""
from __future__ import annotations
import argparse, glob, hashlib, json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "scripts"))
from agentsec.loan_desk.reconcile import run_spl  # noqa: E402
from spl_compat_unbound import RISK, emulate, digest  # noqa: E402

def queries():
    for f in sorted(glob.glob(str(ROOT / "learning/level_1/*/dashboard.definition.json")) + [str(ROOT / "learning/home/dashboard.definition.json")]):
        d = json.loads(Path(f).read_text())
        for k, ds in (d.get("dataSources") or {}).items():
            q = (ds.get("options") or {}).get("query")
            if q:
                yield Path(f).parent.name, k, q

def bind(q, run):
    q = re.sub(r"\$[a-z_]*(run_id|scan_id)\$", f'"{run}"', q)
    return re.sub(r"\$[A-Za-z_:.]+\$", "*", q).strip()

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--run", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--max-exec", type=int, default=60); a = ap.parse_args()
    out, n_exec = {}, 0
    for lab, k, q in queries():
        key = f"{lab}/{k}"; risks = [r for r, p in RISK.items() if re.search(p, q)]
        flagged = [r for r in risks if r not in ("already_dedups", "values()")]
        ent = {"risk_constructs": risks, "uses_dedup": "already_dedups" in risks, "needs_attention": bool(flagged)}
        if ent["needs_attention"] and n_exec < a.max_exec:
            spl = bind(q, a.run); spl = spl[7:] if spl.startswith("search ") else spl
            try:
                base, emu = run_spl(spl), run_spl(emulate(spl)); n_exec += 1
                ent.update(rows=len(base), emulated_rows=len(emu), exact_same=digest(base) == digest(emu))
            except Exception as exc:  # noqa: BLE001
                ent["error"] = str(exc)[:100]
        out[key] = ent
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    s = {"panels": len(out), "using_dedup": sum(v["uses_dedup"] for v in out.values()), "needs_attention": sum(v["needs_attention"] for v in out.values()),
         "executed": n_exec, "differs": [k for k, v in out.items() if v.get("exact_same") is False], "errors": [k for k, v in out.items() if "error" in v]}
    print(json.dumps(s, indent=1)); return 0
if __name__ == "__main__":
    raise SystemExit(main())
