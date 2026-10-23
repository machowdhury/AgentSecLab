#!/usr/bin/env python3
"""For each REPLAY lab, run every data source of its dashboard against each offered specimen in a given Splunk and report:
queries run, search errors, queries with rows, and the row count of the lab's event-level panels. Read-only.
  AGENTSEC_SPLUNK_CONTAINER=<container> validate_restored_specimens.py --out FILE
"""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.loan_desk.reconcile import run_spl  # noqa: E402

LABS = ["LAB-MCP-003", "LAB-MCP-004", "LAB-MCP-005", "LAB-MCP-006", "LAB-MCP-CATALOG", "LAB-BLUE-TEAM-INCIDENT-001", "LAB-MULTI-STAGE-INCIDENT-001", "LAB-SCANNER-RUNTIME-EVIDENCE"]
LABS9 = ["LAB-PI-001", "LAB-RAG-CONTEXT", "LAB-MEMORY-001", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001", "LAB-AGENTSEC-CAPSTONE-001"]
TOK = re.compile(r"\$([A-Za-z_:.]+)\$")


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); ap.add_argument("--set", choices=["batch8", "batch9"], default="batch8"); a = ap.parse_args()
    res = {}
    for lab in (LABS9 if a.set == "batch9" else LABS):
        d = json.loads((ROOT / f"learning/level_1/{lab}/dashboard.definition.json").read_text())
        inputs = d.get("inputs", {})
        opts = {}
        for k, v in inputs.items():
            o = v.get("options", {})
            if o.get("items") and o.get("token"):
                opts[o["token"]] = [i["value"] for i in o["items"]]
        defaults = {v["options"]["token"]: v["options"].get("defaultValue", "*") for v in inputs.values() if v.get("options", {}).get("token")}
        run_tokens = [t for t in opts if "run" in t]
        lab_res = {"options": {t: opts[t] for t in run_tokens}, "runs": {}}
        for t in (run_tokens if a.set == "batch9" else run_tokens[:1]):
            for val in opts[t]:
                env = {**defaults, t: val}
                per = {"queries": 0, "errors": [], "with_rows": 0, "rows": {}}
                for name, ds in (d.get("dataSources") or {}).items():
                    q = (ds.get("options") or {}).get("query")
                    if not q or f"${t}$" not in q:
                        continue
                    spl = TOK.sub(lambda m: str(env.get(m.group(1), "*")), q).strip()
                    spl = spl[7:] if spl.startswith("search ") else spl
                    per["queries"] += 1
                    try:
                        rows = run_spl(spl)
                        per["rows"][name] = len(rows)
                        per["with_rows"] += bool(rows)
                    except Exception as exc:  # noqa: BLE001
                        per["errors"].append(f"{name}: {str(exc)[:60]}")
                lab_res["runs"][f"{t}={val}" if a.set == "batch9" else val] = per
        res[lab] = lab_res
        tot = sum(p["queries"] for p in lab_res["runs"].values()); err = sum(len(p["errors"]) for p in lab_res["runs"].values())
        print(f"{lab}: {len(lab_res['runs'])} offered runs, {tot} bound queries, {err} errors", flush=True)
    Path(a.out).write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
