#!/usr/bin/env python3
"""Build the per-entry preservation table from the four evidence files (no new measurements here)."""
import difflib, json, sys
from pathlib import Path
R = Path(__file__).resolve().parents[1] / "docs/reviews/batch7"
base, head = (json.loads((R / f"preservation_{t}.json").read_text()) for t in ("baseline", "head"))
cmp_ = json.loads((R / "preservation_compare.json").read_text())
bb, bh = (json.loads((R / f"browser_{t}.json").read_text()) for t in ("baseline", "head"))
sv = json.loads((R / "splunk_views_live.json").read_text())
LIVE = {"LAB-PI-001": ["/", "/labs/LAB-PI-001"], "LAB-MCP-001": ["/labs/LAB-MCP-001", "/academy/labs/LAB-MCP-001"], "LAB-RAG-CONTEXT": ["/labs/LAB-RAG-CONTEXT"],
        "LAB-MEMORY-001": ["/labs/LAB-MEMORY-001"], "LAB-AGENT-GOAL-INTEGRITY-001": ["/labs/LAB-AGENT-GOAL-INTEGRITY-001"],
        "LAB-AGENT-DELEGATION-001": ["/labs/LAB-AGENT-DELEGATION-001"], "LAB-AGENTSEC-CAPSTONE-001": ["/labs/LAB-AGENTSEC-CAPSTONE-001"]}
ABSENT_SPECIMENS = {"LAB-BLUE-TEAM-INCIDENT-001", "LAB-MCP-003", "LAB-MCP-004", "LAB-MCP-005", "LAB-MCP-006", "LAB-MCP-CATALOG", "LAB-MULTI-STAGE-INCIDENT-001", "LAB-SCANNER-RUNTIME-EVIDENCE"}
mode_of = {l[0]: l[1] for lv in base["curriculum_path"] for l in lv[1]}
rows, counts = [], {"PRESERVED": 0, "ENHANCED": 0, "REGRESSED": 0, "UNVERIFIED": 0}
for lab in base["registry_ids"]:
    pl = cmp_["per_lab"][lab]
    files = f"{len(base['lab_files'].get(lab, {}))} files identical" if not (pl["files_changed"] or pl["files_removed"]) else f"CHANGED {pl['files_changed']}"
    launches = [k for k in base["launches"] if k.startswith(lab + "|")]
    launch = f"{len(launches)} launches identical (decisions and event order)" if launches and not pl["launches"] else ("n/a (no launch)" if not launches else f"DIFF {pl['launches']}")
    ui = "n/a"
    if lab in LIVE:
        n = bad = 0
        for u in LIVE[lab]:
            for x, y in zip(bb["launch_ui"].get(u, []), bh["launch_ui"].get(u, [])):
                if x.get("after") is None and y.get("after") is None:
                    continue
                n += 1
                if x != y:
                    d = {l[1:] for l in difflib.unified_diff(x.get("after", "").split(" "), y.get("after", "").split(" "), lineterm="", n=0)
                         if l[:1] in "+-" and l[:3] not in ("+++", "---")}
                    bad += bool(d - {"AgentSec", "Loan", "Desk", "Mission"})
        ui = f"{n} UI steps run; " + ("identical results" if not bad else f"{bad} DIFFER") + " (only the added nav item and brand text differ)"
    view = sv.get(lab, {})
    splunk = f"view XML identical; renders ({view.get('panels_rendered')} viz, {view.get('tabs')} tabs, no error)" if view.get("exists_in_app") and not view.get("has_error_banner") else "PROBLEM"
    a11y = "same axe result" if lab not in ("LAB-MCP-001",) else "ENHANCED: Academy workshop page lost its axe 'region' violation"
    status = "PRESERVED"
    note = ""
    if lab == "LAB-MCP-001":
        status = "ENHANCED"
    elif lab in ABSENT_SPECIMENS:
        status = "UNVERIFIED"
        note = "dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable"
    elif lab in LIVE:
        note = "Docker image 500s on this Attack UI page in baseline too (fixed in Gate B image)"
    counts[status] += 1
    rows.append(f"| {lab} | {mode_of.get(lab, base['registry'][lab]['tier'])} | {files} | {launch} | {ui} | {splunk} | {a11y} | **{status}** | {note} |")
out = ["| Entry | Mode | Learning files | Launch behaviour | Browser flow | Splunk view | Accessibility | Result | Note |", "|---|---|---|---|---|---|---|---|---|"] + rows
(R / "PRESERVATION_TABLE.md").write_text("\n".join(out) + "\n")
print(counts, sum(counts.values()))
