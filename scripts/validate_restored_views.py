#!/usr/bin/env python3
"""Open each REPLAY lab's Studio view in Splunk Web once per offered specimen and record what a learner would see.
Logs in with the lab admin password read from the Splunk container's own environment (never printed or stored).
  validate_restored_views.py --splunk http://127.0.0.1:18000 --container agentsec_cold_splunk --out FILE --shots DIR
"""
from __future__ import annotations
import argparse, json, os, re, subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT = Path(__file__).resolve().parents[1]
LABS = {"LAB-MCP-003": "ws_lab_mcp_003", "LAB-MCP-004": "ws_lab_mcp_004", "LAB-MCP-005": "ws_lab_mcp_005", "LAB-MCP-006": "ws_lab_mcp_006",
        "LAB-MCP-CATALOG": "ws_lab_mcp_catalog", "LAB-BLUE-TEAM-INCIDENT-001": "ws_lab_blue_team_incident", "LAB-MULTI-STAGE-INCIDENT-001": "ws_lab_multi_stage_incident",
        "LAB-SCANNER-RUNTIME-EVIDENCE": "ws_lab_scanner_runtime_evidence"}
# Batch 9: the live labs' own dropdown specimens (recovered from the September volumes)
LABS9 = {"LAB-PI-001": "ws_lab_pi_001", "LAB-RAG-CONTEXT": "ws_lab_rag_context", "LAB-MEMORY-001": "ws_lab_memory_security",
         "LAB-AGENT-GOAL-INTEGRITY-001": "ws_lab_agent_goal_integrity", "LAB-AGENT-DELEGATION-001": "ws_lab_agent_delegation",
         "LAB-AGENTSEC-CAPSTONE-001": "ws_lab_agentsec_capstone"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--splunk", required=True); ap.add_argument("--container", required=True); ap.add_argument("--out", required=True); ap.add_argument("--shots", required=True)
    ap.add_argument("--set", choices=["batch8", "batch9"], default="batch8")
    a = ap.parse_args()
    shots = Path(a.shots); shots.mkdir(parents=True, exist_ok=True)
    pw_ = subprocess.run(["docker", "exec", a.container, "printenv", "SPLUNK_PASSWORD"], capture_output=True, text=True).stdout.strip()
    views = {p.stem for p in (ROOT / "splunk_app/agentsec/default/data/ui/views").glob("*.xml")}
    res = {}
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=os.environ.get("AGENTSEC_CHROMIUM"))
        pg = b.new_page(viewport={"width": 1440, "height": 1100})
        pg.goto(f"{a.splunk}/en-US/account/login"); pg.fill("input[name=username]", "admin"); pg.fill("input[name=password]", pw_)
        pg.keyboard.press("Enter"); pg.wait_for_url("**/app/**", timeout=120000)
        for lab, view in (LABS9 if a.set == "batch9" else LABS).items():
            d = json.loads((ROOT / f"learning/level_1/{lab}/dashboard.definition.json").read_text())
            opts_all = []
            for v in d.get("inputs", {}).values():
                o = v.get("options", {})
                if o.get("items") and "run" in str(o.get("token", "")):
                    opts_all.append((o["token"], [(i["label"], i["value"]) for i in o["items"]], o.get("defaultValue")))
                    if a.set == "batch8":
                        break
            opts = opts_all[0] if opts_all else None
            view_name = view if view in views else next((x for x in views if x.endswith(lab.lower().replace("lab-", "").replace("-", "_"))), view)
            res[lab] = {"view": view_name, "exists": view_name in views, "default": opts[2] if opts else None, "options": {}}
            for tok, label, value in ([(o[0], l, v) for o in opts_all for l, v in o[1]] if opts else [(None, "default", None)]):
                url = f"{a.splunk}/en-US/app/agentsec/{view_name}" + (f"?form.{tok}={value}" if opts else "")
                errs = []
                pg.on("pageerror", lambda e, errs=errs: errs.append(str(e)[:100]))
                pg.goto(url, wait_until="domcontentloaded"); pg.wait_for_timeout(11000)
                text = pg.inner_text("body")
                # open the investigation tab when the view has one, so the run-bound panels are rendered
                for tab in ("INVESTIGATE", "INCIDENT", "EVIDENCE", "TIMELINE"):
                    t = pg.get_by_role("tab", name=re.compile(tab, re.I))
                    if t.count():
                        t.first.click(); pg.wait_for_timeout(9000); text = pg.inner_text("body"); break
                short = (value or "default")[:8]
                pg.screenshot(path=str(shots / f"{lab}_{(tok or 'x')[:12]}_{label.replace(' ', '_')[:20]}_{short}.jpg"), type="jpeg", quality=55)
                res[lab]["options"][f"{tok}={value}" if tok and len(opts_all) > 1 else (value or "default")] = {
                    "label": label, "no_results_panels": text.count("No results found"), "search_errors": len(re.findall(r"Error in '|Unknown search command|search_parse_error|Search failed", text)),
                    "shows_event_names": len(re.findall(r"agentsec\.[a-z_.]+", text)), "shows_selected_run": (value or "")[:8] in text or (value or "") in pg.url, "page_errors": errs[:2]}
        b.close()
    Path(a.out).write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    for lab, r in res.items():
        o = r["options"]
        print(f"{lab:32} view_exists={r['exists']} options={len(o)} search_errors={sum(x['search_errors'] for x in o.values())} no_results_total={sum(x['no_results_panels'] for x in o.values())} event_names_seen_min={min(x['shows_event_names'] for x in o.values())}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
