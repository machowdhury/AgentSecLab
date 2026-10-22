#!/usr/bin/env python3
"""Acceptance journey against the RUNNING Docker stack: browser -> Attack Service container -> AcmeBank container ->
real Ollama model -> policy -> collector -> Splunk, with the host verifier answering the page's Verify button.

The learner path uses only the browser. This script additionally (a) cross-checks the verifier's answer with an
independent reconciliation and (b) leaves the Splunk view to scripts/loan_desk_splunk_view_capture.py (it logs in to Splunk Web with the lab admin password
taken from the Splunk container's own environment; the password is never printed, stored or sent to any page of ours).
The Splunk view capture lives in scripts/loan_desk_splunk_view_capture.py.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from playwright.sync_api import sync_playwright  # noqa: E402

from agentsec.loan_desk.reconcile import run_spl, wait_and_reconcile  # noqa: E402
from agentsec.loan_desk.verifier import fetch_events  # noqa: E402


def wait_run(pg, slot, timeout=300000):
    pg.wait_for_function("(s) => { const p = document.querySelector(`[data-run-panel='${s}']`); "
                         "return p && p.getAttribute('aria-busy') === 'false' && p.querySelector('.outcomes, .callout--warn'); }",
                         arg=slot, timeout=timeout)


def step(pg, name):
    pg.click(f"[data-step-link='{name}']")
    pg.wait_for_selector(f"#step-{name}:not([hidden])")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="http://127.0.0.1:5001")
    ap.add_argument("--acmebank", default="http://127.0.0.1:5000")
    ap.add_argument("--splunk", default="http://127.0.0.1:8000")
    ap.add_argument("--chromium", default=os.environ.get("AGENTSEC_CHROMIUM"))
    ap.add_argument("--out", default="docs/reviews/batch4/acceptance")
    a = ap.parse_args()
    out = ROOT / a.out
    shots = out / "screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    res: dict = {"attack_service": a.attack}
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=a.chromium)
        pg = b.new_page(viewport={"width": 1280, "height": 900})
        # 1. find the mission from the Academy home like a learner
        pg.goto(f"{a.attack}/academy")
        pg.screenshot(path=str(shots / "01_academy_home.png"), full_page=True)
        pg.click("text=Start the mission")
        pg.wait_for_selector("[data-mission='loan-desk']")
        pg.wait_for_function("() => !document.querySelector('[data-model-line]').textContent.startsWith('Checking')")
        res["model_line"] = pg.locator("[data-model-line]").inner_text()
        pg.screenshot(path=str(shots / "02_understand.png"), full_page=True)
        # 2. explore: a synthetic application typed by the learner
        step(pg, "explore")
        pg.fill("#f-full_name", "Amara Nwosu"); pg.fill("#f-annual_income", "104000"); pg.fill("#f-credit_score", "718")
        pg.fill("#f-loan_amount", "410000"); pg.fill("#f-term_years", "25"); pg.fill("#f-notes", "Relocating for a hospital position.")
        pg.click("[data-launch='explore']"); wait_run(pg, "explore")
        pg.screenshot(path=str(shots / "03_explore_run.png"), full_page=True)
        res["explore"] = pg.locator("[data-run-panel='explore']").inner_text()
        # 3. predict, attack
        step(pg, "predict")
        pg.check("input[name=follow][value=yes]"); pg.check("input[name=decision][value=ALLOW]"); pg.check("input[name=queue][value=planted]")
        pg.click("[data-lock-prediction]")
        step(pg, "attack"); pg.click("[data-launch='attack']"); wait_run(pg, "attack")
        pg.screenshot(path=str(shots / "04_attack_result.png"), full_page=True)
        attack_id = pg.locator("[data-run-panel='attack'] code").first.inner_text()
        res["attack"] = {"run_id": attack_id, "panel": pg.locator("[data-run-panel='attack']").inner_text()}
        step(pg, "observe"); pg.screenshot(path=str(shots / "05_observe.png"), full_page=True)
        # 4. investigate: real verification through the bridge
        step(pg, "investigate")
        pg.screenshot(path=str(shots / "06_investigate_before_verify.png"), full_page=True)
        pg.click("[data-recheck-evidence]")
        pg.wait_for_function("() => /SPLUNK-VERIFIED|SPLUNK MISMATCH|NOT VERIFIED\\. The (host|verifier)/.test(document.querySelector('[data-evidence-state]').textContent)", timeout=200000)
        res["attack"]["verify_text"] = pg.locator("[data-evidence-state]").inner_text()
        pg.screenshot(path=str(shots / "07_investigate_verified.png"), full_page=True)
        n = pg.evaluate("document.querySelector('[data-run-panel=\"attack\"]').textContent.match(/Local evidence: (\\d+) events/)[1]")
        pg.fill("#splunk-count", n); pg.click("[data-count-form] button[type=submit]")
        res["attack"]["count_feedback"] = pg.locator("[data-count-result]").inner_text()
        pg.select_option("#proof-event", "agentsec.mcp.started"); pg.click("[data-proof-form] button")
        searches = [t.input_value() for t in pg.locator(".spl").all()]
        res["attack"]["page_searches"] = [{"spl": s, "rows": run_spl(s)[:3]} for s in searches]
        # 5. defend, retest
        step(pg, "defend"); pg.check("input[name=posture][value=hardened]"); pg.click("[data-apply-defense]")
        pg.screenshot(path=str(shots / "08_defend.png"), full_page=True)
        step(pg, "retest"); pg.click("[data-launch='retest']"); wait_run(pg, "retest")
        pg.screenshot(path=str(shots / "09_retest_result.png"), full_page=True)
        retest_id = pg.locator("[data-run-panel='retest'] code").first.inner_text()
        res["retest"] = {"run_id": retest_id, "panel": pg.locator("[data-run-panel='retest']").inner_text()}
        # 6. compare, verify both runs from the page
        step(pg, "compare")
        pg.click("text=Verify both runs with Splunk")
        pg.wait_for_function("() => /Retest run: (SPLUNK-VERIFIED|SPLUNK MISMATCH|NOT VERIFIED)/.test(document.querySelector('[data-compare-status]').textContent)", timeout=300000)
        res["compare_status"] = pg.locator("[data-compare-status]").inner_text()
        pg.screenshot(path=str(shots / "10_compare.png"), full_page=True)
        res["compare"] = pg.locator("[data-compare-table]").inner_text()
        # 7. explain
        step(pg, "explain")
        for q_, v in (("q1", "ctrl"), ("q2", "valid"), ("q3", "codes"), ("q4", "started")):
            pg.check(f"input[name={q_}][value={v}]")
        pg.fill("#explain-text", "The attacker hid an instruction in the notes and the agent filed it; policy allowed a valid call. HARDENED requires a reason code, so free text is denied before the handler runs.")
        pg.click("[data-explain-form] button[type=submit]")
        res["explain"] = pg.locator("[data-explain-result]").inner_text()
        pg.screenshot(path=str(shots / "11_explain_complete.png"), full_page=True)
        pg.goto(f"{a.attack}/academy")
        res["progress_on_home"] = pg.locator("[data-progress-for='LAB-LOANDESK-001']").inner_text()
        pg.set_viewport_size({"width": 390, "height": 844}); pg.goto(f"{a.attack}/academy/missions/loan-desk#compare")
        pg.screenshot(path=str(shots / "12_phone.png"), full_page=True)
        # independent cross-check of what the verifier said
        for tag, rid in (("attack", attack_id), ("retest", retest_id)):
            ev = fetch_events(a.acmebank, rid)
            r = wait_and_reconcile(rid, ev, timeout_s=120)
            res[tag]["independent_reconcile"] = {k: r[k] for k in ("reconciled", "problems", "local_events", "indexed_events", "distinct_sequences", "events_with_multivalue_sequence", "naive_value_count")}
        b.close()
    (out / "acceptance_run.json").write_text(json.dumps(res, indent=2, default=str) + "\n", encoding="utf-8")
    print(json.dumps({"attack": res["attack"]["run_id"], "retest": res["retest"]["run_id"], "attack_verify": res["attack"]["verify_text"],
                      "indep_attack": res["attack"]["independent_reconcile"], "indep_retest": res["retest"]["independent_reconcile"],
                      "explain": res["explain"], "progress": res["progress_on_home"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
