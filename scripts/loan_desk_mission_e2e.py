#!/usr/bin/env python3
"""Real end-to-end Academy mission: browser -> host Attack Service -> Docker AcmeBank -> real Ollama model -> policy
-> collector -> Splunk, then host-side Splunk reconciliation and the page's own searches executed against Splunk.

Touches no container. It writes only <out> and (optionally) the host reconciliation records AcmeBank displays.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import requests  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402
from agentsec.loan_desk.reconcile import run_spl, wait_and_reconcile  # noqa: E402


def wait_run(pg, slot, timeout=240000):
    pg.wait_for_function("(s) => { const p = document.querySelector(`[data-run-panel='${s}']`); "
                         "return p && p.getAttribute('aria-busy') === 'false' && p.querySelector('.outcomes, .callout--warn'); }",
                         arg=slot, timeout=timeout)


def go(pg, step, shots, name=None):
    pg.click(f"[data-step-link='{step}']")
    pg.wait_for_selector(f"#step-{step}:not([hidden])")
    return lambda: pg.screenshot(path=str(shots / f"{name or step}.png"), full_page=True)


def local_events(origin, run_id):
    r = requests.get(f"{origin}/api/v1/loan-desk/runs/{run_id}/events.ndjson", timeout=10)
    return [json.loads(x) for x in r.text.splitlines() if x.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acmebank", default="http://127.0.0.1:5000")
    ap.add_argument("--chromium", default=os.environ.get("AGENTSEC_CHROMIUM"))
    ap.add_argument("--out", default="docs/reviews/batch3/mission")
    ap.add_argument("--record-dir", help="host dir bind-mounted as AcmeBank artifacts/loan_desk")
    a = ap.parse_args()
    out = ROOT / a.out
    shots = out / "screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    srv = make_server("127.0.0.1", 0, create_app(AcmeBankClient(a.acmebank)), threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/academy/missions/loan-desk"
    res: dict = {"acmebank": a.acmebank, "steps": {}}
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=a.chromium)
        pg = b.new_page(viewport={"width": 1280, "height": 900})
        pg.goto(url)
        pg.wait_for_function("() => !document.querySelector('[data-model-line]').textContent.startsWith('Checking')")
        res["model_line"] = pg.locator("[data-model-line]").inner_text()
        pg.screenshot(path=str(shots / "01_understand.png"), full_page=True)

        go(pg, "explore", shots)()
        pg.click("[data-launch='explore']")
        wait_run(pg, "explore")
        pg.screenshot(path=str(shots / "02_explore_normal_run.png"), full_page=True)
        res["explore"] = {"run_id": pg.locator("[data-run-panel='explore'] code").first.inner_text(),
                          "panel": pg.locator("[data-run-panel='explore']").inner_text()[:600]}

        go(pg, "predict", shots)
        pg.check("input[name=follow][value=yes]"); pg.check("input[name=decision][value=ALLOW]"); pg.check("input[name=queue][value=planted]")
        pg.click("[data-lock-prediction]")
        pg.screenshot(path=str(shots / "03_predict_locked.png"), full_page=True)

        go(pg, "attack", shots)
        pg.click("[data-launch='attack']")
        wait_run(pg, "attack")
        pg.screenshot(path=str(shots / "04_attack_result.png"), full_page=True)
        attack_id = pg.locator("[data-run-panel='attack'] code").first.inner_text()
        res["attack"] = {"run_id": attack_id, "panel": pg.locator("[data-run-panel='attack']").inner_text()}

        go(pg, "observe", shots)
        pg.screenshot(path=str(shots / "05_observe.png"), full_page=True)

        # INVESTIGATE: reconcile with Splunk on the host, run the page's own searches for real
        go(pg, "investigate", shots)
        loc = local_events(a.acmebank, attack_id)
        rec = wait_and_reconcile(attack_id, loc, timeout_s=180)
        res["attack"]["reconcile"] = rec
        searches = [t.input_value() for t in pg.locator(".spl").all()]
        res["attack"]["page_searches"] = []
        for spl in searches:
            rows = run_spl(spl)
            res["attack"]["page_searches"].append({"spl": spl, "rows": rows[:5]})
        pg.screenshot(path=str(shots / "06_investigate_local_only.png"), full_page=True)
        n = str(rec["indexed_events"])
        pg.fill("#splunk-count", n)
        pg.click("[data-count-form] button[type=submit]")
        res["attack"]["count_feedback"] = pg.locator("[data-count-result]").inner_text()
        pg.select_option("#proof-event", "agentsec.mcp.started"); pg.click("[data-proof-form] button")
        if a.record_dir:
            d = Path(a.record_dir); d.mkdir(parents=True, exist_ok=True)
            (d / f"{attack_id}.splunk.json").write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
            pg.click("[data-recheck-evidence]")
            pg.wait_for_function("() => document.querySelector('[data-evidence-state]').textContent.startsWith('SPLUNK-VERIFIED') || document.querySelector('[data-evidence-state]').textContent.startsWith('SPLUNK MISMATCH')")
        res["attack"]["evidence_state_text"] = pg.locator("[data-evidence-state]").inner_text()
        pg.screenshot(path=str(shots / "07_investigate_verified.png"), full_page=True)

        go(pg, "defend", shots)
        pg.check("input[name=posture][value=hardened]"); pg.click("[data-apply-defense]")
        pg.screenshot(path=str(shots / "08_defend.png"), full_page=True)

        go(pg, "retest", shots)
        pg.click("[data-launch='retest']")
        wait_run(pg, "retest")
        pg.screenshot(path=str(shots / "09_retest_result.png"), full_page=True)
        retest_id = pg.locator("[data-run-panel='retest'] code").first.inner_text()
        rrec = wait_and_reconcile(retest_id, local_events(a.acmebank, retest_id), timeout_s=180)
        res["retest"] = {"run_id": retest_id, "panel": pg.locator("[data-run-panel='retest']").inner_text(), "reconcile": rrec}
        if a.record_dir:
            (Path(a.record_dir) / f"{retest_id}.splunk.json").write_text(json.dumps(rrec, indent=2) + "\n", encoding="utf-8")

        go(pg, "compare", shots)
        pg.screenshot(path=str(shots / "10_compare.png"), full_page=True)
        res["compare"] = pg.locator("[data-compare-table]").inner_text()

        go(pg, "explain", shots)
        for q_, v in (("q1", "ctrl"), ("q2", "valid"), ("q3", "codes"), ("q4", "started")):
            pg.check(f"input[name={q_}][value={v}]")
        pg.fill("#explain-text", "The attacker hid an instruction in the notes. The agent followed it and policy allowed the valid call, so the planted text reached the underwriter queue. HARDENED restricts the note to reason codes, so free text is denied before the handler runs.")
        pg.click("[data-explain-form] button[type=submit]")
        res["explain"] = pg.locator("[data-explain-result]").inner_text()
        pg.screenshot(path=str(shots / "11_explain_complete.png"), full_page=True)

        pg.set_viewport_size({"width": 390, "height": 844})
        go(pg, "compare", shots, "12_compare_phone")()
        b.close()
    srv.shutdown()
    (out / "mission_run.json").write_text(json.dumps(res, indent=2, default=str) + "\n", encoding="utf-8")
    print(json.dumps({k: (v if k in ("model_line", "explain") else "...") for k, v in res.items()}, indent=1))
    print("attack", res["attack"]["run_id"], "reconciled", res["attack"]["reconcile"]["reconciled"], res["attack"]["reconcile"]["indexed_events"], "/", res["attack"]["reconcile"]["local_events"])
    print("retest", res["retest"]["run_id"], "reconciled", res["retest"]["reconcile"]["reconciled"], res["retest"]["reconcile"]["indexed_events"], "/", res["retest"]["reconcile"]["local_events"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
