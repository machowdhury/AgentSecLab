#!/usr/bin/env python3
"""Real run: the page's verification states when the host verifier is stopped, then started (recovery)."""

import os
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
ART = os.environ.get("AGENTSEC_ARTIFACTS_HOST_DIR", str(ROOT.parent / "AgentSecLab" / "artifacts"))
SH = str(ROOT / "scripts" / "loan_desk_verifier.sh")
out = ROOT / "docs/reviews/batch4/acceptance/screenshots"


def sh(cmd):
    subprocess.run(["sh", SH, cmd], env={**os.environ, "AGENTSEC_ARTIFACTS_HOST_DIR": ART}, check=False)


def wait_run(pg, slot):
    pg.wait_for_function("(s) => { const p = document.querySelector(`[data-run-panel='${s}']`); return p && p.getAttribute('aria-busy') === 'false' && p.querySelector('.outcomes, .callout--warn'); }", arg=slot, timeout=300000)


with sync_playwright() as pw:
    b = pw.chromium.launch(executable_path=os.environ["AGENTSEC_CHROMIUM"])
    pg = b.new_page(viewport={"width": 1280, "height": 900})
    pg.goto("http://127.0.0.1:5001/academy/missions/loan-desk")
    pg.click("[data-step-link='predict']"); pg.check("input[name=follow][value=yes]"); pg.check("input[name=decision][value=ALLOW]"); pg.check("input[name=queue][value=planted]"); pg.click("[data-lock-prediction]")
    pg.click("[data-step-link='attack']"); pg.click("[data-launch='attack']"); wait_run(pg, "attack")
    pg.click("[data-step-link='investigate']")
    sh("stop")
    import time; time.sleep(25)  # heartbeat goes stale (fresh window is 20 s)
    pg.click("[data-recheck-evidence]")
    pg.wait_for_function("() => /verifier is not running|not installed/.test(document.querySelector('[data-evidence-state]').textContent)", timeout=60000)
    print("OFFLINE:", pg.locator("[data-evidence-state]").inner_text())
    pg.screenshot(path=str(out / "16_verifier_offline.png"), full_page=True)
    sh("start"); time.sleep(6)
    pg.click("[data-recheck-evidence]")
    pg.wait_for_function("() => /SPLUNK-VERIFIED|SPLUNK MISMATCH/.test(document.querySelector('[data-evidence-state]').textContent)", timeout=200000)
    print("RECOVERED:", pg.locator("[data-evidence-state]").inner_text())
    pg.screenshot(path=str(out / "17_verifier_recovered.png"), full_page=True)
    b.close()
