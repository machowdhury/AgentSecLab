#!/usr/bin/env python3
"""Render the LAB-LOANDESK-001 Studio view in Splunk Web for given run ids and capture screenshots.

Logs in as the lab admin using the password from the Splunk container's own environment (never printed or stored).
This is test automation only; the product never gives any browser a Splunk credential.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_ids", nargs="+")
    ap.add_argument("--splunk", default="http://127.0.0.1:8000")
    ap.add_argument("--chromium", default=os.environ.get("AGENTSEC_CHROMIUM"))
    ap.add_argument("--out", default="docs/reviews/batch4/acceptance/screenshots")
    a = ap.parse_args()
    out = ROOT / a.out
    out.mkdir(parents=True, exist_ok=True)
    pw_ = subprocess.run(["docker", "exec", "agentsec_splunk", "printenv", "SPLUNK_PASSWORD"], capture_output=True, text=True).stdout.strip()
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=a.chromium)
        sp = b.new_page(viewport={"width": 1440, "height": 1100})
        sp.goto(f"{a.splunk}/en-US/account/login?return_to=/en-US/app/agentsec/ws_lab_loandesk_001")
        sp.fill("input[name=username]", "admin")
        sp.fill("input[name=password]", pw_)
        sp.keyboard.press("Enter")
        sp.wait_for_url("**/ws_lab_loandesk_001**", timeout=120000)
        sp.wait_for_timeout(10000)
        sp.screenshot(path=str(out / "13_splunk_view_mission_tab.png"))
        for i, rid in enumerate(a.run_ids):
            box = sp.locator("input[type='text']:visible, textarea:visible").first
            box.click()
            box.fill(rid)
            box.press("Enter")
            sp.get_by_role("tab", name="INVESTIGATE").first.click()
            sp.wait_for_timeout(20000)
            sp.screenshot(path=str(out / f"{14 + i}_splunk_view_run_{i + 1}.png"), full_page=True)
        b.close()
    print("captured", len(a.run_ids), "run view(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
