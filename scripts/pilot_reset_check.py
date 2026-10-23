#!/usr/bin/env python3
"""Between-participant reset check, driven through the real Academy UI: create genuine mission state (a locked prediction),
press the page's two reset controls, and read what the browser still holds. No run is launched and no model is used.
  AGENTSEC_CHROMIUM=... pilot_reset_check.py [--attack http://127.0.0.1:5001]
Exit 0 only if no participant data survives the reset.
"""
from __future__ import annotations
import argparse, json, os, sys
from playwright.sync_api import sync_playwright

KEYS = ("agentsec.academy.loandesk.v1", "agentsec.academy.progress.v1", "agentsec.academy.mcp.v1")


def held(pg):
    return pg.evaluate("""(keys) => { const o = {}; for (const k of keys) { o['local:' + k] = localStorage.getItem(k) !== null; o['session:' + k] = sessionStorage.getItem(k) !== null; } return o; }""", list(KEYS))


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--attack", default="http://127.0.0.1:5001"); a = ap.parse_args()
    out = {}
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=os.environ.get("AGENTSEC_CHROMIUM"))
        pg = b.new_context().new_page()
        pg.goto(f"{a.attack}/academy/missions/loan-desk"); pg.wait_for_timeout(1200)
        pg.get_by_role("button", name="Continue to Explore").click()
        pg.get_by_role("button", name="Continue to Predict").click()
        for name in ("follow", "decision", "queue"):
            pg.locator(f"input[name={name}]").first.check()
        pg.get_by_role("button", name="Lock prediction").click(); pg.wait_for_timeout(500)
        out["after_participant_activity"] = held(pg)
        out["prediction_visible_before"] = pg.locator("input[name=follow]:checked").count()
        # operator procedure: close the participant's tab, open a new tab, press "Reset browser progress" on the path page
        ctx = pg.context
        pg.close()
        pg = ctx.new_page()
        pg.goto(f"{a.attack}/academy/path"); pg.wait_for_timeout(800)
        out["new_tab_before_reset"] = held(pg)
        pg.locator("[data-reset-progress]").click(); pg.wait_for_timeout(300)
        out["after_both_resets"] = held(pg)
        pg.goto(f"{a.attack}/academy/missions/loan-desk"); pg.wait_for_timeout(1200)
        out["mission_reopens_at"] = pg.url.rsplit("#", 1)[-1]
        out["prediction_still_checked"] = sum(pg.locator(f"input[name={n}]:checked").count() for n in ("follow", "decision", "queue"))
        b.close()
    leaked = [k for k, v in out["after_both_resets"].items() if v]
    out["participant_data_left"] = leaked
    out["ok"] = not leaked and out["prediction_still_checked"] == 0 and out["mission_reopens_at"] == "understand"
    print(json.dumps(out, indent=1))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
