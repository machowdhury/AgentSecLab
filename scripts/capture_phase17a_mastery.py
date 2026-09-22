#!/usr/bin/env python3
"""Capture Phase 17A mastery surfaces: Home, Mastery Check, nav, PI, Attack Service.

Does not print credentials. Does not launch attacks.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIDTHS = (1440, 1280, 1024)
HEIGHT = 1100
HOME = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
MASTERY = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_mastery"
PI = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001"
ATTACK = "http://127.0.0.1:5001/"
MENUS = ("Foundations", "Context Security", "Agent Intent", "Capstone")
MASTERY_TABS = (
    "INTRO",
    "FOUNDATIONAL",
    "PRACTITIONER",
    "INVESTIGATOR",
    "ADVANCED",
    "PURPLE TEAM",
    "RUBRIC",
)


def load_env_value(key: str) -> str:
    env_path = ROOT / ".env"
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() == key:
            return value.strip().strip('"').strip("'")
    return ""


def click_tab(page, tab: str) -> bool:
    loc = page.get_by_role("tab", name=tab)
    if loc.count() == 0:
        loc = page.get_by_text(tab, exact=True)
    if loc.count() == 0:
        return False
    loc.first.click()
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=str(ROOT / "docs" / "screenshots" / "agentsec-academy-17a"),
    )
    parser.add_argument("--label", default="pass17a")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright is not installed", file=sys.stderr)
        return 2

    password = load_env_value("SPLUNK_PASSWORD")
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing from .env", file=sys.stderr)
        return 2

    report: dict = {
        "label": args.label,
        "viewports": list(WIDTHS),
        "screenshots": [],
        "nav_labels": [],
        "home_tabs": [],
        "mastery_tabs": [],
        "mastery_check_in_nav": False,
        "attack_where": False,
        "defects": [],
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": HEIGHT})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)

        page.goto(HOME, wait_until="domcontentloaded")
        page.wait_for_timeout(4000)
        body = page.inner_text("body")
        if "Mastery Check" not in body:
            report["defects"].append("HIGH Home missing Mastery Check")
        if "not published" in body.lower():
            report["defects"].append("BLOCKER Home still says identity not published")

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": HEIGHT})
            page.wait_for_timeout(400)
            shot = out / f"{args.label}_home_{width}.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.set_viewport_size({"width": 1440, "height": HEIGHT})
        for tab in ("START", "ORIENT", "PATH", "SPLUNK"):
            if click_tab(page, tab):
                page.wait_for_timeout(800)
                report["home_tabs"].append(tab)

        loc = page.get_by_text("Mastery Check", exact=True)
        if loc.count():
            report["mastery_check_in_nav"] = True
            loc.first.click()
            page.wait_for_timeout(600)
            shot = out / f"{args.label}_nav_mastery_check.png"
            page.screenshot(path=str(shot), full_page=False)
            report["screenshots"].append(str(shot.relative_to(ROOT)))
            page.keyboard.press("Escape")
        else:
            report["defects"].append("HIGH missing nav Mastery Check")

        for menu in MENUS:
            loc = page.get_by_text(menu, exact=True)
            if loc.count() == 0:
                report["defects"].append(f"HIGH missing nav collection {menu}")
                continue
            loc.first.click()
            page.wait_for_timeout(400)
            report["nav_labels"].append(menu)
            page.keyboard.press("Escape")

        page.goto(MASTERY, wait_until="domcontentloaded")
        page.wait_for_timeout(4000)
        mastery_body = page.inner_text("body")
        if "not a certificate" not in mastery_body.lower():
            report["defects"].append("HIGH Mastery Check missing not-a-certificate copy")
        if "Phase 17A" in mastery_body:
            report["defects"].append("HIGH learner UI names Phase 17A")
        if "Path A" not in mastery_body:
            report["defects"].append("HIGH Mastery Check missing Path A")
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": HEIGHT})
            page.wait_for_timeout(400)
            shot = out / f"{args.label}_mastery_{width}.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.set_viewport_size({"width": 1440, "height": HEIGHT})
        for tab in MASTERY_TABS:
            if click_tab(page, tab):
                page.wait_for_timeout(900)
                report["mastery_tabs"].append(tab)
                shot = out / f"{args.label}_mastery_tab_{tab.lower().replace(' ', '_')}.png"
                page.screenshot(path=str(shot), full_page=True)
                report["screenshots"].append(str(shot.relative_to(ROOT)))
            else:
                report["defects"].append(f"HIGH missing Mastery tab {tab}")

        page.goto(PI, wait_until="domcontentloaded")
        page.wait_for_timeout(3500)
        shot = out / f"{args.label}_pi_1440.png"
        page.screenshot(path=str(shot), full_page=True)
        report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.goto(ATTACK, wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        attack_text = page.inner_text("body")
        report["attack_where"] = "Where you are" in attack_text
        if not report["attack_where"]:
            report["defects"].append("HIGH Attack Service missing Where you are")
        shot = out / f"{args.label}_attack_1440.png"
        page.screenshot(path=str(shot), full_page=True)
        report["screenshots"].append(str(shot.relative_to(ROOT)))

        browser.close()

    (out / f"{args.label}_validation.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    blockers = [d for d in report["defects"] if d.startswith("BLOCKER") or d.startswith("HIGH")]
    return 1 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
