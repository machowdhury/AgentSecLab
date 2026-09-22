#!/usr/bin/env python3
"""Capture Phase 16D academy surfaces: Home, nav, labs, Attack Service.

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
VIEWS = {
    "pi": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001",
    "rag": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_rag_context",
    "goal": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agent_goal_integrity",
    "capstone": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agentsec_capstone",
}
ATTACK = "http://127.0.0.1:5001/"
MENUS = ("Foundations", "Context Security", "Agent Intent", "Capstone")


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
        default=str(ROOT / "docs" / "screenshots" / "agentsec-academy-16d"),
    )
    parser.add_argument("--label", default="pass16d")
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
        if "not published" in body.lower():
            report["defects"].append("BLOCKER Home still says identity not published")
        if "Attack Labs" in body and "Foundations" not in body:
            report["defects"].append("HIGH Home still uses Attack Labs directory copy")
        if "Start here" not in body and "START LEARNING" not in body:
            report["defects"].append("HIGH Home missing Start here")

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
                shot = out / f"{args.label}_home_tab_{tab.lower()}.png"
                page.screenshot(path=str(shot), full_page=True)
                report["screenshots"].append(str(shot.relative_to(ROOT)))

        for menu in MENUS:
            loc = page.get_by_text(menu, exact=True)
            if loc.count() == 0:
                report["defects"].append(f"HIGH missing nav collection {menu}")
                continue
            loc.first.click()
            page.wait_for_timeout(600)
            report["nav_labels"].append(menu)
            shot = out / f"{args.label}_nav_{menu.lower().replace(' ', '_')}.png"
            page.screenshot(path=str(shot), full_page=False)
            report["screenshots"].append(str(shot.relative_to(ROOT)))
            page.keyboard.press("Escape")

        for key, url in VIEWS.items():
            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(3500)
            shot = out / f"{args.label}_{key}_1440.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))
            if key == "pi":
                for tab in ("HUNT", "PROVE"):
                    if click_tab(page, tab):
                        page.wait_for_timeout(1200)
                        shot = out / f"{args.label}_pi_{tab.lower()}_1440.png"
                        page.screenshot(path=str(shot), full_page=True)
                        report["screenshots"].append(str(shot.relative_to(ROOT)))
            if key == "capstone":
                for tab in ("PROVE",):
                    if click_tab(page, tab):
                        page.wait_for_timeout(1200)
                        shot = out / f"{args.label}_capstone_prove_1440.png"
                        page.screenshot(path=str(shot), full_page=True)
                        report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.goto(ATTACK, wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        attack_text = page.inner_text("body")
        report["attack_where"] = "Where you are" in attack_text
        if not report["attack_where"]:
            report["defects"].append("HIGH Attack Service missing Where you are")
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": HEIGHT})
            page.wait_for_timeout(300)
            shot = out / f"{args.label}_attack_{width}.png"
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
