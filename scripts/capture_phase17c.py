#!/usr/bin/env python3
"""Capture Phase 17C copy-correction surfaces.

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
MEMORY = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_memory_security"
PI = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001"
ATTACK = "http://127.0.0.1:5001/"


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
        default=str(ROOT / "docs" / "screenshots" / "agentsec-academy-17c"),
    )
    parser.add_argument("--label", default="pass17c")
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
        if click_tab(page, "ORIENT"):
            page.wait_for_timeout(800)
            orient = page.inner_text("body")
            if "proves equivalent input" in orient:
                report["defects"].append("HIGH Home ORIENT still says fingerprint proves equivalent input")
            if "Fingerprint" not in orient:
                report["defects"].append("HIGH Home ORIENT missing Fingerprint")
            shot = out / f"{args.label}_home_orient_1440.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": HEIGHT})
            page.wait_for_timeout(400)
            shot = out / f"{args.label}_home_{width}.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.set_viewport_size({"width": 1440, "height": HEIGHT})
        page.goto(PI, wait_until="domcontentloaded")
        page.wait_for_timeout(3500)
        pi = page.inner_text("body")
        if "**LIVE EVIDENCE**" in pi or "LIVE EVIDENCE · Direct Prompt Injection" in pi:
            report["defects"].append("HIGH PI LEARN still labeled LIVE EVIDENCE alone")
        if "LIVE EXPERIMENT" not in pi or "REPLAY SPECIMEN" not in pi:
            report["defects"].append("HIGH PI LEARN missing LIVE EXPERIMENT vs REPLAY SPECIMEN")
        shot = out / f"{args.label}_pi_1440.png"
        page.screenshot(path=str(shot), full_page=True)
        report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.goto(MEMORY, wait_until="domcontentloaded")
        page.wait_for_timeout(3500)
        if click_tab(page, "BASELINE"):
            page.wait_for_timeout(1000)
            base = page.inner_text("body")
            if "LIVE · write defended · recall defended · mode BASELINE" in base:
                report["defects"].append("HIGH Memory BASELINE stamps LIVE on REPLAY UUIDs")
            if "REPLAY SPECIMEN" not in base:
                report["defects"].append("HIGH Memory BASELINE missing REPLAY SPECIMEN")
            shot = out / f"{args.label}_memory_baseline_1440.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))
        else:
            report["defects"].append("HIGH Memory missing BASELINE tab")
        for width in (1440, 1280, 1024):
            page.set_viewport_size({"width": width, "height": HEIGHT})
            page.wait_for_timeout(300)
            shot = out / f"{args.label}_memory_{width}.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.set_viewport_size({"width": 1440, "height": HEIGHT})
        page.goto(MASTERY, wait_until="domcontentloaded")
        page.wait_for_timeout(3500)
        if click_tab(page, "PURPLE TEAM"):
            page.wait_for_timeout(900)
            purple = page.inner_text("body")
            if "not the 15-point" not in purple:
                report["defects"].append("HIGH Mastery PURPLE TEAM Path B still looks like the 15-point readout")
            if "official REPLAY ATTACK recall" not in purple:
                report["defects"].append("HIGH Mastery PURPLE TEAM missing official REPLAY recall labels")
            shot = out / f"{args.label}_mastery_purple_1440.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))
        else:
            report["defects"].append("HIGH Mastery missing PURPLE TEAM tab")
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": HEIGHT})
            page.wait_for_timeout(300)
            shot = out / f"{args.label}_mastery_{width}.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.goto(ATTACK, wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        attack_text = page.inner_text("body")
        if "AML.T0054" not in attack_text:
            report["defects"].append("HIGH Attack Service missing AML.T0054")
        if "REQUIRES REVALIDATION" not in attack_text:
            report["defects"].append("HIGH Attack Service ATLAS id lacks REQUIRES REVALIDATION")
        if "EVIDENCE READY" not in attack_text:
            report["defects"].append("HIGH Attack Service missing EVIDENCE READY")
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
    print(json.dumps({k: report[k] for k in ("label", "defects", "screenshots")}, indent=2))
    blockers = [d for d in report["defects"] if d.startswith("BLOCKER") or d.startswith("HIGH")]
    return 1 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
