#!/usr/bin/env python3
"""Capture AgentSec Home and grouped navigation screenshots from Splunk Web."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=str(ROOT / "docs" / "screenshots" / "agentsec-home"),
    )
    parser.add_argument("--label", default="pass1")
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

    report = {
        "url": "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home",
        "screenshots": [],
        "nav_labels": [],
        "label": args.label,
        "viewports": [1440, 1280, 1024, 768],
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)
        page.goto(report["url"], wait_until="domcontentloaded")
        page.wait_for_timeout(4000)

        png = out / f"{args.label}_home_1440.png"
        page.screenshot(path=str(png), full_page=True)
        report["screenshots"].append(str(png.relative_to(ROOT)))

        for menu in ("Foundations", "Context Security", "Agent Intent", "Capstone"):
            loc = page.get_by_text(menu, exact=True)
            if loc.count() == 0:
                continue
            loc.first.click()
            page.wait_for_timeout(800)
            report["nav_labels"].append(menu)
            shot = out / f"{args.label}_nav_{menu.lower().replace(' ', '_').replace('/', '_')}.png"
            page.screenshot(path=str(shot), full_page=False)
            report["screenshots"].append(str(shot.relative_to(ROOT)))
            page.keyboard.press("Escape")

        for width in (1280, 1024, 768):
            page.set_viewport_size({"width": width, "height": 1100})
            page.wait_for_timeout(500)
            shot = out / f"{args.label}_home_{width}.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))

        browser.close()

    (out / f"{args.label}_validation.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    return 0 if report["screenshots"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
