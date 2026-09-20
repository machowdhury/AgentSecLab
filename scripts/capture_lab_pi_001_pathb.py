#!/usr/bin/env python3
"""Capture HUNT Path A/B stacked notebook and Attack Service page."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots" / "lab-pi-001"


def load_env_value(key: str) -> str:
    for raw in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() == key:
            return value.strip().strip('"').strip("'")
    return ""


def main() -> int:
    from playwright.sync_api import sync_playwright

    password = load_env_value("SPLUNK_PASSWORD")
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing")
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    report = {"screenshots": []}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)
        page.goto(
            "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001",
            wait_until="domcontentloaded",
        )
        page.wait_for_timeout(4000)
        page.get_by_role("tab", name="HUNT").first.click()
        page.wait_for_timeout(3000)
        hunt_try = OUT / "pass2_hunt_try.png"
        page.screenshot(path=str(hunt_try), full_page=True)
        report["screenshots"].append(str(hunt_try.relative_to(ROOT)))
        sol = page.get_by_text("Solution — Investigation 1", exact=False)
        if sol.count():
            sol.first.scroll_into_view_if_needed()
            page.wait_for_timeout(1500)
        hunt_sol = OUT / "pass2_hunt_solution.png"
        page.screenshot(path=str(hunt_sol), full_page=True)
        report["screenshots"].append(str(hunt_sol.relative_to(ROOT)))
        page.goto("http://127.0.0.1:5001/", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        attack = OUT / "pass2_attack_service.png"
        page.screenshot(path=str(attack), full_page=True)
        report["screenshots"].append(str(attack.relative_to(ROOT)))
        browser.close()
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
