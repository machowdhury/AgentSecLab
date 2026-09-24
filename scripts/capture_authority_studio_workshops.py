#!/usr/bin/env python3
"""Capture Goal and Identity four-path Dashboard Studio workshops."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSHOPS = {
    "goal": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agent_goal_integrity",
    "identity": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agent_delegation",
}
TABS = ("MISSION", "INVESTIGATE", "EVIDENCE", "PATH B · ANSWERS")
WIDTHS = (1920, 1440, 1280, 1024)


def load_env_value(key: str) -> str:
    for raw in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() == key:
            return value.strip().strip('"').strip("'")
    return ""


def click_tab(page, name: str) -> bool:
    locator = page.get_by_role("tab", name=name, exact=True)
    if locator.count() == 0:
        locator = page.get_by_text(name, exact=True)
    if locator.count() == 0:
        return False
    locator.first.click()
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=str(ROOT / "docs" / "screenshots" / "authority-studio-workshops"),
    )
    parser.add_argument("--label", default="final")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: Playwright is not installed.", file=sys.stderr)
        return 2

    password = load_env_value("SPLUNK_PASSWORD")
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing from .env", file=sys.stderr)
        return 2

    report: dict = {"tabs": list(TABS), "widths": list(WIDTHS), "workshops": {}, "failures": []}
    failures: list[str] = report["failures"]

    with sync_playwright() as playwright:
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        launch_options = {"headless": True}
        if chrome.is_file():
            launch_options["executable_path"] = str(chrome)
        browser = playwright.chromium.launch(**launch_options)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)

        for slug, url in WORKSHOPS.items():
            console_errors: list[str] = []
            failed_responses: list[dict] = []
            page.on(
                "console",
                lambda message, bucket=console_errors: bucket.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on(
                "response",
                lambda response, bucket=failed_responses: bucket.append(
                    {"status": response.status, "url": response.url}
                )
                if response.status >= 400
                else None,
            )
            item = {
                "url": url,
                "tabs_found": [],
                "tabs_missing": [],
                "screenshots": [],
                "overflow": {},
                "console_errors": [],
                "known_platform_404s": [],
                "unexpected_http_errors": [],
            }
            report["workshops"][slug] = item
            page.set_viewport_size({"width": 1440, "height": 1100})
            response = page.goto(url, wait_until="domcontentloaded")
            if response is None or not response.ok:
                failures.append(f"{slug}: workshop HTTP load failed")
                continue
            page.wait_for_timeout(5000)

            for tab in TABS:
                if not click_tab(page, tab):
                    item["tabs_missing"].append(tab)
                    failures.append(f"{slug}: missing tab {tab}")
                    continue
                page.wait_for_timeout(8000 if tab in {"EVIDENCE", "PATH B · ANSWERS"} else 2000)
                item["tabs_found"].append(tab)
                png = out / f"{args.label}_{slug}_{tab.lower().replace(' ', '_').replace('·', 'path')}_1440.png"
                page.screenshot(path=str(png), full_page=True)
                item["screenshots"].append(str(png.relative_to(ROOT)))

            for width in WIDTHS:
                page.set_viewport_size({"width": width, "height": 1100})
                if not click_tab(page, "MISSION"):
                    failures.append(f"{slug}: MISSION unavailable at {width}px")
                    continue
                page.wait_for_timeout(1500)
                no_overflow = page.evaluate(
                    "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth"
                )
                item["overflow"][str(width)] = bool(no_overflow)
                png = out / f"{args.label}_{slug}_mission_w{width}.png"
                page.screenshot(path=str(png), full_page=True)
                item["screenshots"].append(str(png.relative_to(ROOT)))

            item["console_errors"] = list(console_errors)
            known_suffixes = (
                "/services/server/scs/tenantinfo?output_mode=json",
                "/services/configs/conf-limits/structured_data_service?output_mode=json",
                "/servicesNS/admin/agentsec/static/appLogo.png",
            )
            item["known_platform_404s"] = [
                row
                for row in failed_responses
                if row["status"] == 404 and row["url"].endswith(known_suffixes)
            ]
            item["unexpected_http_errors"] = [
                row for row in failed_responses if row not in item["known_platform_404s"]
            ]
            if item["unexpected_http_errors"]:
                failures.append(f"{slug}: unexpected browser HTTP errors")
            if console_errors and len(console_errors) != len(item["known_platform_404s"]):
                failures.append(f"{slug}: unclassified browser console errors")

        browser.close()

    path = out / f"{args.label}_validation.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(path.relative_to(ROOT)), "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
