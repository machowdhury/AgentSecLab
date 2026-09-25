#!/usr/bin/env python3
"""Observe the External Security Toolbox in local Splunk Web.

This validates AgentSec-owned Studio content at required widths. Native Splunk
chrome and screen-reader behavior remain outside this bounded check.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots" / "external-security-toolbox"
URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_external_evaluation_garak"
HOME_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
TABS = ("TOOLBOX", "GUIDED", "INVESTIGATE", "CHALLENGE")
WIDTHS = (1920, 1440, 1280, 1024)


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


def click_tab(page, name: str) -> None:
    tab = page.get_by_role("tab", name=name)
    if tab.count() == 0:
        tab = page.get_by_text(name, exact=True)
    if tab.count() == 0:
        raise RuntimeError(f"missing tab {name}")
    tab.first.click()


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: Playwright is not installed", file=sys.stderr)
        return 2
    password = load_env_value("SPLUNK_PASSWORD")
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing from .env", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    report: dict = {
        "url": URL,
        "classification": {
            "rendering": "OBSERVED",
            "zoom": "PARTIAL",
            "screen_reader": "NOT PROVEN",
            "error_state": "PARTIAL",
        },
        "tabs": [],
        "academy_home": {},
        "widths": {},
        "zoom_200": {},
        "keyboard": {},
        "copy_controls": "NOT APPLICABLE — REPLAY view has no runtime identifier to copy",
        "error_state": (
            "TESTED in repository noDataMessage contracts; dependency outage was "
            "not injected into Splunk Web during this capture"
        ),
        "screenshots": [],
    }

    with sync_playwright() as p:
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        launch_options = {"headless": True}
        if chrome.is_file():
            launch_options["executable_path"] = str(chrome)
        browser = p.chromium.launch(**launch_options)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)
        page.goto(URL, wait_until="domcontentloaded")
        page.wait_for_timeout(6000)

        page.goto(HOME_URL, wait_until="domcontentloaded")
        page.wait_for_timeout(3000)
        path_tab = page.get_by_role("tab", name="PATH")
        if path_tab.count() > 0:
            path_tab.first.click()
            page.wait_for_timeout(1200)
        home_text = page.locator("body").inner_text()
        report["academy_home"] = {
            "external_toolbox_listed": "External Security Toolbox" in home_text,
            "scanner_lesson_listed": "Scanner + Runtime Evidence" in home_text,
        }
        page.goto(URL, wait_until="domcontentloaded")
        page.wait_for_timeout(4000)

        for tab_name in TABS:
            click_tab(page, tab_name)
            page.wait_for_timeout(5000 if tab_name in {"GUIDED", "INVESTIGATE"} else 1500)
            report["tabs"].append(tab_name)
            path = OUT / f"final_{tab_name.lower()}.png"
            page.screenshot(path=str(path), full_page=True)
            report["screenshots"].append(str(path.relative_to(ROOT)))

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1000})
            click_tab(page, "TOOLBOX")
            page.wait_for_timeout(1200)
            overflow = page.evaluate(
                "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
            )
            report["widths"][str(width)] = {"horizontal_overflow": bool(overflow)}
            path = OUT / f"final_w{width}_toolbox.png"
            page.screenshot(path=str(path), full_page=True)
            report["screenshots"].append(str(path.relative_to(ROOT)))

        page.set_viewport_size({"width": 1024, "height": 1000})
        page.evaluate("document.documentElement.style.zoom = '2'")
        page.wait_for_timeout(1200)
        report["zoom_200"] = {
            "width": 1024,
            "horizontal_overflow": bool(
                page.evaluate(
                    "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
                )
            ),
        }
        zoom_path = OUT / "final_w1024_zoom200_toolbox.png"
        page.screenshot(path=str(zoom_path), full_page=True)
        report["screenshots"].append(str(zoom_path.relative_to(ROOT)))
        page.evaluate("document.documentElement.style.zoom = '1'")

        first = page.get_by_role("tab", name="TOOLBOX")
        first.focus()
        before = page.evaluate("() => document.activeElement && document.activeElement.textContent")
        page.keyboard.press("ArrowRight")
        page.wait_for_timeout(300)
        after = page.evaluate("() => document.activeElement && document.activeElement.textContent")
        style = first.evaluate(
            "(el) => { const s=getComputedStyle(el); return {outline:s.outline, boxShadow:s.boxShadow}; }"
        )
        report["keyboard"] = {
            "focus_before": (before or "").strip(),
            "focus_after_arrow_right": (after or "").strip(),
            "focused_tab_style": style,
        }
        browser.close()

    report_path = OUT / "final_validation.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if set(report["tabs"]) != set(TABS):
        return 1
    if not all(report["academy_home"].values()):
        return 1
    if any(row["horizontal_overflow"] for row in report["widths"].values()):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
