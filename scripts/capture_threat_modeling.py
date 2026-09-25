#!/usr/bin/env python3
"""Observe the threat-modeling workbench in local Splunk Web."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots" / "threat-modeling"
URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_threat_modeling"
HOME_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
TABS = (
    "FOUNDATIONS",
    "SYSTEM · ARCHITECTURE",
    "MODEL · ANALYZE",
    "ARCHITECT CHALLENGE",
    "PATH B · REVIEW",
)
WIDTHS = (1920, 1440, 1280, 1024)


def env_value(key: str) -> str:
    for raw in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            if name.strip() == key:
                return value.strip().strip("\"'")
    return ""


def tab(page, name: str):
    locator = page.get_by_role("tab", name=name)
    if locator.count() == 0:
        locator = page.get_by_text(name, exact=True)
    if locator.count() == 0:
        raise RuntimeError(f"missing tab {name}")
    return locator.first


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: Playwright is not installed", file=sys.stderr)
        return 2
    password = env_value("SPLUNK_PASSWORD")
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing from .env", file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    report: dict = {
        "classification": {
            "rendering": "OBSERVED",
            "accessibility": "PARTIAL",
            "screen_reader": "NOT TESTED",
        },
        "tabs": [],
        "widths": {},
        "zoom_200": {},
        "keyboard": {},
        "answer_gating": {},
        "academy_home": {},
        "copy_controls": "NOT APPLICABLE — static markdown uses native selectable text; no custom copy widget",
        "error_states": "NOT APPLICABLE — no dashboard search/data dependency; malformed artifacts are rejected by offline contracts",
        "screenshots": [],
    }
    with sync_playwright() as p:
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        launch = {"headless": True}
        if chrome.is_file():
            launch["executable_path"] = str(chrome)
        browser = p.chromium.launch(**launch)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)

        page.goto(HOME_URL, wait_until="domcontentloaded")
        page.wait_for_timeout(2500)
        path_tab = page.get_by_role("tab", name="PATH")
        if path_tab.count():
            path_tab.first.click()
            page.wait_for_timeout(600)
        home = page.locator("body").inner_text()
        report["academy_home"] = {
            "level_7": "L7 Threat modeling and security architecture" in home,
            "challenge": "AcmeBank Agentic Customer Operations Platform" in home,
            "capstone_last_live": "Capstone remains the last LIVE launcher" in home,
        }

        page.goto(URL, wait_until="domcontentloaded")
        page.wait_for_timeout(3500)
        early_text = ""
        for name in TABS:
            tab(page, name).click()
            page.wait_for_timeout(800)
            body = page.locator("body").inner_text()
            if name != "PATH B · REVIEW":
                early_text += "\n" + body
            report["tabs"].append({"name": name, "visible": True})
            image = OUT / f"final_{name.lower().replace(' · ', '_').replace(' ', '_')}.png"
            page.screenshot(path=str(image), full_page=True)
            report["screenshots"].append(str(image.relative_to(ROOT)))
        report["answer_gating"] = {
            "reference_absent_before_review": "A defensible model identifies" not in early_text,
            "review_warning_visible": "Open only after drafting" in page.locator("body").inner_text(),
        }

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1000})
            tab(page, "FOUNDATIONS").click()
            page.wait_for_timeout(500)
            report["widths"][str(width)] = {
                "horizontal_overflow": bool(
                    page.evaluate(
                        "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
                    )
                )
            }
            image = OUT / f"final_w{width}_foundations.png"
            page.screenshot(path=str(image), full_page=True)
            report["screenshots"].append(str(image.relative_to(ROOT)))

        page.set_viewport_size({"width": 512, "height": 1000})
        page.wait_for_timeout(500)
        report["zoom_200"] = {
            "physical_width_equivalent": 1024,
            "effective_css_width": 512,
            "method": "responsive reflow equivalent",
            "horizontal_overflow": bool(
                page.evaluate(
                    "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
                )
            ),
        }
        image = OUT / "final_w1024_zoom200_foundations.png"
        page.screenshot(path=str(image), full_page=True)
        report["screenshots"].append(str(image.relative_to(ROOT)))

        page.set_viewport_size({"width": 1024, "height": 1000})
        first = tab(page, "FOUNDATIONS")
        first.focus()
        before = page.evaluate("() => (document.activeElement?.textContent || '').trim()")
        style = first.evaluate(
            "(el) => { const s=getComputedStyle(el); return {outline:s.outline, boxShadow:s.boxShadow}; }"
        )
        page.keyboard.press("ArrowRight")
        page.wait_for_timeout(200)
        after = page.evaluate("() => (document.activeElement?.textContent || '').trim()")
        report["keyboard"] = {
            "focus_before": before,
            "focus_after_arrow_right": after,
            "focused_tab_style": style,
        }
        browser.close()

    (OUT / "final_validation.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    return 0 if all(report["academy_home"].values()) and all(report["answer_gating"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
