#!/usr/bin/env python3
"""Observe the blue-team workbench in local Splunk Web."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots" / "blue-team-incident"
URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_blue_team_incident"
HOME_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
TABS = ("INCIDENT", "INVESTIGATE", "EVIDENCE · WORKBENCH", "PATH B · ANSWERS")
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
            "dependency_error_injection": "NOT TESTED",
        },
        "tabs": [],
        "widths": {},
        "zoom_200": {},
        "keyboard": {},
        "academy_home": {},
        "copy_controls": "NOT APPLICABLE — no custom copy widget; native table text remains selectable",
        "error_states": "OBSERVED textual NO EVIDENCE / dependency guidance; outage injection NOT TESTED",
        "screenshots": [],
    }
    with sync_playwright() as p:
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        options = {"headless": True}
        if chrome.is_file():
            options["executable_path"] = str(chrome)
        browser = p.chromium.launch(**options)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)

        page.goto(HOME_URL, wait_until="domcontentloaded")
        page.wait_for_timeout(3000)
        path_tab = page.get_by_role("tab", name="PATH")
        if path_tab.count():
            path_tab.first.click()
            page.wait_for_timeout(1000)
        home_text = page.locator("body").inner_text()
        report["academy_home"] = {
            "incident_listed": "AcmeBank Incident AI-2026-001" in home_text,
            "blue_team_level_listed": "L6 Blue-team investigation" in home_text,
            "capstone_last_live": "Capstone remains the last LIVE launcher" in home_text,
        }

        page.goto(URL, wait_until="domcontentloaded")
        page.wait_for_timeout(5000)
        for name in TABS:
            tab(page, name).click()
            page.wait_for_timeout(5000 if "EVIDENCE" in name or "ANSWERS" in name else 1200)
            body = page.locator("body").inner_text()
            report["tabs"].append(
                {
                    "name": name,
                    "visible": True,
                    "has_no_evidence_guidance": (
                        "NO EVIDENCE" in body if "EVIDENCE" in name else None
                    ),
                }
            )
            path = OUT / f"final_{name.lower().replace(' · ', '_').replace(' ', '_')}.png"
            page.screenshot(path=str(path), full_page=True)
            report["screenshots"].append(str(path.relative_to(ROOT)))

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1000})
            tab(page, "INCIDENT").click()
            page.wait_for_timeout(1000)
            overflow = page.evaluate(
                "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
            )
            report["widths"][str(width)] = {"horizontal_overflow": bool(overflow)}
            path = OUT / f"final_w{width}_incident.png"
            page.screenshot(path=str(path), full_page=True)
            report["screenshots"].append(str(path.relative_to(ROOT)))

        # Browser 200% zoom halves the available CSS viewport. A 512 CSS-pixel
        # viewport is the reflow-equivalent of 1024 physical pixels at 200%.
        # CSS `zoom:2` is not used because it forces geometric overflow instead
        # of exercising responsive reflow.
        page.set_viewport_size({"width": 512, "height": 1000})
        page.wait_for_timeout(1000)
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
        report["zoom_200"]["overflow_sources"] = page.evaluate(
            """() => Array.from(document.querySelectorAll('*'))
              .map(el => {
                const r = el.getBoundingClientRect();
                return {
                  tag: el.tagName,
                  id: el.id,
                  className: String(el.className).slice(0, 100),
                  left: Math.round(r.left),
                  right: Math.round(r.right),
                  width: Math.round(r.width)
                };
              })
              .filter(row => row.right > document.documentElement.clientWidth + 2)
              .sort((a, b) => b.right - a.right)
              .slice(0, 8)"""
        )
        path = OUT / "final_w1024_zoom200_incident.png"
        page.screenshot(path=str(path), full_page=True)
        report["screenshots"].append(str(path.relative_to(ROOT)))

        page.set_viewport_size({"width": 1024, "height": 1000})
        first = tab(page, "INCIDENT")
        first.focus()
        before = page.evaluate("() => (document.activeElement?.textContent || '').trim()")
        page.keyboard.press("ArrowRight")
        page.wait_for_timeout(300)
        after = page.evaluate("() => (document.activeElement?.textContent || '').trim()")
        style = first.evaluate(
            "(el) => { const s=getComputedStyle(el); return {outline:s.outline, boxShadow:s.boxShadow}; }"
        )
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
    if not all(report["academy_home"].values()):
        return 1
    if len(report["tabs"]) != len(TABS):
        return 1
    if any(row["horizontal_overflow"] for row in report["widths"].values()):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
