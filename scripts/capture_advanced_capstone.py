#!/usr/bin/env python3
"""Observe the L10 mastery capstone in local Splunk Web."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots" / "advanced-capstone"
URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_advanced_capstone"
HOME = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
TABS = (
    "MISSION", "ARCHITECTURE", "INVESTIGATE", "EVIDENCE", "TIMELINE",
    "DATA", "CONTROLS", "DETECT & HUNT", "RESPOND", "REPORT", "PATH B",
)
ATTACK_ID = "fd994587-7e1c-4a70-8013-54cb2c85254d"


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
        print("ERROR: Playwright not installed", file=sys.stderr)
        return 2
    password = env_value("SPLUNK_PASSWORD")
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing", file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    report = {
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
        "semantic_states": {},
        "copy_controls": "native selectable markdown and Splunk table cells; no custom copy widget",
        "failure_states": {},
        "screenshots": [],
    }
    with sync_playwright() as p:
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        browser = p.chromium.launch(
            headless=True,
            **({"executable_path": str(chrome)} if chrome.is_file() else {}),
        )
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)

        page.goto(HOME, wait_until="domcontentloaded")
        page.wait_for_timeout(2500)
        path = page.get_by_role("tab", name="PATH")
        if path.count():
            path.first.click()
            page.wait_for_timeout(500)
        home = page.locator("body").inner_text()
        report["academy_home"] = {
            "level_10": "L10 Advanced capstone and mastery" in home,
            "incident": "MASTER-2026-001" in home,
            "capstone_last_live": "Capstone remains the last LIVE launcher" in home,
        }

        page.goto(URL, wait_until="domcontentloaded")
        page.wait_for_timeout(4500)
        early = ""
        path_b = ""
        mission = ""
        for name in TABS:
            tab(page, name).click()
            page.wait_for_timeout(1200)
            if name in {"INVESTIGATE", "TIMELINE", "CONTROLS", "DETECT & HUNT", "PATH B"}:
                try:
                    page.get_by_text("distinct_events").first.wait_for(timeout=20000)
                except Exception:
                    pass
            body = page.locator("body").inner_text()
            if name == "PATH B":
                path_b = body
            else:
                early += "\n" + body
            if name == "MISSION":
                mission = body
            report["tabs"].append({"name": name, "visible": True})
            image = OUT / f"final_{name.lower().replace(' & ', '_').replace(' ', '_')}.png"
            page.screenshot(path=str(image), full_page=True)
            report["screenshots"].append(str(image.relative_to(ROOT)))
        report["answer_gating"] = {
            "mission_has_no_run_id": ATTACK_ID not in mission,
            "mission_has_no_disposition": "H2 disposition is REFUTED" not in mission,
            "disposition_absent_before_path_b": "H2 disposition is REFUTED" not in early,
            "disposition_present_in_path_b": "H2 disposition is REFUTED" in path_b,
            "discovery_table_may_show_run_id": ATTACK_ID in early,
        }
        report["semantic_states"] = {
            "textual_states": all(term in early for term in ("PROVEN", "NOT PROVEN", "REFUTED")),
            "distinct_events": "dc(_raw)" in early,
        }
        report["failure_states"] = {
            "no_evidence_found": "NO EVIDENCE FOUND" in early,
            "insufficient_evidence": "INSUFFICIENT EVIDENCE" in early,
            "never_safe": "Never write SAFE" in early,
        }
        for width in (1920, 1440, 1280, 1024):
            page.set_viewport_size({"width": width, "height": 1000})
            tab(page, "MISSION").click()
            page.wait_for_timeout(400)
            report["widths"][str(width)] = {
                "horizontal_overflow": bool(page.evaluate(
                    "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
                ))
            }
            image = OUT / f"final_w{width}_mission.png"
            page.screenshot(path=str(image), full_page=True)
            report["screenshots"].append(str(image.relative_to(ROOT)))
        page.set_viewport_size({"width": 512, "height": 1000})
        page.wait_for_timeout(400)
        report["zoom_200"] = {
            "physical_width_equivalent": 1024,
            "effective_css_width": 512,
            "method": "responsive reflow equivalent",
            "horizontal_overflow": bool(page.evaluate(
                "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
            )),
        }
        image = OUT / "final_w1024_zoom200_mission.png"
        page.screenshot(path=str(image), full_page=True)
        report["screenshots"].append(str(image.relative_to(ROOT)))
        page.set_viewport_size({"width": 1024, "height": 1000})
        first = tab(page, "MISSION")
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
    (OUT / "final_validation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    gating = {
        key: value
        for key, value in report["answer_gating"].items()
        if key != "discovery_table_may_show_run_id"
    }
    checks = (
        list(report["academy_home"].values())
        + list(gating.values())
        + list(report["semantic_states"].values())
        + list(report["failure_states"].values())
    )
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
