#!/usr/bin/env python3
"""Live P1.4 Academy qualification against a running Attack Service.

Walks the REPLAY beginner journey, captures screenshots, records zoom geometry,
and writes JSON evidence. Does not launch LIVE unless --live is passed.
Does not modify Splunk or unrelated applications.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "tests" / "support" / "chrome_zoom_extension"
ATTACK_REPLAY = "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49"
RETEST_REPLAY = "7a1d37b5-d589-4dfd-8322-25ebd0152dbc"


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def geometry(page) -> dict:
    return page.evaluate(
        """() => ({
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight,
            devicePixelRatio: window.devicePixelRatio,
            scrollWidth: document.documentElement.scrollWidth,
            clientWidth: document.documentElement.clientWidth,
            overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth
        })"""
    )


def clipped(page) -> list:
    return page.evaluate(
        """() => Array.from(document.querySelectorAll('main *')).filter(n => {
            const s = getComputedStyle(n);
            if (s.clip && s.clip !== 'auto') return false;
            if (s.display === 'none' || s.visibility === 'hidden' || !n.offsetParent) return false;
            return (s.overflowX === 'hidden' || s.overflowX === 'clip') && n.scrollWidth > n.clientWidth + 1;
        }).map(n => n.tagName + '.' + n.className)"""
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.environ.get("ACADEMY_BASE_URL", "http://127.0.0.1:5001"))
    parser.add_argument("--out", default=str(ROOT / "artifacts" / "p1.4-figma-academy-20261009"))
    parser.add_argument("--headed", action="store_true")
    args = parser.parse_args()
    out = Path(args.out)
    shots = out / "screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    log: dict = {"started": utc(), "base_url": args.base_url, "pages": {}, "workflow": {}, "zoom": {}}

    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not args.headed)
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.on("pageerror", lambda e: log.setdefault("page_errors", []).append(str(e)))

        for path, name in (
            ("/academy", "home"),
            ("/academy/foundations", "foundations"),
            ("/academy/path", "path"),
            ("/academy/status", "status"),
            ("/academy/labs/LAB-MCP-001", "workshop"),
        ):
            resp = page.goto(args.base_url + path, wait_until="networkidle")
            shot = shots / f"{name}_1920.png"
            page.screenshot(path=str(shot), full_page=True)
            log["pages"][name] = {
                "path": path,
                "http": resp.status if resp else None,
                "title": page.title(),
                "h1": page.locator("h1").inner_text(),
                "geometry": geometry(page),
                "clipped": clipped(page),
                "screenshot": str(shot.relative_to(ROOT)),
                "sha256": sha256(shot),
            }

        page.set_viewport_size({"width": 1024, "height": 768})
        page.goto(args.base_url + "/academy", wait_until="networkidle")
        shot = shots / "home_1024.png"
        page.screenshot(path=str(shot), full_page=True)
        log["pages"]["home_1024"] = {"geometry": geometry(page), "clipped": clipped(page), "sha256": sha256(shot)}

        page.set_viewport_size({"width": 320, "height": 568})
        page.goto(args.base_url + "/academy/labs/LAB-MCP-001", wait_until="networkidle")
        shot = shots / "workshop_320.png"
        page.screenshot(path=str(shot), full_page=True)
        log["pages"]["workshop_320"] = {"geometry": geometry(page), "overflowX": geometry(page)["overflowX"], "clipped": clipped(page), "sha256": sha256(shot)}

        page.set_viewport_size({"width": 1920, "height": 1080})
        page.goto(args.base_url + "/academy/labs/LAB-MCP-001", wait_until="networkidle")
        page.get_by_role("button", name="Continue to Baseline").click()
        page.get_by_role("button", name="Load the recorded baseline").click()
        page.locator('[data-evidence-slot="baseline"] table').wait_for()
        page.get_by_role("button", name="Continue to Predict").click()
        page.get_by_label("DENY", exact=True).check()
        page.get_by_label("No", exact=True).check()
        page.get_by_role("button", name="Lock prediction and continue").click()
        page.get_by_role("button", name="Use the recorded ATTACK (REPLAY)").click()
        card = page.locator('[data-run-card="ATTACK"]')
        card.locator("h3").wait_for()
        attack_text = card.inner_text()
        page.get_by_role("button", name="Continue to Investigate").click()
        page.locator("[data-questions] fieldset").first.wait_for()
        page.get_by_role("button", name="Continue to Defend").click()
        page.get_by_role("button", name="Continue to Retest").click()
        page.get_by_role("button", name="Use the recorded RETEST (REPLAY)").click()
        page.locator('[data-run-card="RETEST"] h3').wait_for()
        page.get_by_role("button", name="Continue to Compare").click()
        page.locator("[data-compare-slot] table").wait_for()
        compare_text = page.locator("[data-compare-slot]").inner_text()
        page.get_by_role("button", name="Continue to Explain").click()
        page.locator("[data-explanation]").fill(
            "ATTACK run allowed an out-of-grant tool and mcp.started was observed. "
            "RETEST denied the same request before the handler. Splunk did not decide."
        )
        page.get_by_role("button", name="Mark workflow complete").click()
        shot = shots / "explain_complete_1920.png"
        page.screenshot(path=str(shot), full_page=True)
        log["workflow"] = {
            "mode": "REPLAY",
            "attack_run_id": ATTACK_REPLAY,
            "retest_run_id": RETEST_REPLAY,
            "attack_has_replay_badge": "REPLAY" in attack_text and ATTACK_REPLAY in attack_text,
            "compare_has_allow_and_deny": "ALLOW" in compare_text and "DENY" in compare_text,
            "complete": "Workflow complete" in page.locator("[data-complete-feedback]").inner_text(),
            "screenshot_sha256": sha256(shot),
            "page_errors": log.get("page_errors", []),
        }

        # Viewport stand-ins for 200% and 400% (1920x1080 window). Genuine chrome.tabs.setZoom is a separate headed probe.
        for label, width, height in (("zoom200_standin", 960, 540), ("zoom400_standin", 480, 270)):
            page.set_viewport_size({"width": width, "height": height})
            page.goto(args.base_url + "/academy/labs/LAB-MCP-001", wait_until="networkidle")
            shot = shots / f"workshop_{label}.png"
            page.screenshot(path=str(shot), full_page=True)
            geo = geometry(page)
            log["zoom"][label] = {
                "method": "viewport_standin",
                "geometry": geo,
                "overflowX": geo["overflowX"],
                "clipped": clipped(page),
                "sha256": sha256(shot),
            }

        browser.close()

    log["ended"] = utc()
    log["screen_reader"] = "UNTESTED"
    payload = out / "qualification.json"
    payload.write_text(json.dumps(log, indent=2) + "\n")
    print(payload)
    print(json.dumps({"workflow_complete": log["workflow"]["complete"], "home_http": log["pages"]["home"]["http"]}, indent=2))
    return 0 if log["workflow"]["complete"] and log["pages"]["home"]["http"] == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
