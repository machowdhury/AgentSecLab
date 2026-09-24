#!/usr/bin/env python3
"""Capture and validate Goal/Identity Attack Service workbenches.

LIVE launches create fresh server-owned run IDs. The controlled error capture
intercepts the browser request and is therefore SIMULATED, not runtime evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABS = {
    "goal": {
        "lab_id": "LAB-AGENT-GOAL-INTEGRITY-001",
        "url": "http://127.0.0.1:5001/labs/LAB-AGENT-GOAL-INTEGRITY-001",
    },
    "identity": {
        "lab_id": "LAB-AGENT-DELEGATION-001",
        "url": "http://127.0.0.1:5001/labs/LAB-AGENT-DELEGATION-001",
    },
}
WIDTHS = (1920, 1440, 1280, 1024)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=str(ROOT / "docs" / "screenshots" / "authority-security-workbenches"),
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

    report: dict = {
        "evidence_classification": {
            "live_launches": "MEASURED",
            "layout_checks": "OBSERVED",
            "controlled_error": "SIMULATED",
            "zoom": "PARTIAL — CSS zoom emulation, not assistive technology",
            "screen_reader": "PARTIAL — no assistive-technology session",
        },
        "widths": list(WIDTHS),
        "labs": {},
    }
    failures: list[str] = []

    with sync_playwright() as playwright:
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        launch_options = {"headless": True}
        if chrome.is_file():
            launch_options["executable_path"] = str(chrome)
        browser = playwright.chromium.launch(**launch_options)

        for slug, config in LABS.items():
            context = browser.new_context(viewport={"width": 1440, "height": 1100})
            page = context.new_page()
            console_errors: list[str] = []
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            lab_report: dict = {
                "lab_id": config["lab_id"],
                "url": config["url"],
                "screenshots": [],
                "initial_overflow": {},
                "completed_overflow": {},
                "zoom_200_overflow": None,
                "keyboard_focus": False,
                "copy_run_id": False,
                "console_errors": [],
                "simulated_error_console": [],
                "attack": {},
                "retest": {},
            }
            report["labs"][slug] = lab_report

            for width in WIDTHS:
                page.set_viewport_size({"width": width, "height": 1100})
                response = page.goto(config["url"], wait_until="networkidle")
                if response is None or not response.ok:
                    failures.append(f"{slug}: HTTP load failed at {width}px")
                    continue
                no_overflow = page.evaluate(
                    "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth"
                )
                lab_report["initial_overflow"][str(width)] = bool(no_overflow)
                if not no_overflow:
                    failures.append(f"{slug}: initial horizontal overflow at {width}px")
                png = out / f"{args.label}_{slug}_initial_w{width}.png"
                page.screenshot(path=str(png), full_page=True)
                lab_report["screenshots"].append(str(png.relative_to(ROOT)))

            page.set_viewport_size({"width": 1440, "height": 1100})
            page.goto(config["url"], wait_until="networkidle")
            for _ in range(24):
                page.keyboard.press("Tab")
                if page.evaluate("() => document.activeElement && document.activeElement.id") in {
                    "attack-button",
                    "retest-button",
                }:
                    lab_report["keyboard_focus"] = True
                    break
            if not lab_report["keyboard_focus"]:
                failures.append(f"{slug}: launch controls not reached by keyboard")

            page.locator("#attack-button").click()
            page.wait_for_function(
                "() => document.getElementById('attack-response').textContent.trim().startsWith('{')",
                timeout=180000,
            )
            attack = json.loads(page.locator("#attack-response").text_content() or "")
            lab_report["attack"] = attack

            page.locator("#retest-button").click()
            page.wait_for_function(
                "() => document.getElementById('retest-response').textContent.trim().startsWith('{')",
                timeout=180000,
            )
            retest = json.loads(page.locator("#retest-response").text_content() or "")
            lab_report["retest"] = retest

            if slug == "goal":
                attack_runtime = attack.get("runtime", {})
                retest_runtime = retest.get("runtime", {})
                if attack_runtime.get("wrong_goal_lookup_policy_count") != 1:
                    failures.append("goal: ATTACK wrong-goal count was not 1")
                if retest_runtime.get("wrong_goal_lookup_policy_count") != 0:
                    failures.append("goal: RETEST wrong-goal count was not 0")
                if retest_runtime.get("in_task_lookup_policy_count") != 1:
                    failures.append("goal: RETEST permitted in-task count was not 1")
            else:
                if attack.get("runtime", {}).get("lookup_customer_tier_handler_count") != 1:
                    failures.append("identity: ATTACK privileged handler count was not 1")
                if retest.get("runtime", {}).get("lookup_customer_tier_handler_count") != 0:
                    failures.append("identity: RETEST privileged handler count was not 0")
                if retest.get("runtime", {}).get("who_authenticated") != "NOT PROVEN / NOT MODELED":
                    failures.append("identity: authentication limitation was not explicit")

            page.locator("[data-copy-target='primary-run-id']").click()
            page.wait_for_function(
                "() => { const value = document.getElementById('launch-status').textContent; "
                "return value.startsWith('Copied') || value.startsWith('Copy unavailable'); }"
            )
            lab_report["copy_run_id"] = "Copied" in page.locator("#launch-status").inner_text()
            if not lab_report["copy_run_id"]:
                failures.append(f"{slug}: Copy Run ID did not report success")

            for width in WIDTHS:
                page.set_viewport_size({"width": width, "height": 1100})
                no_overflow = page.evaluate(
                    "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth"
                )
                lab_report["completed_overflow"][str(width)] = bool(no_overflow)
                if not no_overflow:
                    failures.append(f"{slug}: completed horizontal overflow at {width}px")
                png = out / f"{args.label}_{slug}_completed_w{width}.png"
                page.screenshot(path=str(png), full_page=True)
                lab_report["screenshots"].append(str(png.relative_to(ROOT)))

            page.set_viewport_size({"width": 1440, "height": 1100})
            page.locator("#advanced").evaluate("(node) => { node.open = true; }")
            advanced = out / f"{args.label}_{slug}_advanced_1440.png"
            page.screenshot(path=str(advanced), full_page=True)
            lab_report["screenshots"].append(str(advanced.relative_to(ROOT)))

            page.evaluate("() => { document.body.style.zoom = '200%'; }")
            lab_report["zoom_200_overflow"] = bool(
                page.evaluate(
                    "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth"
                )
            )
            zoom = out / f"{args.label}_{slug}_zoom200.png"
            page.screenshot(path=str(zoom), full_page=True)
            lab_report["screenshots"].append(str(zoom.relative_to(ROOT)))
            page.evaluate("() => { document.body.style.zoom = ''; }")

            lab_report["console_errors"] = list(console_errors)
            if console_errors:
                failures.append(f"{slug}: browser console errors before simulation")
            console_errors.clear()
            page.route(
                "**/api/launch",
                lambda route: route.fulfill(
                    status=503,
                    content_type="application/json",
                    body='{"error":"controlled_capture_failure"}',
                ),
            )
            page.locator("#attack-button").click()
            page.wait_for_function(
                "() => document.getElementById('launch-status').textContent.startsWith('ERROR')"
            )
            error_png = out / f"{args.label}_{slug}_simulated_error.png"
            page.screenshot(path=str(error_png), full_page=False)
            lab_report["screenshots"].append(str(error_png.relative_to(ROOT)))
            lab_report["simulated_error_console"] = list(console_errors)
            context.close()

        browser.close()

    report["failures"] = failures
    report_path = out / f"{args.label}_validation.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(report_path.relative_to(ROOT)), "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
