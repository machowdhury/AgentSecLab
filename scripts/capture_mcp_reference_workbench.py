#!/usr/bin/env python3
"""Capture and validate the LAB-MCP-001 Attack workbench.

Browser checks are OBSERVED UI evidence. Launch results remain runtime evidence
and must be recorded separately with their fresh run.ids.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
URL = "http://127.0.0.1:5001/labs/LAB-MCP-001"


def overflow(page) -> dict[str, int | bool]:
    return page.evaluate(
        """() => ({
          scrollWidth: document.documentElement.scrollWidth,
          clientWidth: document.documentElement.clientWidth,
          overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1
        })"""
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=str(ROOT / "docs" / "screenshots" / "mcp-reference-workbench"),
    )
    parser.add_argument("--label", default="postbuild")
    parser.add_argument("--skip-live", action="store_true")
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    report: dict = {
        "url": URL,
        "label": args.label,
        "screenshots": [],
        "viewports": {},
        "console_errors": [],
        "page_errors": [],
        "keyboard": {},
        "zoom_200": {},
        "live": {"run": False},
    }

    with sync_playwright() as p:
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        launch_options = {"headless": True}
        if chrome.is_file():
            launch_options["executable_path"] = str(chrome)
        browser = p.chromium.launch(**launch_options)
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        page.on("console", lambda message: report["console_errors"].append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: report["page_errors"].append(str(error)))

        for width in (1920, 1440, 1280, 1024):
            page.set_viewport_size({"width": width, "height": 1000})
            page.goto(URL, wait_until="networkidle")
            page.get_by_role("heading", name="Tool Authorization", exact=True).wait_for()
            state = overflow(page)
            report["viewports"][str(width)] = state
            screenshot = out / f"{args.label}_attack_initial_{width}.png"
            page.screenshot(path=str(screenshot), full_page=True)
            report["screenshots"].append(str(screenshot.relative_to(ROOT)))

        page.set_viewport_size({"width": 1440, "height": 1000})
        page.goto(URL, wait_until="networkidle")
        page.keyboard.press("Tab")
        first_focus = page.evaluate("document.activeElement && document.activeElement.textContent.trim()")
        page.keyboard.press("Tab")
        second_focus = page.evaluate("document.activeElement && document.activeElement.textContent.trim()")
        report["keyboard"] = {
            "first_focus": first_focus,
            "second_focus": second_focus,
            "visible_focus_rule": page.evaluate(
                """() => {
                  const el = document.activeElement;
                  return el ? getComputedStyle(el).outlineStyle !== 'none' : false;
                }"""
            ),
        }

        page.evaluate("document.documentElement.style.zoom = '2'")
        report["zoom_200"] = overflow(page)
        zoom_png = out / f"{args.label}_attack_zoom200.png"
        page.screenshot(path=str(zoom_png), full_page=True)
        report["screenshots"].append(str(zoom_png.relative_to(ROOT)))
        page.evaluate("document.documentElement.style.zoom = '1'")

        if not args.skip_live:
            page.get_by_role("button", name="Run ATTACK").click()
            page.locator("#run-id[data-value]").wait_for(timeout=180_000)
            attack_id = page.locator("#run-id").get_attribute("data-value")
            page.get_by_role("button", name="Copy Run ID").click()
            page.wait_for_function(
                """() => document.querySelector('#copy-feedback')?.textContent.includes('copied')
                  || document.querySelector('#copy-feedback')?.textContent.includes('failed')"""
            )
            copy_feedback = page.locator("#copy-feedback").inner_text()
            page.get_by_role("button", name="Run RETEST").click()
            page.wait_for_function(
                """attack => {
                  const current = document.querySelector('#run-id')?.dataset.value;
                  return current && current !== attack;
                }""",
                arg=attack_id,
                timeout=180_000,
            )
            retest_id = page.locator("#run-id").get_attribute("data-value")
            live_png = out / f"{args.label}_attack_pair_1440.png"
            page.screenshot(path=str(live_png), full_page=True)
            report["screenshots"].append(str(live_png.relative_to(ROOT)))
            page.locator("#advanced").evaluate("element => { element.open = true; }")
            advanced_response = page.locator("#result-json").inner_text()
            advanced_request = page.locator("#request-json").inner_text()
            advanced_png = out / f"{args.label}_attack_advanced_1440.png"
            page.screenshot(path=str(advanced_png), full_page=True)
            report["screenshots"].append(str(advanced_png.relative_to(ROOT)))
            report["live"] = {
                "run": True,
                "attack_run_id": attack_id,
                "retest_run_id": retest_id,
                "copy_feedback": copy_feedback,
                "comparison_rows": page.locator("#comparison-body tr").count(),
                "advanced_response_contains_retest": bool(
                    retest_id and retest_id in advanced_response
                ),
                "advanced_request_is_closed_contract": all(
                    field in advanced_request
                    for field in ("lab_id", "specimen_id", "mode", "execution")
                )
                and not any(
                    field in advanced_request
                    for field in ("profile", "allowed_tools", "policy")
                ),
            }

        browser.close()

    report_path = out / f"{args.label}_validation.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    failed = (
        report["console_errors"]
        or report["page_errors"]
        or any(row["overflow"] for row in report["viewports"].values())
        or report["zoom_200"].get("overflow")
        or not report["keyboard"].get("visible_focus_rule")
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
