#!/usr/bin/env python3
"""Check unchanged workbenches after Capstone route integration."""

from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT
    / "docs"
    / "screenshots"
    / "lab-agentsec-capstone"
    / "capstone-integration_shared-regression.json"
)
LABS = {
    "mcp": "LAB-MCP-001",
    "rag": "LAB-RAG-CONTEXT",
    "memory": "LAB-MEMORY-001",
    "goal": "LAB-AGENT-GOAL-INTEGRITY-001",
    "identity": "LAB-AGENT-DELEGATION-001",
}


def main() -> int:
    report: dict = {"labs": {}, "failures": []}
    chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=str(chrome) if chrome.is_file() else None,
        )
        for name, lab_id in LABS.items():
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            console_errors: list[str] = []
            page_errors: list[str] = []
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: page_errors.append(str(error)))
            checks = {}
            for width in (1440, 1024):
                page.set_viewport_size({"width": width, "height": 1000})
                response = page.goto(
                    f"http://127.0.0.1:5001/labs/{lab_id}",
                    wait_until="networkidle",
                )
                primary_action = page.locator(".mode-actions button").first
                primary_action.focus()
                checks[str(width)] = {
                    "http": response.status if response else 0,
                    "no_horizontal_overflow": page.evaluate(
                        "document.documentElement.scrollWidth <= window.innerWidth"
                    ),
                    "initial_hierarchy": page.locator(".mission").count() == 1,
                    "comparison": page.locator(".comparison-section").count() == 1,
                    "advanced": page.locator("#advanced").count() == 1,
                    "focus_outline": primary_action.evaluate(
                        "(node) => { const s=getComputedStyle(node); "
                        "return `${s.outlineStyle} ${s.outlineWidth}`; }"
                    ),
                }
            result = {
                "lab_id": lab_id,
                "checks": checks,
                "console_errors": console_errors,
                "page_errors": page_errors,
            }
            report["labs"][name] = result
            for width, values in checks.items():
                if (
                    values["http"] != 200
                    or not values["no_horizontal_overflow"]
                    or not values["initial_hierarchy"]
                    or not values["comparison"]
                    or not values["advanced"]
                    or values["focus_outline"].startswith("none")
                ):
                    report["failures"].append(f"{name} {width}: {values}")
            if console_errors or page_errors:
                report["failures"].append(
                    f"{name}: console={console_errors} page={page_errors}"
                )
            page.close()
        browser.close()
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT.relative_to(ROOT)), "failures": report["failures"]}, indent=2))
    return 1 if report["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
