#!/usr/bin/env python3
"""Capture a LIVE AcmeBank COMPLETED screenshot. Does not stub the model."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots" / "acmebank"
PNG = OUT / "pass2_completed.png"
JSON_OUT = OUT / "pass2_completed_validation.json"
ACME = "http://127.0.0.1:5000"


def main() -> int:
    health = requests.get(f"{ACME}/health", timeout=10).json()
    if not health.get("ollama_reachable"):
        print("STOP: AcmeBank reports ollama_reachable=false", file=sys.stderr)
        print(json.dumps(health), file=sys.stderr)
        return 2

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright is not installed", file=sys.stderr)
        return 2

    report: dict = {
        "health": {
            "ollama_reachable": health.get("ollama_reachable"),
            "ollama_model": health.get("ollama_model"),
            "security.profile": health.get("security.profile"),
        },
        "ui_states": [],
    }

    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        page.goto(f"{ACME}/", wait_until="domcontentloaded")
        page.wait_for_selector("#loan-form")
        ready = page.locator("#ui-status").get_attribute("data-state")
        report["ui_states"].append(ready)
        if ready != "READY":
            print(f"STOP: expected READY, got {ready}", file=sys.stderr)
            browser.close()
            return 1

        page.locator("#submit-loan").click()
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state === 'RUNNING'",
            timeout=5000,
        )
        report["ui_states"].append(page.locator("#ui-status").get_attribute("data-state"))

        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state !== 'RUNNING'",
            timeout=240000,
        )
        state = page.locator("#ui-status").get_attribute("data-state")
        report["ui_states"].append(state)
        summary = page.locator("#status-live").inner_text()
        report["status_live"] = summary
        run_id = page.locator("#run-id").input_value()
        report["run_id"] = run_id

        details = page.locator("#tech-details")
        if details.count():
            page.locator("#result-json").wait_for(state="attached", timeout=5000)
            raw = page.locator("#result-json").inner_text()
            try:
                body = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                body = {"_parse_error": True, "_raw": raw[:500]}
            report["runtime"] = {
                "terminal": body.get("terminal"),
                "blocked": body.get("blocked"),
                "llm_call_count": body.get("llm_call_count"),
                "error_stage": body.get("error_stage"),
                "testbed_mode": body.get("testbed_mode"),
                "profile": body.get("profile"),
                "run_id": body.get("run_id"),
                "hops": [
                    {
                        "hop.index": hop.get("hop.index"),
                        "control.decision": hop.get("control.decision"),
                        "operation.executed": hop.get("operation.executed"),
                        "llm.started": hop.get("llm.started"),
                    }
                    for hop in body.get("hops") or []
                ],
            }

        page.screenshot(path=str(PNG), full_page=True)
        report["screenshot"] = str(PNG.relative_to(ROOT))
        body_text = page.inner_text("body")
        report["allow_described_as_execution"] = (
            "ALLOW is execution" in body_text or "ALLOW means the model ran" in body_text
        )
        browser.close()

    JSON_OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if state != "COMPLETED":
        print(f"STOP: UI state is {state}, not COMPLETED", file=sys.stderr)
        return 1
    runtime = report.get("runtime") or {}
    if runtime.get("terminal") != "completed_allowed":
        print("STOP: runtime terminal is not completed_allowed", file=sys.stderr)
        return 1
    if runtime.get("llm_call_count", 0) < 1:
        print("STOP: llm_call_count is not evidence of governed execution", file=sys.stderr)
        return 1
    if not run_id:
        print("STOP: run.id missing from UI", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
