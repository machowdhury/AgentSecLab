#!/usr/bin/env python3
"""Capture Phase 14E learner surfaces: PI PROVE, MCP workshop, Attack Service, Home.

Does not print credentials. Requires READY Splunk + Playwright + Attack Service.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_TABS = (
    "LEARN",
    "BASELINE",
    "ATTACK",
    "OBSERVE",
    "HUNT",
    "DETECT",
    "DEFEND",
    "RETEST",
    "COMPARE",
    "PROVE",
)
PI_TABS = MCP_TABS
WIDTHS = (1440, 1280, 1024)
TABLE_TABS = {
    "BASELINE",
    "ATTACK",
    "OBSERVE",
    "HUNT",
    "DETECT",
    "RETEST",
    "COMPARE",
    "PROVE",
}


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


def http_status(page, url: str) -> int:
    response = page.goto(url, wait_until="domcontentloaded")
    return int(response.status) if response is not None else 0


def click_tab(page, name: str) -> bool:
    loc = page.get_by_role("tab", name=name)
    if loc.count() == 0:
        loc = page.get_by_text(name, exact=True)
    if loc.count() == 0:
        return False
    loc.first.click()
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="pass1")
    parser.add_argument(
        "--skip-launch",
        action="store_true",
        help="Do not click LIVE ATTACK/RETEST (use after a prior launch capture).",
    )
    args = parser.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright is not installed", file=sys.stderr)
        return 2

    password = load_env_value("SPLUNK_PASSWORD")
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing from .env", file=sys.stderr)
        return 2

    pi_dir = ROOT / "docs" / "screenshots" / "lab-pi-001"
    mcp_dir = ROOT / "docs" / "screenshots" / "lab-mcp-001"
    atk_dir = ROOT / "docs" / "screenshots" / "attack-service-mcp"
    home_dir = ROOT / "docs" / "screenshots" / "agentsec-home"
    for path in (pi_dir, mcp_dir, atk_dir, home_dir):
        path.mkdir(parents=True, exist_ok=True)

    report: dict = {
        "label": args.label,
        "http": {},
        "tabs": {},
        "screenshots": [],
        "defects": [],
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})

        report["http"]["attack_home"] = http_status(page, "http://127.0.0.1:5001/")
        report["http"]["attack_mcp"] = http_status(page, "http://127.0.0.1:5001/labs/LAB-MCP-001")
        report["http"]["attack_unknown"] = http_status(page, "http://127.0.0.1:5001/labs/LAB-ZZZ-001")

        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)

        home_url = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
        pi_url = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001"
        mcp_url = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_mcp_001"
        report["http"]["home"] = http_status(page, home_url)
        report["http"]["pi"] = http_status(page, pi_url)
        report["http"]["mcp"] = http_status(page, mcp_url)

        def snap(path: Path, full: bool = True) -> None:
            page.screenshot(path=str(path), full_page=full)
            report["screenshots"].append(str(path.relative_to(ROOT)))

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1100})
            page.goto(home_url, wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            snap(home_dir / f"{args.label}_home_{width}.png")

            page.goto("http://127.0.0.1:5001/", wait_until="domcontentloaded")
            page.wait_for_timeout(800)
            snap(ROOT / "docs" / "screenshots" / "attack-ui" / f"{args.label}_pi_{width}.png")
            page.goto("http://127.0.0.1:5001/labs/LAB-MCP-001", wait_until="domcontentloaded")
            page.wait_for_timeout(800)
            snap(atk_dir / f"{args.label}_ready_{width}.png")

        page.set_viewport_size({"width": 1440, "height": 1100})
        page.goto("http://127.0.0.1:5001/labs/LAB-MCP-001", wait_until="domcontentloaded")
        page.wait_for_selector("#fire-attack")
        snap(atk_dir / f"{args.label}_viewport_1440.png", full=False)
        if not args.skip_launch:
            page.locator("#fire-attack").click()
            page.wait_for_function(
                "() => document.getElementById('attack-run-id').value.length > 10",
                timeout=180000,
            )
            snap(atk_dir / f"{args.label}_attack_result_1440.png", full=False)
            page.locator("#fire-retest").click()
            page.wait_for_function(
                "() => document.getElementById('retest-run-id').value.length > 10",
                timeout=180000,
            )
            snap(atk_dir / f"{args.label}_retest_result_1440.png", full=False)
            report["attack_service_run_ids"] = {
                "attack": page.locator("#attack-run-id").input_value(),
                "retest": page.locator("#retest-run-id").input_value(),
            }

        page.goto(pi_url, wait_until="domcontentloaded")
        page.wait_for_timeout(4000)
        submit = page.get_by_role("button", name="Submit")
        if submit.count() > 0 and submit.first.is_enabled():
            submit.first.click()
            page.wait_for_timeout(2500)
        found = []
        missing = []
        for tab in PI_TABS:
            if click_tab(page, tab):
                found.append(tab)
            else:
                missing.append(tab)
        report["tabs"]["pi"] = {"found": found, "missing": missing}
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1100})
            click_tab(page, "PROVE")
            page.wait_for_timeout(2500)
            snap(pi_dir / f"{args.label}_prove_{width}.png")
        page.set_viewport_size({"width": 1440, "height": 1100})
        click_tab(page, "HUNT")
        page.wait_for_timeout(4000)
        snap(pi_dir / f"{args.label}_hunt_regression_1440.png")

        page.goto(mcp_url, wait_until="domcontentloaded")
        page.wait_for_timeout(4000)
        submit = page.get_by_role("button", name="Submit")
        if submit.count() > 0 and submit.first.is_enabled():
            submit.first.click()
            page.wait_for_timeout(2500)
        found = []
        missing = []
        for tab in MCP_TABS:
            if not click_tab(page, tab):
                missing.append(tab)
                continue
            found.append(tab)
            page.wait_for_timeout(8000 if tab in TABLE_TABS else 2000)
            snap(mcp_dir / f"{args.label}_{tab.lower()}.png")
        report["tabs"]["mcp"] = {"found": found, "missing": missing}
        for width, suffix in ((1280, "w1280"), (1024, "w1024")):
            page.set_viewport_size({"width": width, "height": 1100})
            for tab in ("LEARN", "ATTACK", "HUNT", "PROVE"):
                if not click_tab(page, tab):
                    continue
                page.wait_for_timeout(4000)
                snap(mcp_dir / f"{args.label}_{suffix}_{tab.lower()}.png")

        browser.close()

    out = ROOT / "docs" / "screenshots" / "lab-mcp-001" / f"{args.label}_phase14e_validation.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if any(code >= 400 for key, code in report["http"].items() if key != "attack_unknown"):
        return 1
    if report["http"].get("attack_unknown") != 400:
        return 1
    if report["tabs"].get("mcp", {}).get("missing") or report["tabs"].get("pi", {}).get("missing"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
