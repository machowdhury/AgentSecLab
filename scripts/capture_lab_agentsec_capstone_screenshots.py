#!/usr/bin/env python3
"""Capture LAB-AGENTSEC-CAPSTONE-001 Dashboard Studio screenshots from Splunk Web.

Does not print credentials. Requires a READY local Splunk and Playwright.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABS = (
    "MISSION",
    "ARCHITECTURE",
    "ATTACK",
    "INVESTIGATE",
    "TRACE",
    "AUTHORITY",
    "DEFEND",
    "RETEST",
    "COMPARE",
    "PROVE",
)
TOKENS = (
    "retrieve_run_id",
    "write_run_id",
    "run_id",
)
TOKEN_LABELS = {
    "retrieve_run_id": "Investigate retrieve specimen",
    "write_run_id": "Investigate write specimen",
    "run_id": "Investigate recall specimen",
}
SPECIMEN_IDS = {
    "retrieve_run_id": "5a15fe04-4bb1-4f70-8ec0-ab83f423dcde",
    "write_run_id": "5dd71f94-5b12-4c52-b5ed-93a0b6832d45",
    "run_id": "3d2b66a1-9ef1-4b1d-b993-444db50fd3ee",
    "baseline_retrieve_run_id": "5a15fe04-4bb1-4f70-8ec0-ab83f423dcde",
    "baseline_write_run_id": "5dd71f94-5b12-4c52-b5ed-93a0b6832d45",
    "baseline_recall_run_id": "3d2b66a1-9ef1-4b1d-b993-444db50fd3ee",
    "attack_retrieve_run_id": "2a248113-7436-46a7-9b1d-0243489ac000",
    "attack_write_run_id": "348c8f18-fdfb-4501-ad8a-3f1bcda64c34",
    "attack_recall_run_id": "2437f64a-fff4-424f-8a83-0f04285662e4",
    "retest_retrieve_run_id": "f9015037-651d-4207-ac57-4f3ea1abc673",
    "retest_write_run_id": "3f8d6305-2d3b-4988-9e65-dc99b7ac10de",
    "retest_recall_run_id": "8d2c016f-cadc-4463-939a-23a183221b3d",
}
TABLE_TABS = {
    "ATTACK",
    "INVESTIGATE",
    "TRACE",
    "AUTHORITY",
    "RETEST",
    "COMPARE",
    "PROVE",
}
CLIP_TABS = ("MISSION", "ARCHITECTURE", "COMPARE")
REQUIRED_TABS = (
    "MISSION",
    "ARCHITECTURE",
    "ATTACK",
    "INVESTIGATE",
    "AUTHORITY",
    "DEFEND",
    "RETEST",
    "COMPARE",
    "PROVE",
)
WIDTHS = (1440, 1280, 1024)


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


def click_tab(page, tab: str):
    loc = page.get_by_role("tab", name=tab)
    if loc.count() == 0:
        loc = page.get_by_text(tab, exact=True)
    if loc.count() == 0:
        return False
    loc.first.click()
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=str(ROOT / "docs" / "screenshots" / "lab-agentsec-capstone"),
        help="Directory for PNG + validation JSON",
    )
    parser.add_argument("--label", default="pass16b", help="Filename prefix")
    parser.add_argument(
        "--skip-launch",
        action="store_true",
        help="Skip Attack Service LIVE click capture",
    )
    parser.add_argument(
        "--only-launch",
        action="store_true",
        help="Capture Attack Service launcher only",
    )
    parser.add_argument(
        "--tabs",
        default="",
        help="Comma-separated tab names to capture (default: all 11)",
    )
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "ERROR: playwright is not installed. pip install playwright && playwright install chromium",
            file=sys.stderr,
        )
        return 2

    password = load_env_value("SPLUNK_PASSWORD")
    if not args.only_launch and not password:
        print("ERROR: SPLUNK_PASSWORD missing from .env", file=sys.stderr)
        return 2

    tabs = tuple(t.strip().upper() for t in args.tabs.split(",") if t.strip()) or TABS
    report: dict = {
        "url": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agentsec_capstone",
        "tabs_found": [],
        "tabs_missing": [],
        "tokens_found": [],
        "tokens_missing": [],
        "token_values": {},
        "screenshots": [],
        "clipping_screenshots": [],
        "label": args.label,
        "tabs_requested": list(tabs),
        "viewports": list(WIDTHS),
        "http": {},
        "attack_service": {},
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        atk_dir = ROOT / "docs" / "screenshots" / "attack-service-capstone"
        atk_dir.mkdir(parents=True, exist_ok=True)
        if not args.skip_launch:
            for width in WIDTHS:
                page.set_viewport_size({"width": width, "height": 1100})
                resp = page.goto(
                    "http://127.0.0.1:5001/labs/LAB-AGENTSEC-CAPSTONE-001",
                    wait_until="domcontentloaded",
                )
                report["http"][f"attack_{width}"] = int(resp.status) if resp is not None else 0
                page.wait_for_timeout(1200)
                png = atk_dir / f"{args.label}_launcher_{width}.png"
                page.screenshot(path=str(png), full_page=True)
                report["screenshots"].append(str(png.relative_to(ROOT)))
            page.set_viewport_size({"width": 1440, "height": 1100})
            page.goto(
                "http://127.0.0.1:5001/labs/LAB-AGENTSEC-CAPSTONE-001",
                wait_until="networkidle",
            )
            page.wait_for_selector("#fire-attack")
            page.wait_for_timeout(800)
            page.locator("#fire-attack").click()
            page.wait_for_function(
                "() => (document.getElementById('attack-run-id') && document.getElementById('attack-run-id').value.length > 10)",
                timeout=180000,
            )
            page.wait_for_timeout(1500)
            png = atk_dir / f"{args.label}_attack_results_1440.png"
            page.screenshot(path=str(png), full_page=True)
            report["screenshots"].append(str(png.relative_to(ROOT)))
            report["attack_service"]["attack_retrieve_run_id"] = page.locator(
                "#attack-retrieve-run-id"
            ).input_value()
            report["attack_service"]["attack_write_run_id"] = page.locator(
                "#attack-write-run-id"
            ).input_value()
            report["attack_service"]["attack_recall_run_id"] = page.locator(
                "#attack-recall-run-id"
            ).input_value()
            page.locator("#fire-retest").click()
            page.wait_for_function(
                "() => (document.getElementById('retest-run-id') && document.getElementById('retest-run-id').value.length > 10)",
                timeout=180000,
            )
            page.wait_for_timeout(1500)
            png = atk_dir / f"{args.label}_retest_results_1440.png"
            page.screenshot(path=str(png), full_page=True)
            report["screenshots"].append(str(png.relative_to(ROOT)))
            report["attack_service"]["retest_retrieve_run_id"] = page.locator(
                "#retest-retrieve-run-id"
            ).input_value()
            report["attack_service"]["retest_write_run_id"] = page.locator(
                "#retest-write-run-id"
            ).input_value()
            report["attack_service"]["retest_recall_run_id"] = page.locator(
                "#retest-recall-run-id"
            ).input_value()
        if not args.only_launch:
            page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
            page.locator("input[name='username']").fill("admin")
            page.locator("input[name='password']").fill(password)
            page.locator("input[type='submit'], button[type='submit']").first.click()
            page.wait_for_url("**/app/**", timeout=60000)

            page.goto(report["url"], wait_until="domcontentloaded")
            page.wait_for_timeout(4000)
            submit = page.get_by_role("button", name="Submit")
            if submit.count() > 0 and submit.first.is_enabled():
                submit.first.click()
                page.wait_for_timeout(3000)

            for token in TOKENS:
                label = TOKEN_LABELS[token]
                loc = page.get_by_label(label, exact=True)
                if loc.count() == 0:
                    loc = page.get_by_role("combobox", name=label)
                if loc.count() == 0:
                    loc = page.get_by_role("textbox", name=label)
                if loc.count() == 0:
                    report["tokens_missing"].append(token)
                    continue
                try:
                    value = loc.first.input_value()
                except Exception:
                    value = (loc.first.inner_text() or "").strip()
                report["token_values"][token] = value
                expected = SPECIMEN_IDS[token]
                canonical = (
                    value == expected
                    or expected in value
                    or value.startswith("Baseline")
                    or value.startswith("Attack")
                    or value.startswith("Retest")
                    or "defended" in value.lower()
                    or "vulnerable" in value.lower()
                    or "retrieve" in value.lower()
                    or "write" in value.lower()
                    or "recall" in value.lower()
                )
                if canonical:
                    report["tokens_found"].append(token)
                else:
                    report["tokens_missing"].append(token)

            for tab in tabs:
                if not click_tab(page, tab):
                    report["tabs_missing"].append(tab)
                    continue
                page.wait_for_timeout(12000 if tab in TABLE_TABS else 2000)
                report["tabs_found"].append(tab)
                png = out / f"{args.label}_{tab.lower()}.png"
                page.screenshot(path=str(png), full_page=True)
                report["screenshots"].append(str(png.relative_to(ROOT)))

            overview = out / f"{args.label}_overview.png"
            page.screenshot(path=str(overview), full_page=False)
            report["screenshots"].insert(0, str(overview.relative_to(ROOT)))

            for width in (1280, 1024):
                page.set_viewport_size({"width": width, "height": 1100})
                page.wait_for_timeout(1000)
                for tab in REQUIRED_TABS:
                    if not click_tab(page, tab):
                        continue
                    page.wait_for_timeout(4000 if tab in TABLE_TABS else 1500)
                    png = out / f"{args.label}_w{width}_{tab.lower()}.png"
                    page.screenshot(path=str(png), full_page=True)
                    rel = str(png.relative_to(ROOT))
                    report["clipping_screenshots"].append(rel)
                    report["screenshots"].append(rel)

        browser.close()

    (out / f"{args.label}_validation.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "tabs_found",
                    "tabs_missing",
                    "tokens_found",
                    "tokens_missing",
                    "token_values",
                    "screenshots",
                    "clipping_screenshots",
                    "http",
                    "attack_service",
                )
            },
            indent=2,
        )
    )
    if args.only_launch:
        return 0 if report["attack_service"].get("attack_recall_run_id") else 1
    if report["tabs_missing"] or report["tokens_missing"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
