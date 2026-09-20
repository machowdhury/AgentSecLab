#!/usr/bin/env python3
"""Capture LAB-MEMORY-001 Dashboard Studio screenshots from Splunk Web.

Does not print credentials. Requires a READY local Splunk and Playwright.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABS = (
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
TOKENS = (
    "write_run_id",
    "run_id",
)
TOKEN_LABELS = {
    "write_run_id": "Investigate write specimen",
    "run_id": "Investigate recall specimen",
}
SPECIMEN_IDS = {
    "write_run_id": "a8407246-7992-4ad8-bd02-cb701e150f30",
    "run_id": "914c41ce-5123-49eb-892c-c948295dbc46",
    "baseline_write_run_id": "a8407246-7992-4ad8-bd02-cb701e150f30",
    "baseline_recall_run_id": "914c41ce-5123-49eb-892c-c948295dbc46",
    "attack_write_run_id": "05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464",
    "attack_recall_run_id": "b8737cd9-9b6b-48f2-acfa-178ae1446ddc",
    "retest_write_run_id": "060a0a72-ceb5-4b99-8330-98de81d8ae5e",
    "retest_recall_run_id": "5d5b9d1b-092d-4ddb-8422-4092d289cd49",
}
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
CLIP_TABS = ("LEARN", "COMPARE", "DETECT")


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
        default=str(ROOT / "docs" / "screenshots" / "lab-memory-security"),
        help="Directory for PNG + validation JSON",
    )
    parser.add_argument("--label", default="pass1", help="Filename prefix")
    parser.add_argument(
        "--tabs",
        default="",
        help="Comma-separated tab names to capture (default: all 10)",
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
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing from .env", file=sys.stderr)
        return 2

    tabs = tuple(t.strip().upper() for t in args.tabs.split(",") if t.strip()) or TABS
    report: dict = {
        "url": "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_memory_security",
        "tabs_found": [],
        "tabs_missing": [],
        "tokens_found": [],
        "tokens_missing": [],
        "token_values": {},
        "screenshots": [],
        "clipping_screenshots": [],
        "label": args.label,
        "tabs_requested": list(tabs),
        "viewports": [1440, 1024, 768],
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
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
                or value.startswith("Normal")
                or "defended" in value.lower()
                or "vulnerable" in value.lower()
                or "write" in value.lower()
                or "recall" in value.lower()
                or "scan" in value.lower()
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

        for width in (1024, 768):
            page.set_viewport_size({"width": width, "height": 1100})
            page.wait_for_timeout(1000)
            for tab in CLIP_TABS:
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
                )
            },
            indent=2,
        )
    )
    if report["tabs_missing"] or report["tokens_missing"] or len(report["tabs_found"]) != len(tabs):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
