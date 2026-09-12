#!/usr/bin/env python3
"""Capture AcmeBank and Attack Service screenshots. Does not print secrets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIDTHS = (1440, 1024, 768, 390)
HEIGHT = 1100


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="pass1")
    parser.add_argument("--acme", default="http://127.0.0.1:5000/")
    parser.add_argument("--attack", default="http://127.0.0.1:5001/")
    args = parser.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright is not installed", file=sys.stderr)
        return 2

    report: dict = {
        "label": args.label,
        "widths": list(WIDTHS),
        "screenshots": [],
        "states": {},
    }

    acme_dir = ROOT / "docs" / "screenshots" / "acmebank"
    atk_dir = ROOT / "docs" / "screenshots" / "attack-ui"
    acme_dir.mkdir(parents=True, exist_ok=True)
    atk_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        def snap(page, path: Path) -> None:
            page.screenshot(path=str(path), full_page=True)
            report["screenshots"].append(str(path.relative_to(ROOT)))

        page = browser.new_page()
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": HEIGHT})
            page.goto(args.acme, wait_until="domcontentloaded")
            page.wait_for_selector("#loan-form")
            snap(page, acme_dir / f"{args.label}_ready_{width}.png")
            page.goto(args.attack, wait_until="domcontentloaded")
            page.wait_for_selector("#fire")
            snap(page, atk_dir / f"{args.label}_ready_{width}.png")

        page.set_viewport_size({"width": 1440, "height": HEIGHT})
        page.goto(args.acme, wait_until="domcontentloaded")
        page.wait_for_selector("#loan-form")
        page.locator("#submit-loan").click()
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state === 'RUNNING'",
            timeout=5000,
        )
        snap(page, acme_dir / f"{args.label}_running.png")
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state !== 'RUNNING'",
            timeout=180000,
        )
        acme_state = page.locator("#ui-status").inner_text()
        report["states"]["acmebank"] = acme_state
        snap(page, acme_dir / f"{args.label}_{acme_state.lower()}.png")
        page.set_viewport_size({"width": 390, "height": HEIGHT})
        snap(page, acme_dir / f"{args.label}_{acme_state.lower()}_390.png")

        page.set_viewport_size({"width": 1440, "height": HEIGHT})
        page.goto(args.attack, wait_until="domcontentloaded")
        page.locator("#fire").click()
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state === 'RUNNING'",
            timeout=5000,
        )
        snap(page, atk_dir / f"{args.label}_running.png")
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state !== 'RUNNING'",
            timeout=180000,
        )
        atk_state = page.locator("#ui-status").inner_text()
        report["states"]["attack"] = atk_state
        snap(page, atk_dir / f"{args.label}_{atk_state.lower()}.png")
        page.set_viewport_size({"width": 390, "height": HEIGHT})
        snap(page, atk_dir / f"{args.label}_{atk_state.lower()}_390.png")
        browser.close()

    out = ROOT / "docs" / "screenshots" / f"web-ui-{args.label}-validation.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
