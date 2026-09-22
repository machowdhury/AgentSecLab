#!/usr/bin/env python3
"""Capture Phase 17D release surfaces. Does not print credentials. Does not launch attacks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIDTHS = (1440, 1280, 1024)
HEIGHT = 1100
PAGES = (
    ("home", "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"),
    ("pi", "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001"),
    ("mcp", "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_mcp_001"),
    ("memory", "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_memory_security"),
    ("goal", "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agent_goal_integrity"),
    ("capstone", "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agentsec_capstone"),
    ("mastery", "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_mastery"),
)
ATTACK = "http://127.0.0.1:5001/"


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=str(ROOT / "docs" / "screenshots" / "agentsec-academy-17d"),
    )
    parser.add_argument("--label", default="pass17d")
    args = parser.parse_args()
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright is not installed", file=sys.stderr)
        return 2

    password = load_env_value("SPLUNK_PASSWORD")
    if not password:
        print("ERROR: SPLUNK_PASSWORD missing from .env", file=sys.stderr)
        return 2

    report: dict = {
        "label": args.label,
        "viewports": list(WIDTHS),
        "screenshots": [],
        "defects": [],
        "http": {},
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": HEIGHT})
        page.goto("http://127.0.0.1:8000/en-US/account/login", wait_until="domcontentloaded")
        page.locator("input[name='username']").fill("admin")
        page.locator("input[name='password']").fill(password)
        page.locator("input[type='submit'], button[type='submit']").first.click()
        page.wait_for_url("**/app/**", timeout=60000)

        for name, url in PAGES:
            page.set_viewport_size({"width": 1440, "height": HEIGHT})
            resp = page.goto(url, wait_until="domcontentloaded")
            code = resp.status if resp else 0
            report["http"][name] = code
            if code >= 400:
                report["defects"].append(f"BLOCKER {name} HTTP {code}")
            page.wait_for_timeout(3500)
            body = page.inner_text("body")
            if "HTTP 400" in body or "Bad Request" in body[:200]:
                report["defects"].append(f"HIGH {name} body looks like HTTP 400")
            if name == "home" and "ORIENT" not in body and "START" not in body:
                report["defects"].append("HIGH Home missing START/ORIENT")
            if name == "pi" and ("LIVE EXPERIMENT" not in body or "REPLAY SPECIMEN" not in body):
                report["defects"].append("HIGH PI missing LIVE vs REPLAY labels")
            for width in WIDTHS:
                page.set_viewport_size({"width": width, "height": HEIGHT})
                page.wait_for_timeout(300)
                shot = out / f"{args.label}_{name}_{width}.png"
                page.screenshot(path=str(shot), full_page=True)
                report["screenshots"].append(str(shot.relative_to(ROOT)))

        page.goto(ATTACK, wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        attack_text = page.inner_text("body")
        if "REQUIRES REVALIDATION" not in attack_text:
            report["defects"].append("HIGH Attack Service ATLAS qualifier missing")
        if "AML.T0054" not in attack_text:
            report["defects"].append("HIGH Attack Service missing AML.T0054")
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": HEIGHT})
            page.wait_for_timeout(300)
            shot = out / f"{args.label}_attack_{width}.png"
            page.screenshot(path=str(shot), full_page=True)
            report["screenshots"].append(str(shot.relative_to(ROOT)))

        browser.close()

    (out / f"{args.label}_validation.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({k: report[k] for k in ("label", "defects", "http", "screenshots")}, indent=2))
    blockers = [d for d in report["defects"] if d.startswith("BLOCKER") or d.startswith("HIGH")]
    return 1 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
