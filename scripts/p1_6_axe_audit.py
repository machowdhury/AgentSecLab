#!/usr/bin/env python3
"""Automated axe-core audit of the Academy pages and every workshop step (WCAG 2.x A/AA rules).

usage: p1_6_axe_audit.py --axe /path/to/axe.min.js --base http://127.0.0.1:5001 --out FILE

Automated rules are not a screen-reader test. The test browser context bypasses
CSP only to inject axe; the served CSP is not changed. The workshop is driven with
the recorded REPLAY pair, so no LIVE run is launched.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

PAGES = ("/academy", "/academy/foundations", "/academy/path", "/academy/status", "/academy/labs/LAB-MCP-001")
STEPS = ("start", "baseline", "predict", "attack", "investigate", "defend", "retest", "compare", "explain")
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]


def audit(page, axe_source: str) -> dict:
    page.evaluate(axe_source)
    result = page.evaluate("tags => axe.run(document, {runOnly: {type: 'tag', values: tags}})", TAGS)
    return {
        "violations": [{"id": v["id"], "impact": v["impact"], "nodes": len(v["nodes"]),
                        "targets": [n["target"] for n in v["nodes"][:5]]} for v in result["violations"]],
        "incomplete": [{"id": v["id"], "nodes": len(v["nodes"])} for v in result["incomplete"]],
        "passes": len(result["passes"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--axe", required=True, type=Path)
    parser.add_argument("--base", default="http://127.0.0.1:5001")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    axe_source = args.axe.read_text(encoding="utf-8")
    report = {"queried_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "base": args.base,
              "tags": TAGS, "pages": {}, "workshop_steps": {}}
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1280, "height": 900}, bypass_csp=True)
        page = ctx.new_page()
        for path in PAGES:
            page.goto(args.base + path, wait_until="networkidle")
            report["pages"][path] = audit(page, axe_source)
        page.goto(args.base + "/academy/labs/LAB-MCP-001#predict", wait_until="networkidle")
        page.locator('input[name="predict-control"][value="UNSURE"]').check()
        page.locator('input[name="predict-execution"][value="UNSURE"]').check()
        page.locator("[data-lock-prediction]").click()
        page.wait_for_timeout(800)
        switch = page.locator("[data-switch-replay]")
        if switch.is_visible():
            switch.click()
        else:
            page.locator('[data-use-replay="ATTACK"]').click()
            page.wait_for_timeout(800)
            page.goto(args.base + "/academy/labs/LAB-MCP-001#retest", wait_until="networkidle")
            page.locator('[data-use-replay="RETEST"]').click()
        page.wait_for_timeout(1500)
        page.goto(args.base + "/academy/labs/LAB-MCP-001#baseline", wait_until="networkidle")
        page.locator("[data-load-baseline]").click()
        page.wait_for_timeout(1000)
        for step in STEPS:
            page.locator(f'[data-step-link="{step}"]').click(force=True)
            page.wait_for_timeout(1200)
            if step == "investigate":
                first = page.locator("[data-questions] li").first
                first.locator("input[type=radio]").first.check()
                first.get_by_role("button", name="Check against the evidence").click()
            report["workshop_steps"][step] = audit(page, axe_source)
        browser.close()
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    total = 0
    for group in ("pages", "workshop_steps"):
        for name, res in report[group].items():
            total += len(res["violations"])
            print(group, name, "violations:", [(v["id"], v["impact"], v["nodes"]) for v in res["violations"]] or "none",
                  "incomplete:", [v["id"] for v in res["incomplete"]] or "none", "passes:", res["passes"])
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
