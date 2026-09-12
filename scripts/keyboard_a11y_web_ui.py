#!/usr/bin/env python3
"""MEASURED keyboard-navigation check for AcmeBank and Attack Service.

Does not claim WCAG or screen-reader certification.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots" / "web-ui-keyboard-validation.json"


def focused(page) -> dict:
    return page.evaluate(
        """() => {
          const el = document.activeElement;
          if (!el) return {tag: null, id: null, text: null};
          const style = window.getComputedStyle(el);
          const outline = style.outlineStyle + " " + style.outlineWidth + " " + style.outlineColor;
          return {
            tag: el.tagName,
            id: el.id || null,
            type: el.getAttribute("type"),
            text: (el.innerText || el.value || "").slice(0, 80),
            outline,
            outlineWidth: style.outlineWidth,
            disabled: Boolean(el.disabled)
          };
        }"""
    )


def tab_until(page, predicate, limit: int = 20) -> list[dict]:
    seen: list[dict] = []
    for _ in range(limit):
        page.keyboard.press("Tab")
        info = focused(page)
        seen.append(info)
        if predicate(info):
            return seen
    return seen


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright is not installed", file=sys.stderr)
        return 2

    report: dict = {
        "class": "MEASURED",
        "limitation": (
            "Playwright Tab/Enter/Space on Chromium. Not a screen-reader test. "
            "Not a WCAG certification."
        ),
        "acmebank": {},
        "attack": {},
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})

        page.goto("http://127.0.0.1:5000/", wait_until="domcontentloaded")
        page.wait_for_selector("#loan-form")
        page.locator(".skip-link").focus()
        skip = focused(page)
        page.keyboard.press("Tab")
        after_skip = focused(page)
        acme_order = [skip, after_skip]
        while after_skip.get("id") != "submit-loan" and len(acme_order) < 12:
            page.keyboard.press("Tab")
            after_skip = focused(page)
            acme_order.append(after_skip)
        submit_focus = after_skip
        page.keyboard.press("Enter")
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state === 'RUNNING'",
            timeout=5000,
        )
        running_disabled = page.locator("#submit-loan").is_disabled()
        page.keyboard.press("Enter")
        still_running_or_later = page.locator("#ui-status").get_attribute("data-state")
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state !== 'RUNNING'",
            timeout=240000,
        )
        copy_path = tab_until(page, lambda i: i.get("id") == "copy-run-id", limit=25)
        copy_focused = any(i.get("id") == "copy-run-id" for i in copy_path)
        run_focused = any(i.get("id") == "run-id" for i in copy_path)
        visible_outline = any(
            i.get("outlineWidth") and i.get("outlineWidth") != "0px" for i in acme_order + [submit_focus]
        )
        report["acmebank"] = {
            "skip_link_can_focus": skip.get("tag") == "A" and (skip.get("text") or "").startswith("Skip"),
            "skip_link_tag": skip.get("tag"),
            "skip_link_text": skip.get("text"),
            "textarea_reached": any(i.get("id") == "input" for i in acme_order),
            "submit_reached": submit_focus.get("id") == "submit-loan",
            "enter_activated_submit": True,
            "running_button_disabled": running_disabled,
            "second_enter_while_running_state": still_running_or_later,
            "run_id_reachable": run_focused,
            "copy_run_id_reachable": copy_focused,
            "focus_indicator_nonzero_outline": visible_outline,
            "focus_samples": acme_order[:6] + [submit_focus],
            "final_state": page.locator("#ui-status").get_attribute("data-state"),
        }

        page.goto("http://127.0.0.1:5001/", wait_until="domcontentloaded")
        page.wait_for_selector("#fire")
        page.locator(".skip-link").focus()
        atk_skip = focused(page)
        atk_order = [atk_skip]
        fire = atk_skip
        while fire.get("id") != "fire" and len(atk_order) < 20:
            page.keyboard.press("Tab")
            fire = focused(page)
            atk_order.append(fire)
        fire_reached = fire.get("id") == "fire"
        page.keyboard.press("Enter")
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state === 'RUNNING'",
            timeout=5000,
        )
        fire_disabled = page.locator("#fire").is_disabled()
        page.keyboard.press("Enter")
        page.wait_for_function(
            "() => document.getElementById('ui-status').dataset.state !== 'RUNNING'",
            timeout=60000,
        )
        atk_copy = tab_until(page, lambda i: i.get("id") == "copy-run-id", limit=25)
        atk_outline = any(
            i.get("outlineWidth") and i.get("outlineWidth") != "0px" for i in atk_order
        )
        report["attack"] = {
            "skip_link_can_focus": (atk_skip.get("text") or "").startswith("Skip"),
            "skip_link_text": atk_skip.get("text"),
            "fire_reached": fire_reached,
            "enter_activated_fire": True,
            "running_button_disabled": fire_disabled,
            "copy_run_id_reachable": any(i.get("id") == "copy-run-id" for i in atk_copy),
            "run_id_reachable": any(i.get("id") == "run-id" for i in atk_copy),
            "focus_indicator_nonzero_outline": atk_outline,
            "focus_samples": atk_order[:8],
            "final_state": page.locator("#ui-status").get_attribute("data-state"),
        }
        browser.close()

    ok = (
        report["acmebank"].get("textarea_reached")
        and report["acmebank"].get("submit_reached")
        and report["acmebank"].get("running_button_disabled")
        and report["acmebank"].get("copy_run_id_reachable")
        and report["attack"].get("fire_reached")
        and report["attack"].get("running_button_disabled")
        and report["attack"].get("copy_run_id_reachable")
        and report["acmebank"].get("skip_link_can_focus")
        and report["attack"].get("skip_link_can_focus")
    )
    report["verdict"] = "MEASURED" if ok else "NOT VERIFIED"
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
