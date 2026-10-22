"""Attack UI accessibility (Batch 8): the four lab pages that failed WCAG AA colour contrast, plus every other Attack UI page.

Zero serious or critical axe violations; every control reachable and operable from the keyboard; and proof that the fix
changed one declaration and removed nothing. SKIPPED, not passed, without Playwright and a Chromium.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from tests.ui.test_loan_desk_mission_browser import browser, page, stack  # noqa: E402,F401

ROOT = Path(__file__).resolve().parents[2]
PAGES = ["/", "/acmebank", "/labs/LAB-PI-001", "/labs/LAB-MCP-001", "/labs/LAB-RAG-CONTEXT", "/labs/LAB-MEMORY-001",
         "/labs/LAB-AGENT-GOAL-INTEGRITY-001", "/labs/LAB-AGENT-DELEGATION-001", "/labs/LAB-AGENTSEC-CAPSTONE-001"]
FIXED = ["/labs/LAB-RAG-CONTEXT", "/labs/LAB-MEMORY-001", "/labs/LAB-AGENT-GOAL-INTEGRITY-001", "/labs/LAB-AGENT-DELEGATION-001"]


def base(stack):
    return stack().split("/academy")[0]


@pytest.mark.parametrize("path", PAGES)
def test_no_serious_or_critical_axe_violation(page, stack, path):
    pytest.importorskip("axe_playwright_python")
    from axe_playwright_python.sync_playwright import Axe
    page.goto(base(stack) + path)
    bad = [(v["id"], v["impact"], [n["target"] for n in v["nodes"]][:2]) for v in Axe().run(page).response["violations"] if v["impact"] in ("serious", "critical")]
    assert not bad, bad


@pytest.mark.parametrize("path", FIXED)
def test_the_retest_button_hint_now_meets_aa_contrast_in_both_states(page, stack, path):
    pytest.importorskip("axe_playwright_python")
    from axe_playwright_python.sync_playwright import Axe
    page.goto(base(stack) + path)
    assert page.evaluate("getComputedStyle(document.querySelector('#retest-button > small')).opacity") == "1"
    assert not [v for v in Axe().run(page).response["violations"] if v["id"] == "color-contrast"]
    page.click("#attack-button")
    page.wait_for_timeout(2500)
    assert not [v for v in Axe().run(page).response["violations"] if v["id"] == "color-contrast"]  # after a launch


@pytest.mark.parametrize("path", PAGES)
def test_every_visible_enabled_control_is_reachable_by_tab(page, stack, path):
    page.goto(base(stack) + path)
    # candidates that can really take focus (hidden steps and collapsed content cannot), identified by trying
    want = page.evaluate("""() => {
        const out = [];
        for (const e of document.querySelectorAll('a[href], button, input:not([type=hidden]), select, textarea, summary, [tabindex]')) {
            if (e.disabled || e.tabIndex < 0) continue;
            e.focus();
            if (document.activeElement === e) out.push(e.id || e.getAttribute('href') || e.textContent.trim().slice(0, 30));
        }
        document.activeElement.blur();
        return out;
    }""")
    seen = set()
    for _ in range(len(want) + 40):
        page.keyboard.press("Tab")
        seen.add(page.evaluate("document.activeElement.id || document.activeElement.getAttribute('href') || document.activeElement.textContent.trim().slice(0, 30)"))
    missing = [w for w in want if w not in seen]
    assert not missing, missing[:8]


@pytest.mark.parametrize("path", FIXED)
def test_the_launch_controls_work_from_the_keyboard_alone(page, stack, path):
    page.goto(base(stack) + path)
    page.focus("#attack-button")
    assert page.evaluate("getComputedStyle(document.activeElement).outlineStyle") != "none" or page.evaluate("getComputedStyle(document.activeElement).boxShadow") != "none"  # visible focus
    page.keyboard.press("Enter")
    page.wait_for_timeout(2500)
    page.focus("#retest-button")
    page.keyboard.press("Space")
    page.wait_for_timeout(2500)
    assert "run" in page.inner_text("body").lower()


def test_the_contrast_fix_changed_one_declaration_and_removed_nothing():
    css = (ROOT / "src/agentsec/static/agentsec-workbench.css").read_text()
    restored = css.replace("opacity: 1; /* was .92: white on the teal RETEST button measured 4.31:1 and failed WCAG AA (4.5:1); at full opacity it is 4.8:1 */", "opacity: .92;")
    assert restored != css
    baseline = json.loads((ROOT / "docs/reviews/batch7/preservation_baseline.json").read_text())["assets"]["src/agentsec/static/agentsec-workbench.css"]
    assert hashlib.sha256(restored.encode()).hexdigest()[:16] == baseline


@pytest.mark.parametrize("path", PAGES)
def test_no_control_or_heading_was_lost_against_the_baseline(page, stack, path):
    base_pages = json.loads((ROOT / "docs/reviews/batch7/browser_baseline.json").read_text())["pages"]
    page.goto(base(stack) + path)
    now = page.evaluate("() => ({buttons: document.querySelectorAll('button').length, inputs: document.querySelectorAll('input,select,textarea').length, links: document.querySelectorAll('a[href]').length})")
    then = base_pages[path]["controls"]
    assert now["buttons"] >= then["buttons"] and now["inputs"] >= then["inputs"] and now["links"] >= then["links"], (now, then)
    heads = page.eval_on_selector_all("h1,h2,h3", "els => els.map(e => e.tagName + ':' + e.textContent.trim().replace(/\\s+/g,' '))")
    assert [h for h in base_pages[path]["headings"] if h not in heads] == []
