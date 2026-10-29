"""Attack console workflow: select scenario -> configure -> launch -> progress -> results -> evidence (Playwright, in-process, no Docker)."""
from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")
from tests.ui.test_loan_desk_mission_browser import browser, page, stack  # noqa: E402,F401


def test_critical_workflow_and_disclosures(page, stack):
    root = stack().split("/academy")[0]
    page.set_viewport_size({"width": 768, "height": 900})
    page.goto(root + "/labs/LAB-PI-001")
    assert page.locator("h1").count() == 1
    # scenario selection and rail
    assert page.locator(".scenario-cards a").count() == 7 and page.locator(".step-rail li").count() == 6
    # boundaries are shortened to a strip, full text kept in a disclosure
    assert "not production authentication" in page.inner_text(".scope-strip")
    assert "NOT PRODUCTION AUTHENTICATION" in page.text_content("#scope-heading-box")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    # configure
    page.check("input[name=predict-control][value=DENY]")
    page.check("input[name=predict-execution][value=NO]")
    assert "PREDICTION RECORDED" in page.inner_text("#prediction-recorded")
    assert page.eval_on_selector(".step-rail a[aria-current=step]", "e => e.hash") == "#fire-attack"  # READY: next step is Launch
    # evidence drawer closed until a run exists
    assert page.evaluate("document.getElementById('evidence-drawer').open") is False
    # launch + progress
    page.click("#fire-attack")
    page.wait_for_function("document.getElementById('ui-status').dataset.state !== 'READY'", timeout=20000)
    page.wait_for_function("document.getElementById('attack-run-id').value.length > 10", timeout=30000)
    # results + evidence
    assert page.evaluate("document.getElementById('evidence-drawer').open") is True
    assert page.input_value("#run-id") == page.input_value("#attack-run-id")
    facts = page.inner_text("#fact-list")
    assert "No request has been sent yet" not in facts and "HTTP 200" in facts
    # the step rail follows the run state: a finished launch leaves "5 Results" as the current step
    assert page.eval_on_selector(".step-rail a[aria-current=step]", "e => e.hash") == "#fact-list"
    assert page.get_attribute(".step-rail", "data-run-state") == page.get_attribute("#ui-status", "data-state") != "READY"
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


def test_baseline_and_retest_launch(page, stack):
    root = stack().split("/academy")[0]
    page.goto(root + "/labs/LAB-PI-001")
    prev = ""
    for mode in ("baseline", "retest"):
        page.click(f"#fire-{mode}")
        page.wait_for_function("(p) => { const v = document.getElementById('run-id').value; return v.length > 10 && v !== p; }", arg=prev, timeout=30000)
        prev = page.input_value("#run-id")
    page.wait_for_function("document.getElementById('retest-run-id').value.length > 10", timeout=30000)
    assert page.input_value("#retest-run-id")
    compare = page.inner_text("#compare-list")
    assert "ATTACK" in compare and "RETEST" in compare and "Launch ATTACK and RETEST to fill" in compare  # BASELINE never fills the ATTACK/RETEST pair



@pytest.mark.parametrize("path", ["/labs/LAB-AGENT-GOAL-INTEGRITY-001", "/labs/LAB-RAG-CONTEXT", "/labs/LAB-AGENTSEC-CAPSTONE-001", "/labs/LAB-MCP-001"])
def test_workbench_templates_share_the_console_and_attack_flow(page, stack, path):
    root = stack().split("/academy")[0]
    page.goto(root + path)
    assert page.locator("h1").count() == 1
    assert page.locator(".scenario-cards a").count() == 7
    assert page.locator(".scenario-card[aria-current=page]").count() == 1
    if "MCP" in path:
        return  # wizard page: scenario cards only; its own stepper is covered by the existing Academy tests
    assert page.locator(".step-rail li").count() == 6 and page.locator(".scope-strip").count() == 1
    page.click("#attack-button")
    page.wait_for_function("document.getElementById('primary-run-id').textContent.trim() !== 'Not launched'", timeout=30000)
    assert page.inner_text("#launch-status").strip()
    if "CAPSTONE" not in path:
        page.click("#retest-button")
        page.wait_for_function("(document.getElementById('retest-response')||{}).textContent !== 'Not run'", timeout=30000)


@pytest.mark.parametrize("path", ["/labs/LAB-PI-001", "/labs/LAB-RAG-CONTEXT", "/labs/LAB-AGENT-DELEGATION-001", "/labs/LAB-AGENTSEC-CAPSTONE-001", "/labs/LAB-MCP-001"])
def test_axe_at_768_after_launch(page, stack, path):
    pytest.importorskip("axe_playwright_python")
    from axe_playwright_python.sync_playwright import Axe
    root = stack().split("/academy")[0]
    page.set_viewport_size({"width": 768, "height": 900})
    page.goto(root + path)
    for sel in ("#fire-attack", "#attack-button"):
        if page.locator(sel).count() and page.locator(sel).is_visible():
            page.click(sel)
            page.wait_for_timeout(2500)
            break
    bad = [(v["id"], [n["target"] for n in v["nodes"]][:2]) for v in Axe().run(page).response["violations"] if v["impact"] in ("serious", "critical")]
    assert not bad, bad
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
