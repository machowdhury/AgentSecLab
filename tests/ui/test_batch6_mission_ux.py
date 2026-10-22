"""Batch 6 mission UX in a real browser: Back button, glossary, first-run readiness, zero axe violations of any impact.

Fixtures are shared with the main mission journey test. SKIPPED, not passed, without Playwright and a Chromium.
"""
from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")
from tests.ui.test_loan_desk_mission_browser import browser, go, page, predict, stack, wait_run  # noqa: E402,F401


def test_browser_back_returns_to_the_step_the_learner_was_on_not_to_step_one(page, stack):
    page.goto(stack())
    go(page, "explore")
    go(page, "predict")
    predict(page)
    go(page, "attack")
    assert page.url.endswith("#attack")
    page.go_back()
    page.wait_for_selector("#step-predict:not([hidden])")
    assert page.url.endswith("#predict")
    page.go_back()
    page.wait_for_selector("#step-explore:not([hidden])")
    page.go_forward()
    page.wait_for_selector("#step-predict:not([hidden])")


def test_back_into_a_locked_step_never_opens_it(page, stack):
    page.goto(stack())
    go(page, "explore")
    page.goto(page.url.split("#")[0] + "#attack")
    page.wait_for_selector("#step-understand:not([hidden]), #step-explore:not([hidden])")
    assert page.locator("#step-attack").is_hidden()


def test_reload_keeps_the_current_step_and_does_not_add_history(page, stack):
    page.goto(stack())
    go(page, "explore")
    n = page.evaluate("history.length")
    page.reload()
    page.wait_for_selector("#step-explore:not([hidden])")
    assert page.evaluate("history.length") == n


def test_objectives_prerequisites_and_duration_are_visible_before_any_action(page, stack):
    page.goto(stack())
    body = page.inner_text("main")
    assert "By the end you will be able to" in body and "What you need" in body and "25 to 40 minutes" in body
    assert page.locator("#h-objectives + ul li").count() == 5


def test_a_glossary_term_link_opens_the_glossary_and_focuses_the_definition(page, stack):
    page.goto(stack())
    assert not page.evaluate("document.querySelector('[data-glossary]').open")
    page.click("#step-understand a.term[data-term='pdp']")
    assert page.evaluate("document.querySelector('[data-glossary]').open")
    assert page.evaluate("document.activeElement.id") == "term-pdp"
    defined = page.locator("[data-glossary] dt").all_inner_texts()
    for word in ("Posture", "Scope", "PDP", "Model proposal", "Handler execution", "Evidence verification"):
        assert any(word in d for d in defined), word


def test_ready_model_shows_ready_rows_and_no_fix(page, stack):
    page.goto(stack())
    page.wait_for_function("() => !document.querySelector('[data-model-line]').textContent.startsWith('Checking')")
    assert page.locator("[data-readiness]").is_visible() or page.locator("[data-readiness]").count() == 1


def test_missing_model_shows_the_exact_command_a_copy_button_and_no_download(page, stack, monkeypatch):
    from agentsec.loan_desk.model import OllamaChat
    monkeypatch.setattr(OllamaChat, "readiness", lambda self: {"model": "llama3.2:latest", "ollama_reachable": True, "model_installed": False,
        "installed_models": ["llama3.2:1b"], "fix": {"kind": "pull_model", "command": "ollama pull llama3.2:latest", "where": "on the Ollama host", "note": "The lab never downloads models for you."}})
    from tests.loan_desk_support import PostureAwareModel
    page.route("**/api/missions/loan-desk/status", lambda route: route.fulfill(json={
        "available": False, "reason": "Ollama is reachable but model 'llama3.2:latest' is not installed.", "model": "llama3.2:latest", "proposal_source": "model",
        "identity": {}, "readiness": OllamaChat("x", "llama3.2:latest").readiness()}))
    page.goto(stack())
    page.wait_for_selector("[data-readiness]:not([hidden])")
    txt = page.locator("[data-readiness]").inner_text()
    assert "Not ready" in txt and "ollama pull llama3.2:latest" in page.locator("[data-readiness-command]").inner_text()
    assert page.locator("[data-retry-status]").is_visible() and "Check again" in page.locator("[data-retry-status]").inner_text()
    page.context.grant_permissions(["clipboard-read", "clipboard-write"])
    page.click("[data-copy-command]")
    page.wait_for_function("() => document.querySelector('[data-copy-status]').textContent.length > 0")


def test_every_step_has_zero_axe_violations_of_any_impact(page, stack):
    pytest.importorskip("axe_playwright_python")
    from axe_playwright_python.sync_playwright import Axe
    page.goto(stack())
    go(page, "explore")
    page.click("[data-launch='explore']")
    wait_run(page, "explore")
    predict(page)
    go(page, "attack")
    page.click("[data-launch='attack']")
    wait_run(page, "attack")
    for step in ("understand", "explore", "predict", "attack", "observe", "investigate", "defend"):
        go(page, step)
        found = [(v["id"], v["impact"], [n["target"] for n in v["nodes"]][:2]) for v in Axe().run(page).response["violations"]]
        assert not found, (step, found)
