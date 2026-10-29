"""AcmeBank redesign in a real browser: critical loan workflow, states, axe, no horizontal scroll.

The loan request is the page's only workflow (there is no accounts or transactions UI). /process is fulfilled at the network layer so
the three outcome states are deterministic and no model is needed. SKIPPED without Playwright and AGENTSEC_CHROMIUM.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app as create_attack  # noqa: E402
from agentsec.bank_app import build_runtime, create_app as create_bank  # noqa: E402

CHROMIUM = os.environ.get("AGENTSEC_CHROMIUM")


@pytest.fixture(scope="module")
def urls(tmp_path_factory):
    import agentsec.settings as st
    os.environ.update(AGENTSEC_OTEL_ENABLED="false", AGENTSEC_SECURITY_PROFILE="defended", AGENTSEC_ARTIFACTS_DIR=str(tmp_path_factory.mktemp("art")))
    st.reset_settings_cache()
    bank = make_server("127.0.0.1", 0, create_bank(build_runtime(st.get_settings(), otel_enabled=False)), threaded=True)
    attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(f"http://127.0.0.1:{bank.server_port}")), threaded=True)
    for s in (bank, attack):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{bank.server_port}/", f"http://127.0.0.1:{attack.server_port}/acmebank"
    for s in (bank, attack):
        s.shutdown()


@pytest.fixture(scope="module")
def browser():
    if not (CHROMIUM and Path(CHROMIUM).is_file()):
        pytest.skip("set AGENTSEC_CHROMIUM to a Chromium executable")
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROMIUM)
        yield b
        b.close()


@pytest.fixture(params=[1280, 768])
def page(browser, request):
    pg = browser.new_page(viewport={"width": request.param, "height": 900})
    yield pg
    pg.close()


def fulfil(pg, body, status=200):
    pg.route("**/process", lambda r: r.fulfill(status=status, content_type="application/json", body=json.dumps(body)))


def test_landmarks_one_h1_and_simulated_label(page, urls):
    page.goto(urls[0])
    assert page.locator("h1").count() == 1
    assert page.locator("main").count() == 1 and page.locator("header").count() >= 1
    assert "Simulated bank" in page.locator(".ab-sim").inner_text()
    assert page.locator("label[for=input]").count() == 1 and page.locator("#status-live").get_attribute("role") == "status"
    assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")


def test_loan_request_success_flow(page, urls):
    fulfil(page, {"run_id": "run-abc-123", "terminal": "completed_allowed", "llm_call_count": 4})
    page.goto(urls[0])
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function("document.getElementById('ui-status').dataset.state==='COMPLETED'")
    assert page.locator("#ab-steps").get_attribute("data-step") == "3"
    assert page.locator("#run-id").input_value() == "run-abc-123"
    assert page.locator("#submit-loan").is_enabled() and page.locator("#loan-form").get_attribute("aria-busy") == "false"
    assert "completed_allowed" in page.locator("#result-summary").inner_text()
    page.locator("#tech-details summary").click()
    assert "run-abc-123" in page.locator("#result-json").inner_text()
    assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")


def test_denied_and_error_states(page, urls):
    fulfil(page, {"run_id": "r-deny", "terminal": "completed_denied"})
    page.goto(urls[0])
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function("document.getElementById('ui-status').dataset.state==='DENIED'")
    assert page.locator("#ab-steps").get_attribute("data-outcome") == "DENIED"
    page.unroute("**/process")
    page.route("**/process", lambda r: r.abort())
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function("document.getElementById('ui-status').dataset.state==='ERROR'")
    assert "not a control DENY" in page.locator("#result-summary").inner_text()


def test_keyboard_reaches_submit_and_focus_is_visible(page, urls):
    page.goto(urls[0])
    page.locator("#input").focus()
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.id") == "submit-loan"
    assert page.evaluate("getComputedStyle(document.activeElement).outlineStyle") != "none"


def test_read_only_view_keeps_lab_labels_and_ids(page, urls):
    page.goto(urls[1])
    for sel in ("#readonly-notice", "#behind-the-ai", "#go-workbench"):
        assert page.locator(sel).count() == 1
    assert page.locator("#loan-form").count() == 0 and page.locator("h1").count() == 1
    assert "DOCUMENTED" in page.locator("#readonly-notice").inner_text()


@pytest.mark.parametrize("which", [0, 1])
def test_axe_no_serious_or_critical(page, urls, which):
    axe_mod = pytest.importorskip("axe_playwright_python.sync_playwright")
    page.goto(urls[which])
    page.evaluate("document.getElementById('behind-the-ai').open = true")
    res = axe_mod.Axe().run(page)
    bad = [(v["id"], v["impact"]) for v in res.response["violations"] if v["impact"] in ("serious", "critical")]
    assert not bad, bad


def test_resubmit_clears_previous_outcome(page, urls):
    fulfil(page, {"run_id": "r1", "terminal": "completed_denied"})
    page.goto(urls[0])
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function("document.getElementById('ui-status').dataset.state==='DENIED'")
    page.unroute("**/process")
    # Hold the response so RUNNING is observable, then release a success.
    release = {}
    def slow(route):
        release["route"] = route
    page.route("**/process", slow)
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function("document.getElementById('ui-status').dataset.state==='RUNNING'")
    assert page.locator("#ab-steps").get_attribute("data-outcome") is None
    while "route" not in release:
        page.wait_for_timeout(50)
    release["route"].fulfill(status=200, content_type="application/json", body=json.dumps({"run_id": "r2", "terminal": "completed_allowed"}))
    page.wait_for_function("document.getElementById('ui-status').dataset.state==='COMPLETED'")
    assert page.locator("#ab-steps").get_attribute("data-outcome") == "COMPLETED"
