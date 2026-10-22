"""Loan Desk in a real browser. Proposals come from a labelled test double (the page says so) except the
unavailable-model case, which uses the real Ollama client against a closed port.
SKIPPED, not passed, without Playwright and a Chromium (set AGENTSEC_CHROMIUM).
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from tests.loan_desk_support import FINAL, SUBMIT, ScriptedModel, tool

P = tool("get_applicant_profile", applicant_id="APP-1001")
C = tool("get_credit_summary", applicant_id="APP-1001")

pw_mod = pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.bank_app import build_runtime, create_app  # noqa: E402
from agentsec.loan_desk import agent as agent_mod  # noqa: E402
from agentsec.loan_desk.model import OllamaChat  # noqa: E402


def _chromium():
    env = os.environ.get("AGENTSEC_CHROMIUM")
    if env and Path(env).is_file():
        return env
    try:
        with pw_mod.sync_playwright() as p:
            d = p.chromium.executable_path
        return d if Path(d).is_file() else None
    except Exception:  # noqa: BLE001
        return None


@pytest.fixture(scope="module")
def browser():
    exe = _chromium()
    if not exe:
        pytest.skip("Playwright/Chromium not available (set AGENTSEC_CHROMIUM)")
    with pw_mod.sync_playwright() as p:
        b = p.chromium.launch(executable_path=exe)
        yield b
        b.close()


@pytest.fixture
def serve(settings):
    servers = []

    def start(model):
        rt = build_runtime(settings, otel_enabled=False)
        rt.loan_desk_model = model
        server = make_server("127.0.0.1", 0, create_app(rt), threaded=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}/loan-desk"

    yield start
    for s in servers:
        s.shutdown()


@pytest.fixture
def page(browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    yield pg
    ctx.close()


def submit_example(pg, url):
    pg.goto(url)
    pg.click("#example")
    pg.click("#submit")


def wait_done(pg):
    pg.wait_for_function("() => !['RUNNING','IDLE'].includes(document.getElementById('run-status').dataset.state)", timeout=20000)


def test_success_flow_shows_proposed_authorized_executed(page, serve):
    url = serve(ScriptedModel([P, C, SUBMIT, FINAL]))
    submit_example(page, url)
    wait_done(page)
    assert page.locator("#run-status").inner_text() == "COMPLETED"
    row = page.locator("#timeline > li").first.inner_text()
    assert "get_applicant_profile" in row and "PROPOSED by SCRIPTED TEST DOUBLE (not model-driven)" in row
    assert "POLICY: ALLOW" in row and "HANDLER BEGAN" in row and "untrusted data" in row
    assert page.locator("#result-card").is_visible() and page.locator("#reco").inner_text() == "Proceed to underwriter"
    assert "No loan was approved" in page.locator("#advisory").inner_text()
    run_id = page.locator("#ev-run").inner_text()
    assert run_id in page.input_value("#ev-spl") and page.locator("#ev-indexed").inner_text().startswith("NOT VERIFIED.")
    assert [i.get_attribute("data-s") for i in page.locator("#phases > li").all()] == ["done"] * 5
    nd = page.request.get(page.url.split("/loan-desk")[0] + f"/api/v1/loan-desk/runs/{run_id}/events.ndjson").text()
    assert all(json.loads(x)["agentsec.run.id"] == run_id for x in nd.splitlines())


def test_page_verifies_through_the_bridge_and_never_without_it(page, serve, settings):
    from tests.loan_desk_support import FakeVerifierThread, bridge_online
    url = serve(ScriptedModel([P, C, SUBMIT, FINAL]))
    origin = url.split("/loan-desk")[0]
    submit_example(page, url)
    wait_done(page)
    assert page.locator("#ev-indexed").get_attribute("data-state") == "NOT_VERIFIED"
    page.click("#refresh-ev")  # no verifier installed at all
    page.wait_for_function("() => document.getElementById('ev-indexed').textContent.includes('not installed')")
    assert page.locator("#ev-indexed").get_attribute("data-state") != "SPLUNK_VERIFIED"
    bridge_online(settings.artifacts_dir)  # key + fresh heartbeat, but no verifier loop answering
    page.click("#refresh-ev")
    page.wait_for_function("() => document.getElementById('ev-indexed').dataset.state === 'PENDING'")
    fake = FakeVerifierThread(settings.artifacts_dir, origin)  # TEST DOUBLE verifier answering the request
    try:
        page.wait_for_function("() => document.getElementById('ev-indexed').dataset.state === 'SPLUNK_VERIFIED'", timeout=15000)
    finally:
        fake.close()
    assert "indexed of" in page.locator("#ev-indexed").inner_text()


def test_denied_actions_show_handler_did_not_run(page, serve):
    url = serve(ScriptedModel([tool("issue_loan_offer", applicant_id="APP-1001", amount=420000),
                               tool("get_applicant_profile", applicant_id="APP-2001"), P, C, SUBMIT, FINAL]))
    submit_example(page, url)
    wait_done(page)
    rows = page.locator("#timeline > li").all_inner_texts()
    assert "POLICY: DENY" in rows[0] and "HANDLER DID NOT RUN" in rows[0] and "scope_not_granted" in rows[0]
    assert "resource_not_bound_to_run" in rows[1] and "HANDLER BEGAN" not in rows[1]
    assert "the handler never began" in rows[0]
    assert "Marcus" not in page.content()


def test_handler_failure_is_visible(page, serve, monkeypatch):
    real = agent_mod.run_tool

    def boom(s, t, a):
        if t == "lookup_lending_policy":
            raise RuntimeError("synthetic fault")
        return real(s, t, a)
    monkeypatch.setattr(agent_mod, "run_tool", boom)
    url = serve(ScriptedModel([tool("lookup_lending_policy", topic="dti"), P, C, SUBMIT, FINAL]))
    submit_example(page, url)
    wait_done(page)
    row = page.locator("#timeline > li").first.inner_text()
    assert "HANDLER BEGAN" in row and "Handler error: RuntimeError: synthetic fault" in row


def test_unreachable_ollama_fails_visibly_without_any_action(page, serve):
    url = serve(OllamaChat("http://127.0.0.1:9", "mistral:latest", timeout=3))  # real client, closed port
    page.goto(url)
    page.wait_for_function("() => document.getElementById('model-chip').dataset.state !== 'CHECKING'")
    assert page.locator("#model-chip").get_attribute("data-state") == "UNAVAILABLE"
    assert "not reachable" in page.locator("#model-banner").inner_text()
    page.click("#example")
    page.click("#submit")
    wait_done(page)
    assert page.locator("#run-status").inner_text() == "FAILED"
    live = page.locator("#live").inner_text()
    assert "No action was proposed" in live and "no tool ran" in live
    assert page.locator("#timeline-card").is_hidden() and page.locator("#result-card").is_hidden()
    assert page.locator("#phases > li[data-s='failed']").count() == 1
    assert page.locator("#submit").is_enabled()  # the learner can retry


def test_validation_errors_are_inline_accessible_and_stop_the_request(page, serve):
    url = serve(ScriptedModel([FINAL]))
    posts = []
    page.on("request", lambda r: posts.append(r.url) if r.method == "POST" else None)
    page.goto(url)
    page.click("#submit")
    assert page.locator("#form-errors").is_visible() and page.locator("[aria-invalid='true']").count() >= 6
    assert page.evaluate("document.activeElement.id") == "full_name"
    assert "required" in page.locator("#err-annual_income").inner_text()
    assert posts == []
    page.click("#example")
    page.fill("#credit_score", "950")
    page.click("#submit")
    assert "between 300 and 900" in page.locator("#err-credit_score").inner_text() and posts == []


def test_server_side_synthetic_data_guard_reaches_the_field(page, serve):
    url = serve(ScriptedModel([FINAL]))
    page.goto(url)
    page.click("#example")
    page.fill("#notes", "email me at real.person@example.com")
    page.click("#submit")
    page.wait_for_selector("#err-notes:not(:empty)")
    assert "real email address" in page.locator("#err-notes").inner_text()
    assert page.locator("#run-status").inner_text() == "IDLE" and page.locator("#submit").is_enabled()


def test_submit_is_disabled_while_a_run_is_in_flight(page, serve):
    class Slow(ScriptedModel):
        def chat(self, messages):
            time.sleep(0.8)
            return super().chat(messages)

    url = serve(Slow([P, C, SUBMIT, FINAL]))
    submit_example(page, url)
    assert page.locator("#submit").is_disabled() and page.locator("#loan-form").get_attribute("aria-busy") == "true"
    assert page.locator("#run-status").inner_text() == "RUNNING"
    wait_done(page)
    assert page.locator("#submit").is_enabled()


def test_untrusted_text_is_rendered_as_text_not_markup(page, serve):
    url = serve(ScriptedModel([P, C, SUBMIT, FINAL]))
    page.goto(url)
    page.click("#example")
    page.fill("#notes", "<img src=x onerror=window.__pwn=1><b>bold</b>")
    page.click("#submit")
    wait_done(page)
    assert page.evaluate("window.__pwn") is None and page.locator("#timeline img").count() == 0
    assert "<img" in page.locator("#timeline > li").first.inner_text()


def test_keyboard_reaches_every_control_and_no_serious_axe_violations(page, serve):
    pytest.importorskip("axe_playwright_python")
    from axe_playwright_python.sync_playwright import Axe
    url = serve(ScriptedModel([P, C, SUBMIT, FINAL]))
    page.goto(url)
    seen = []
    for _ in range(30):
        page.keyboard.press("Tab")
        seen.append(page.evaluate("document.activeElement.id"))
    assert {"full_name", "annual_income", "credit_score", "loan_amount", "term_years", "province", "employment",
            "notes", "example", "submit"} <= set(seen)
    for stage in ("idle", "done"):
        if stage == "done":
            page.click("#example"); page.click("#submit"); wait_done(page)
        bad = [v for v in Axe().run(page).response["violations"] if v["impact"] in ("serious", "critical")]
        assert not bad, [(v["id"], [n["target"] for n in v["nodes"]]) for v in bad]


def test_phone_width_has_no_horizontal_scroll(browser, serve):
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    pg = ctx.new_page()
    submit_example(pg, serve(ScriptedModel([P, C, SUBMIT, FINAL])))
    wait_done(pg)
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    ctx.close()


def test_shared_shell_is_present_and_marks_acmebank_current(page, serve):
    page.goto(serve(ScriptedModel([FINAL])))
    assert page.locator("nav.as-shell").count() == 1
    assert page.locator("nav.as-shell a[aria-current='page']").inner_text() == "AcmeBank"


def test_outcome_facts_and_unverified_prose_are_shown_separately(page, serve):
    lying = {**FINAL, "summary": "The debt service ratio is 38.5% so this is a strong application overall."}
    url = serve(ScriptedModel([tool("get_applicant_profile", applicant_id="APP-2002"), P, C, SUBMIT, lying]))
    submit_example(page, url)
    wait_done(page)
    assert "BLOCKED (1 action)" in page.locator("#out-security-v").inner_text()
    assert page.locator("#out-business-v").inner_text().startswith("COMPLETE")
    ops = page.locator("#out-ops").inner_text()
    assert "Proposed 4" in ops and "denied 1" in ops and "executed 3" in ops and "no denied action ran" in ops
    assert "resource_not_bound_to_run" in page.locator("#out-blocked").inner_text()
    facts = page.locator("#facts-list").inner_text()
    assert "Monthly payment at 5.2% (indicative)" in facts and "computed here" in facts and "38.5" not in facts
    assert page.locator("#screening > li[data-r='PASS']").count() == 2
    assert "ADVISORY · NOT VERIFIED" in page.locator("#result-h").inner_text()
    warn = page.locator("#claims-warn")
    assert warn.is_visible() and "38.5%" in warn.inner_text() and "Do not rely" in warn.inner_text()
