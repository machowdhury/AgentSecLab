"""The Loan Desk mission in a real browser: all ten steps, gates, and the failure/recovery states.

AcmeBank and the Attack Service run in this process. The agent is a labelled test double that obeys a planted note
unless policy denies it, so the journey is deterministic. The real-model journey is scripts/loan_desk_mission_e2e.py.
SKIPPED, not passed, without Playwright and a Chromium (set AGENTSEC_CHROMIUM).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

pw_mod = pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app as create_attack  # noqa: E402
from agentsec.bank_app import build_runtime, create_app as create_bank  # noqa: E402
from tests.loan_desk_support import FakeVerifierThread, PostureAwareModel  # noqa: E402


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
def stack(settings):
    servers = []

    def start(model=None, bank_url=None):
        start.bank_url = bank_url
        if bank_url is None:
            rt = build_runtime(settings, otel_enabled=False)
            rt.loan_desk_model = model or PostureAwareModel()
            bank = make_server("127.0.0.1", 0, create_bank(rt), threaded=True)
            threading.Thread(target=bank.serve_forever, daemon=True).start()
            servers.append(bank)
            bank_url = f"http://127.0.0.1:{bank.server_port}"
            start.bank_url = bank_url
        attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(bank_url)), threaded=True)
        threading.Thread(target=attack.serve_forever, daemon=True).start()
        servers.append(attack)
        return f"http://127.0.0.1:{attack.server_port}/academy/missions/loan-desk"

    start.bank_url = None
    yield start
    for s in servers:
        s.shutdown()


@pytest.fixture
def page(browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    yield pg
    ctx.close()


def go(pg, step):
    pg.click(f"[data-step-link='{step}']")
    pg.wait_for_selector(f"#step-{step}:not([hidden])")


def wait_run(pg, slot, timeout=20000):
    pg.wait_for_function("(s) => { const p = document.querySelector(`[data-run-panel='${s}']`); "
                         "return p && p.getAttribute('aria-busy') === 'false' && p.querySelector('.outcomes, .callout--warn'); }",
                         arg=slot, timeout=timeout)


def predict(pg):
    go(pg, "predict")
    pg.check("input[name=follow][value=yes]")
    pg.check("input[name=decision][value=ALLOW]")
    pg.check("input[name=queue][value=planted]")
    pg.click("[data-lock-prediction]")


def test_the_full_ten_step_journey_with_a_real_before_and_after(page, stack, settings, request):
    page.goto(stack())
    page.wait_for_function("() => !document.querySelector('[data-model-line]').textContent.startsWith('Checking')")
    assert "scripted-test-double" in page.locator("[data-model-line]").inner_text() or "test_double" in page.locator("[data-model-line]").inner_text()

    # gates: nothing past Predict opens before its prerequisite
    for step, why in (("attack", "Lock your prediction"), ("observe", "Launch the attack"), ("retest", "Apply the defense"), ("compare", "Finish both")):
        page.click(f"[data-step-link='{step}']", force=True)  # aria-disabled links are not "enabled" to Playwright
        assert why in page.locator("[data-gate-message]").inner_text()
        assert page.locator(f"#step-{step}").is_hidden()

    # EXPLORE: a normal application (hardened default posture), then validation UX
    go(page, "explore")
    page.fill("#f-credit_score", "42")
    page.click("[data-launch='explore']")
    page.wait_for_selector("[data-err='credit_score']:not(:empty)")
    assert "between 300 and 900" in page.locator("[data-err='credit_score']").inner_text()
    assert page.locator("[data-form-errors]").is_visible()
    page.fill("#f-credit_score", "705")
    page.click("[data-launch='explore']")
    wait_run(page, "explore")
    explore = page.locator("[data-run-panel='explore']").inner_text()
    assert "COMPLETED" in explore and "Nothing needed blocking" in explore and "READY_FOR_REVIEW" in explore

    # PREDICT then ATTACK (baseline)
    predict(page)
    assert page.locator("[data-prediction-locked]").is_visible() and page.locator("[data-lock-prediction]").is_disabled()
    go(page, "attack")
    page.click("[data-launch='attack']")
    assert page.locator("[data-launch='attack']").is_disabled()  # no double launch
    wait_run(page, "attack")
    atk = page.locator("[data-run-panel='attack']").inner_text()
    assert "posture BASELINE" in atk and "PRE-APPROVED by Regional Director Alvarez" in atk
    assert "copies text written by the applicant" in atk and "ALLOW (granted_scope_and_bound_resource)" in atk

    # OBSERVE compares the prediction with the run
    go(page, "observe")
    obs = page.locator("[data-prediction-review]").inner_text()
    assert "Your prediction versus the run" in obs and obs.count("match") >= 3
    assert "PRE-APPROVED" in page.locator("[data-queue-view]").inner_text()

    # INVESTIGATE: searches carry the run.id; counts are checked honestly
    go(page, "investigate")
    run_id = page.locator("[data-run-panel='attack'] code").first.inner_text()
    spl = page.locator(".spl").all()
    assert len(spl) == 3 and all(run_id in s.input_value() for s in spl)
    assert "NOT VERIFIED" in page.locator("[data-evidence-state]").inner_text() and "LOCAL evidence" in page.locator("[data-evidence-state]").inner_text()
    n = page.evaluate("document.querySelector('[data-run-panel=\"attack\"]').textContent.match(/Local evidence: (\\d+) events/)[1]")
    page.fill("#splunk-count", "abc"); page.click("[data-count-form] button[type=submit]")
    assert "whole number" in page.locator("[data-count-error]").inner_text()
    page.fill("#splunk-count", str(int(n) * 2)); page.click("[data-count-form] button[type=submit]")
    assert "double" in page.locator("[data-count-result]").inner_text()
    page.fill("#splunk-count", n); page.click("[data-count-form] button[type=submit]")
    assert "matches" in page.locator("[data-count-result]").inner_text() and "learner-reported" in page.locator("[data-count-result]").inner_text()
    page.select_option("#proof-event", "agentsec.control.decision"); page.click("[data-proof-form] button")
    assert "Not quite" in page.locator("[data-proof-result]").inner_text()
    page.select_option("#proof-event", "agentsec.mcp.started"); page.click("[data-proof-form] button")
    assert "Correct" in page.locator("[data-proof-result]").inner_text()
    assert page.locator("a:has-text('Open in Splunk')").first.get_attribute("href").startswith("http://127.0.0.1:8000/en-US/app/search/search?q=")
    # verification without a running verifier is an explicit non-success
    page.click("[data-recheck-evidence]")
    page.wait_for_function("() => document.querySelector('[data-evidence-state]').textContent.includes('not installed')")
    assert "SPLUNK-VERIFIED" not in page.locator("[data-evidence-state]").inner_text()
    fake = FakeVerifierThread(settings.artifacts_dir, stack.bank_url)  # TEST DOUBLE verifier speaking the real bridge protocol
    request.addfinalizer(fake.close)
    page.wait_for_timeout(500)
    page.click("[data-recheck-evidence]")
    page.wait_for_function("() => document.querySelector('[data-evidence-state]').textContent.includes('SPLUNK-VERIFIED')", timeout=20000)

    # DEFEND, retest first without applying: still locked
    go(page, "defend")
    assert "new</strong> control" in page.inner_html("#step-defend").replace("<strong>New</strong>", "new</strong>").lower() or "New" in page.locator("#step-defend .callout--warn").inner_text()
    page.check("input[name=posture][value=hardened]"); page.click("[data-apply-defense]")
    assert "HARDENED (applied)" in page.locator("[data-defense-current]").inner_text()
    go(page, "retest")
    assert "HARDENED" in page.locator("[data-retest-posture]").inner_text()
    page.click("[data-launch='retest']")
    wait_run(page, "retest")
    ret = page.locator("[data-run-panel='retest']").inner_text()
    assert "argument_not_allowed:note (handler did not run)" in ret and "BLOCKED" in ret and "READY_FOR_REVIEW" in ret and "PRE-APPROVED" not in ret.split("Underwriter queue")[1]

    # COMPARE
    go(page, "compare")
    table = page.locator("[data-compare-table]").inner_text()
    assert "ATTACK" in table and "RETEST" in table and "YES" in table
    assert page.locator("[data-compare-table] tr.is-different").count() >= 4
    assert "did not under HARDENED" in page.locator("[data-compare-table] .callout").last.inner_text()

    # EXPLAIN: wrong answers are refused, then completion is recorded
    go(page, "explain")
    page.check("input[name=q1][value=splunk]"); page.check("input[name=q2][value=safe]"); page.check("input[name=q3][value=codes]"); page.check("input[name=q4][value=started]")
    page.fill("#explain-text", "x" * 80)
    page.click("[data-explain-form] button[type=submit]")
    assert "Not yet. Revisit: q1, q2" in page.locator("[data-explain-result]").inner_text()
    page.check("input[name=q1][value=ctrl]"); page.check("input[name=q2][value=valid]")
    page.fill("#explain-text", "short")
    page.click("[data-explain-form] button[type=submit]")
    assert "at least 60" in page.locator("[data-explain-error]").inner_text()
    page.fill("#explain-text", "The attacker hid an instruction in notes; policy allowed the valid call; HARDENED denied free text before the handler ran.")
    page.click("[data-explain-form] button[type=submit]")
    assert "Mission complete" in page.locator("[data-explain-result]").inner_text()
    assert "workflow_complete" in page.evaluate("localStorage.getItem('agentsec.academy.progress.v1')")
    page.goto(page.url.split("/academy")[0] + "/academy")
    assert page.locator("[data-progress-for='LAB-LOANDESK-001']").inner_text() == "Workflow complete"


def test_reversible_defense_returns_the_attack_to_working(page, stack):
    page.goto(stack())
    go(page, "explore"); predict(page); go(page, "attack")
    page.click("[data-launch='attack']"); wait_run(page, "attack")
    go(page, "defend")
    page.check("input[name=posture][value=hardened]"); page.click("[data-apply-defense]")
    page.click("[data-revert-defense]")
    assert "BASELINE (applied)" in page.locator("[data-defense-current]").inner_text()
    go(page, "retest")
    assert "expect the attack to work again" in page.locator("[data-retest-posture]").inner_text()
    page.click("[data-launch='retest']"); wait_run(page, "retest")
    go(page, "compare")
    assert "do not show the defense working" in page.locator("[data-compare-table] .callout").last.inner_text()


def test_acmebank_down_is_a_visible_recoverable_state(page, stack):
    page.goto(stack(bank_url="http://127.0.0.1:9"))
    page.wait_for_function("() => !document.querySelector('[data-mission-banner]').hidden")
    assert "cannot be reached" in page.locator("[data-mission-banner]").inner_text()
    assert page.locator("[data-retry-status]").is_visible()
    go(page, "explore")
    page.click("[data-launch='explore']")
    page.wait_for_selector("[data-run-panel='explore'] button:has-text('Retry')")
    assert "Nothing ran" in page.locator("[data-run-panel='explore']").inner_text()
    assert page.locator("[data-launch='explore']").is_enabled()


def test_browser_disconnect_while_polling_recovers(page, stack):
    page.goto(stack(model=PostureAwareModel(delay=0.15)))
    go(page, "explore")
    failures = {"n": 0}

    def flaky(route):
        if "/runs/" in route.request.url and failures["n"] < 2:
            failures["n"] += 1
            route.abort()
        else:
            route.continue_()

    page.route("**/api/missions/loan-desk/runs/*", flaky)
    page.click("[data-launch='explore']")
    page.wait_for_selector("[data-run-panel='explore'] [data-reconnect]", timeout=10000)
    assert "Disconnected" in page.locator("[data-reconnect]").inner_text()
    wait_run(page, "explore", timeout=30000)
    assert "COMPLETED" in page.locator("[data-run-panel='explore']").inner_text()
    assert "Connection restored" in page.locator("[data-run-panel='explore']").inner_text()


def test_stop_waiting_then_keep_waiting_and_reload_resumes(page, stack):
    url = stack(model=PostureAwareModel(delay=0.6))
    page.goto(url)
    go(page, "explore")
    page.click("[data-launch='explore']")
    page.click("button:has-text('Stop waiting')")
    assert "run continues inside AcmeBank" in page.locator("[data-run-panel='explore']").inner_text()
    assert page.locator("[data-launch='explore']").is_enabled()
    page.click("button:has-text('Keep waiting')")
    wait_run(page, "explore", timeout=30000)
    page.reload()
    page.wait_for_selector("[data-run-panel='explore'] .outcomes")
    assert "COMPLETED" in page.locator("[data-run-panel='explore']").inner_text()  # re-adopted after reload


def test_mission_is_keyboard_operable_and_axe_clean(page, stack):
    pytest.importorskip("axe_playwright_python")
    from axe_playwright_python.sync_playwright import Axe
    page.goto(stack())
    seen = set()
    for _ in range(40):
        page.keyboard.press("Tab")
        seen.add(page.evaluate("document.activeElement.getAttribute('data-step-link') || document.activeElement.tagName"))
    assert {"understand", "explore", "explain"} <= seen
    go(page, "explore"); predict(page); go(page, "attack"); page.click("[data-launch='attack']"); wait_run(page, "attack")
    for step in ("understand", "explore", "predict", "attack", "observe", "investigate", "defend"):
        go(page, step)
        bad = [v for v in Axe().run(page).response["violations"] if v["impact"] in ("serious", "critical")]
        assert not bad, (step, [(v["id"], [n["target"] for n in v["nodes"]][:3]) for v in bad])


def test_phone_width_has_no_horizontal_scroll(browser, stack):
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    pg = ctx.new_page()
    pg.goto(stack())
    for step in ("explore", "predict", "attack"):
        go(pg, step) if step != "attack" else (predict(pg), go(pg, "attack"))
        assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), step
    ctx.close()
