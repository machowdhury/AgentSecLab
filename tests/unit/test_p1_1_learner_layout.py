"""P1.1: the START and PREDICT primary actions must be visible without scrolling.

Two layers, kept separate:

* Offline structure checks on the rendered markup (always run). They pin the properties the
  remediation must not lose: one primary action, the context panels still present, both
  prediction questions and all seven options present, and the disabled-state explanation.
* A real-browser layout check (runs only when a Chromium/Chrome is available; otherwise it is
  SKIPPED, not passed). It serves the real Flask app, drives it with real clicks and measures
  where the CTA actually renders. It checks layout only. It launches no experiment and
  makes no claim about runtime or Splunk evidence.
"""
from __future__ import annotations

import re
import threading

import pytest

from agentsec.attack_app import AcmeBankClient, create_app


@pytest.fixture(scope="module")
def app():
    application = create_app(AcmeBankClient("http://acmebank.example:5000"))
    application.config["TESTING"] = True
    return application


@pytest.fixture(scope="module")
def html(app) -> str:
    return app.test_client().get("/labs/LAB-MCP-001").get_data(as_text=True)


def _section(html: str, step: str) -> str:
    body = re.sub(r"<script.*?</script>", "", html, flags=re.S)
    return body.split(f'id="step-{step}"')[1].split("</section>")[0]


# --- structure (offline) ---------------------------------------------------------------


def test_start_has_exactly_one_primary_action_and_it_precedes_the_context_panels(html):
    start = _section(html, "start")
    assert len(re.findall(r'class="cta[ "]', start)) == 1
    cta = start.index('id="start-lab"')
    # the lead and the request-path diagram still come first; the action is not hoisted above them
    assert start.index('class="lead"') < start.index('class="flow"') < cta
    # nothing was removed: the three context panels are still on the page, after the action
    for heading in ("The story", "The question", "Your route"):
        assert start.index(f"<h3>{heading}</h3>") > cta
    assert "never granted" in start
    assert 'id="see-world-1"' in start


def test_predict_keeps_both_questions_all_options_and_the_disabled_explanation(html):
    predict = _section(html, "predict")
    assert predict.count("<fieldset") == 2
    assert re.findall(r'name="predict-control" value="(\w+)"', predict) == ["ALLOW", "DENY", "ERROR", "UNKNOWN"]
    assert re.findall(r'name="predict-execution" value="(\w+)"', predict) == ["YES", "NO", "UNKNOWN"]
    assert predict.count("UNSURE") >= 2
    button = re.search(r'<button[^>]*id="record-prediction"[^>]*>', predict).group(0)
    assert 'aria-disabled="true"' in button  # locked until both answers exist
    assert "Answer both questions to continue" in predict
    assert "not graded" in predict


def test_predict_does_not_disclose_an_outcome_before_the_attack(html):
    predict = _section(html, "predict").lower()
    for leak in ("tool_not_granted", "fail_open", "handler count", "pipeline stopped", "mcp.started"):
        assert leak not in predict


# --- real browser layout (skipped when no browser is available) ------------------------


@pytest.fixture(scope="module")
def served(app):
    from werkzeug.serving import make_server

    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    pw = sync_api.sync_playwright().start()
    launched = None
    for kwargs in ({}, {"channel": "chrome"}):
        try:
            launched = pw.chromium.launch(**kwargs)
            break
        except Exception:  # noqa: BLE001 - any launch failure means "no browser here"
            continue
    if launched is None:
        pw.stop()
        pytest.skip("no Chromium/Chrome available for the real-browser layout check")
    try:
        yield launched
    finally:
        launched.close()
        pw.stop()


def _page(browser, base: str, width: int, height: int):
    page = browser.new_page(viewport={"width": width, "height": height})
    page.goto(f"{base}/labs/LAB-MCP-001", wait_until="load")
    page.evaluate("sessionStorage.clear()")
    page.reload(wait_until="load")
    return page


def _in_view(page, selector: str) -> dict:
    return page.evaluate(
        """(sel) => { const b = document.querySelector(sel).getBoundingClientRect();
          return {top: b.top, bottom: b.bottom, vh: innerHeight,
                  hOverflow: document.documentElement.scrollWidth > innerWidth}; }""",
        selector,
    )


@pytest.mark.parametrize("size", [(1920, 1080), (1024, 768)])
def test_start_cta_is_visible_without_scrolling(browser, served, size):
    page = _page(browser, served, *size)
    box = _in_view(page, "#start-lab")
    assert 0 <= box["top"] and box["bottom"] <= box["vh"], box
    assert not box["hOverflow"]
    page.close()


def test_predict_cta_is_visible_at_1920x1080_and_does_not_move_when_answers_are_chosen(browser, served):
    page = _page(browser, served, 1920, 1080)
    page.click("#start-lab")
    page.click("#skip-baseline")
    empty = _in_view(page, "#record-prediction")
    assert 0 <= empty["top"] and empty["bottom"] <= empty["vh"], empty
    assert page.get_attribute("#record-prediction", "aria-disabled") == "true"
    # Enter on the locked CTA must not advance (disabled state is real, not just styled)
    page.focus("#record-prediction")
    page.keyboard.press("Enter")
    assert page.evaluate("document.querySelector('.step-view:not([hidden])').dataset.step") == "predict"
    page.check('input[name="predict-control"][value="UNKNOWN"]', force=True)
    page.check('input[name="predict-execution"][value="UNKNOWN"]', force=True)
    answered = _in_view(page, "#record-prediction")
    assert page.get_attribute("#record-prediction", "aria-disabled") == "false"
    assert 0 <= answered["top"] and answered["bottom"] <= answered["vh"], answered
    assert abs(answered["top"] - empty["top"]) <= 2, (empty, answered)  # choosing an answer must not shift the CTA
    assert not answered["hOverflow"]
    page.click("#record-prediction")
    assert page.evaluate("document.querySelector('.step-view:not([hidden])').dataset.step") == "attack"
    page.close()
