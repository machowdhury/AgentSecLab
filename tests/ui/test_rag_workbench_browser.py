"""LAB-RAG-CONTEXT in the native Academy, in a real browser: Learn, Practice (predict, baseline, attack, retest, compare), Prove.

AcmeBank and the Attack Service run in this process; the RAG specimens call no model, so every decision comes from the real contract.
Error states are injected at the browser's network layer. SKIPPED, not passed, without Playwright and a Chromium (set AGENTSEC_CHROMIUM).
"""
from __future__ import annotations

import re
import threading

import pytest

pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app as create_attack  # noqa: E402
from agentsec.bank_app import build_runtime, create_app as create_bank  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401

HASH = "c565f364c7c5"


@pytest.fixture
def base(settings):
    servers = []
    bank = make_server("127.0.0.1", 0, create_bank(build_runtime(settings, otel_enabled=False)), threaded=True)
    attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(f"http://127.0.0.1:{bank.server_port}")), threaded=True)
    for s in (bank, attack):
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
    yield f"http://127.0.0.1:{attack.server_port}/learn/lab/LAB-RAG-CONTEXT"
    for s in servers:
        s.shutdown()


def launches(pg):
    seen = []
    pg.on("request", lambda r: seen.append(r.post_data) if r.url.endswith("/api/launch") and r.method == "POST" else None)
    return seen


def tab(pg, name):
    pg.get_by_role("tab", name=re.compile(name)).click()


def lock(pg, cls="OBSERVE", dec="ALLOW", hnd="will run"):
    pg.get_by_label(re.compile(rf"^{cls}")).first.check()
    pg.locator("input[name=rg-dec]").locator(f"xpath=following-sibling::span[text()='{dec}']").click()
    pg.get_by_label(hnd).check()
    pg.get_by_role("button", name="Lock prediction").click()


def test_learn_explains_the_lab_and_opening_the_page_launches_nothing(page, base):
    sent = launches(page)
    page.goto(base)
    text = page.locator("main, .page").first.inner_text()
    for needle in ("retrieval-augmented generation", "retrieved content is data", "Where the trust boundary is", "What the attacker controls", "Accepted is not obeyed", "CTRL-MCP-001"):
        assert needle.lower() in text.lower(), needle
    assert page.locator(".m-path__node").count() == 7
    tab(page, "Practice")
    assert page.get_by_text("calls no language model").count() == 1
    assert sent == [], "opening Learn and Practice never launches"


def test_attack_is_gated_by_the_prediction_and_baseline_retest_attack_read_correctly(page, base):
    sent = launches(page)
    page.goto(base); tab(page, "Practice")
    attack = page.get_by_role("button", name=re.compile("Launch ATTACK"))
    retest = page.get_by_role("button", name=re.compile("Run RETEST"))
    assert attack.is_disabled() and retest.is_disabled()
    assert page.get_by_role("button", name="Lock prediction").is_disabled()
    page.get_by_role("button", name=re.compile("Run BASELINE")).click()
    page.wait_for_selector("text=NORMAL DOCUMENT OBSERVED, NO FOLLOW-ON")
    assert attack.is_disabled(), "a baseline does not unlock the attack"
    lock(page)
    attack.dblclick()                                   # a double click must send one launch only
    page.wait_for_selector("text=FOLLOW-ON TOOL ALLOWED AND RAN")
    assert len([s for s in sent if "ATTACK" in s]) == 1
    page.get_by_text("You predicted OBSERVE for the classification, ALLOW").wait_for()
    assert retest.is_enabled()
    retest.click()
    page.wait_for_selector("text=FOLLOW-ON TOOL DENIED, HANDLER DID NOT RUN")
    assert len(sent) == 3
    cmp_ = page.locator("table", has_text="Follow-on decision (CTRL-MCP-001)")
    row = lambda k: cmp_.locator("tr", has_text=k).inner_text()
    assert "ALLOW" in row("Follow-on decision") and "DENY" in row("Follow-on decision")
    assert HASH in row("Content hash") and row("Content hash").count(HASH) == 2, "same document bytes on both runs"
    assert re.search(r"Handler count\s+1\s+0", row("Handler count"))
    assert "tool_not_granted" in row("Follow-on reason")
    body = page.locator("main, .page").first.inner_text()
    assert "no signed verifier" in body and not re.search(r"SPLUNK[- ]VERIFIED|independently verified: yes", body, re.I)
    assert "did not stop anything; the authorization control did" in body, "never credit the classifier"


def test_prove_separates_live_runs_from_recorded_specimens_and_never_claims_verification(page, base):
    page.goto(base); tab(page, "Prove")
    assert page.get_by_text("You have not launched anything in this lab yet").count() == 1
    tab(page, "Practice"); lock(page)
    page.get_by_role("button", name=re.compile("Launch ATTACK")).click()
    page.wait_for_selector("text=FOLLOW-ON TOOL ALLOWED AND RAN")
    tab(page, "Prove")
    heads = page.locator("table", has_text="Per live run").locator("th").evaluate_all("els => els.map(e => e.textContent)")
    assert [h.split(". ", 1)[-1] for h in heads[1:]] == ["Retrieved content observed", "Content classification", "Follow-on tool authorization", "Actual tool execution", "Telemetry received", "Independently verified"]
    row = page.locator("table", has_text="Per live run").locator("tbody tr").inner_text()
    assert "doc.lending-policy.malicious" in row and "OBSERVE" in row and "Handler count 1" in row and "No. This lab has no signed verifier" in row
    assert page.get_by_text("LIVE, NEW RUNS").count() == 1 and page.get_by_text("Recorded REPLAY ATTACK specimen").count() == 1


@pytest.mark.parametrize("mode", ["http503", "abort"])
def test_error_states_show_no_run_and_the_button_recovers(page, base, mode):
    sent = launches(page)
    if mode == "http503":
        page.route("**/api/launch", lambda r: r.fulfill(status=503, content_type="application/json", body='{"error":"runtime_unreachable","error_class":"ERROR"}'))
    else:
        page.route("**/api/launch", lambda r: r.abort())
    page.goto(base); tab(page, "Practice")
    page.get_by_role("button", name=re.compile("Run BASELINE")).click()
    page.wait_for_selector("[role=alert]")
    assert page.get_by_text(re.compile("Target unavailable|did not produce a run")).count() >= 1
    assert page.locator(".m-run").count() == 0 and len(sent) == 1, "no run card and no automatic retry"
    assert page.get_by_role("button", name=re.compile("Run BASELINE")).is_enabled()


def test_mobile_layout_has_no_horizontal_scroll_and_pi_lab_still_renders(browser, base):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    for t in ("Learn", "Practice", "Prove"):
        pg.goto(base); tab(pg, t)
        assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), t
    pg.goto(base); tab(pg, "Practice"); lock(pg)  # with run cards, the comparison and the hop tables on screen
    pg.get_by_role("button", name=re.compile("Launch ATTACK")).click(); pg.wait_for_selector("text=FOLLOW-ON TOOL ALLOWED AND RAN")
    pg.get_by_role("button", name=re.compile("Run RETEST")).click(); pg.wait_for_selector("text=FOLLOW-ON TOOL DENIED, HANDLER DID NOT RUN")
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "practice with runs"
    tab(pg, "Prove"); assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "prove with runs"
    pg.goto(base.replace("LAB-RAG-CONTEXT", "LAB-PI-001")); tab(pg, "Practice")
    assert pg.get_by_label("Guided sequence for Direct Prompt Injection").count() == 1
    ctx.close()
