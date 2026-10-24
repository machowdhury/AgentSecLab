"""LAB-AGENT-GOAL-INTEGRITY-001 and LAB-AGENT-DELEGATION-001 in the native Academy, in a real browser: Learn, Practice, Prove.

AcmeBank and the Attack Service run in this process; neither lab calls a model, so every decision comes from the real contract.
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
from tests.ui.test_rag_workbench_browser import launches, tab  # noqa: E402

GOAL, DELEGATION = "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001"
CASES = {
    GOAL: dict(learn=["authorized tool is not an authorized goal", "Two controls, two questions", "Authorized tool, unauthorized use"], pick=[("classify", "OBSERVE"), ("decision", "ALLOW"), ("handler", "will run")],
               baseline="NORMAL TASK, IN-TASK TOOL USE", attack="AUTHORIZED TOOL RAN FOR AN UNAUTHORIZED GOAL", retest="GOAL EXPANSION DENIED, AUTHORIZED TASK KEPT",
               rows={"Goal decision": ("OBSERVE", "DENY"), "Effective action": ("extract_full_policy", "summarize_lending_policy"), "Tool decision": ("ALLOW", "ALLOW"), "Wrong-goal handler count": ("1", "0"), "In-task handler count": ("0", "1")},
               guess="You predicted OBSERVE from the goal control, ALLOW from the tool control", head="Proposed and effective action"),
    DELEGATION: dict(learn=["claimed identity is not an authenticated one", "Where the delegation boundary is", "NOT PROVEN / NOT MODELED"], pick=[("classify", "OBSERVE"), ("decision", "ALLOW"), ("handler", "will run")],
               baseline="GRANTED TOOL RAN, NO PRIVILEGED REQUEST", attack="PRIVILEGED TOOL ALLOWED AND RAN", retest="PRIVILEGED TOOL DENIED, HANDLER DID NOT RUN",
               rows={"Identity classification": ("OBSERVE", "OBSERVE"), "Who authenticated": ("NOT PROVEN / NOT MODELED", "NOT PROVEN / NOT MODELED"), "Tool decision": ("ALLOW", "DENY"), "Privileged handler count": ("1", "0")},
               guess="You predicted OBSERVE from the identity control, ALLOW from the tool control", head="Claim as recorded"),
}


@pytest.fixture
def url(settings):
    servers = []
    bank = make_server("127.0.0.1", 0, create_bank(build_runtime(settings, otel_enabled=False)), threaded=True)
    attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(f"http://127.0.0.1:{bank.server_port}")), threaded=True)
    for s in (bank, attack):
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
    yield lambda lab: f"http://127.0.0.1:{attack.server_port}/learn/lab/{lab}"
    for s in servers:
        s.shutdown()


def lock(pg, lab):
    for key, opt in CASES[lab]["pick"]:
        pg.locator(f"input[name='{lab}-{key}']").locator("xpath=following-sibling::span").filter(has_text=re.compile(f"^{opt}")).click()
    pg.get_by_role("button", name="Lock prediction").click()


def main(pg):
    return pg.locator("main, .page").first.inner_text()


@pytest.mark.parametrize("lab", [GOAL, DELEGATION])
def test_learn_explains_the_lab_and_opening_the_page_launches_nothing(page, url, lab):
    sent = launches(page)
    page.goto(url(lab))
    text = main(page).lower()
    for needle in CASES[lab]["learn"]:
        assert needle.lower() in text, needle
    assert page.locator(".m-path__node").count() == 7
    tab(page, "Practice")
    assert page.get_by_text("calls no language model").count() == 1
    assert sent == [], "opening Learn and Practice never launches"


@pytest.mark.parametrize("lab", [GOAL, DELEGATION])
def test_gating_and_baseline_attack_retest_read_the_real_records(page, url, lab):
    c, sent = CASES[lab], launches(page)
    page.goto(url(lab)); tab(page, "Practice")
    attack, retest = page.get_by_role("button", name=re.compile("Launch ATTACK")), page.get_by_role("button", name=re.compile("Run RETEST"))
    assert attack.is_disabled() and retest.is_disabled() and page.get_by_role("button", name="Lock prediction").is_disabled()
    page.get_by_role("button", name=re.compile("Run BASELINE")).click()
    page.wait_for_selector(f"text={c['baseline']}")
    assert attack.is_disabled(), "a baseline does not unlock the attack"
    lock(page, lab)
    attack.dblclick()                                   # a double click must send one launch only
    page.wait_for_selector(f"text={c['attack']}")
    assert len([s for s in sent if "ATTACK" in s]) == 1
    page.get_by_text(c["guess"]).wait_for()
    assert retest.is_enabled()
    retest.click()
    page.wait_for_selector(f"text={c['retest']}")
    assert len(sent) == 3
    cmp_ = page.locator("table", has_text="ATTACK (live)")
    for fact, (x, y) in c["rows"].items():
        cells = cmp_.locator("tr", has_text=fact).first.locator("td").all_inner_texts()
        assert cells[1:] == [x, y], (fact, cells)
    body = main(page)
    assert "no signed verifier" in body and not re.search(r"SPLUNK[- ]VERIFIED|independently verified: yes", body, re.I)
    assert "no model was involved" in body


@pytest.mark.parametrize("lab", [GOAL, DELEGATION])
def test_prove_separates_live_runs_from_recorded_specimens_and_never_claims_verification(page, url, lab):
    page.goto(url(lab)); tab(page, "Prove")
    assert page.get_by_text("You have not launched anything in this lab yet").count() == 1
    tab(page, "Practice"); lock(page, lab)
    page.get_by_role("button", name=re.compile("Launch ATTACK")).click()
    page.wait_for_selector(f"text={CASES[lab]['attack']}")
    tab(page, "Prove")
    t = page.locator("table", has_text="Per live run")
    heads = t.locator("th").evaluate_all("els => els.map(e => e.textContent)")
    assert [h.split(". ", 1)[-1] for h in heads[1:]][-1] == "Independently verified" and len(heads) == 7 and CASES[lab]["head"] in heads[1]
    row = t.locator("tbody tr").inner_text()
    assert "No. This lab has no signed verifier" in row and "handler" in row.lower()
    assert page.get_by_text("LIVE, NEW RUNS").count() == 1 and page.get_by_text("Recorded REPLAY ATTACK specimen").count() == 1
    if lab == DELEGATION:
        assert "NOT PROVEN / NOT MODELED" in row


@pytest.mark.parametrize("mode", ["http503", "abort"])
def test_error_states_show_no_run_and_the_button_recovers(page, url, mode):
    sent = launches(page)
    page.route("**/api/launch", (lambda r: r.fulfill(status=503, content_type="application/json", body='{"error":"runtime_unreachable","error_class":"ERROR"}')) if mode == "http503" else (lambda r: r.abort()))
    page.goto(url(DELEGATION)); tab(page, "Practice")
    page.get_by_role("button", name=re.compile("Run BASELINE")).click()
    page.wait_for_selector("[role=alert]")
    assert page.locator(".m-run").count() == 0 and len(sent) == 1, "no run card and no automatic retry"
    assert page.get_by_role("button", name=re.compile("Run BASELINE")).is_enabled()


@pytest.mark.parametrize("lab", [GOAL, DELEGATION])
def test_mobile_layout_has_no_horizontal_scroll_with_runs_on_screen(browser, url, lab):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    for t in ("Learn", "Practice", "Prove"):
        pg.goto(url(lab)); tab(pg, t)
        assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), t
    pg.goto(url(lab)); tab(pg, "Practice"); lock(pg, lab)
    pg.get_by_role("button", name=re.compile("Launch ATTACK")).click(); pg.wait_for_selector(f"text={CASES[lab]['attack']}")
    pg.get_by_role("button", name=re.compile("Run RETEST")).click(); pg.wait_for_selector(f"text={CASES[lab]['retest']}")
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "practice with runs"
    tab(pg, "Prove"); assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "prove with runs"
    ctx.close()
