"""LAB-MCP-003/004/005 recorded-evidence workbench in a real browser: Learn, predict, explore, compare, Prove.

The page is the committed Academy build served by the Attack Service. It must never launch anything or call a backend for these labs, so the
tests also fail on any /api request other than the shell's own configuration. SKIPPED, not passed, without Playwright and a Chromium (set AGENTSEC_CHROMIUM).
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app as create_attack  # noqa: E402
from agentsec.bank_app import build_runtime, create_app as create_bank  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401

ROOT = Path(__file__).resolve().parents[2]
DATA = {l["id"]: l["explainer"]["recorded"] for l in json.loads((ROOT / "academy-ui/src/content/curriculum.json").read_text(encoding="utf-8"))["labs"] if l["explainer"] and l["explainer"].get("recorded")}


@pytest.fixture
def root(settings):
    bank = make_server("127.0.0.1", 0, create_bank(build_runtime(settings, otel_enabled=False)), threaded=True)
    attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(f"http://127.0.0.1:{bank.server_port}")), threaded=True)
    for s in (bank, attack):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{attack.server_port}/learn/lab/"
    for s in (bank, attack):
        s.shutdown()


SHELL_GETS = ("/api/learn/config", "/api/academy/status")      # the Academy shell's own read-only polling, present on every page


def watch(pg):
    """Every /api request other than the shell's own GETs. A launch, a POST or any lab call would land here."""
    seen = []
    pg.on("request", lambda r: seen.append((r.method, r.url)) if "/api/" in r.url and not (r.method == "GET" and r.url.endswith(SHELL_GETS)) else None)
    return seen


def tab(pg, name):
    pg.get_by_role("tab", name=re.compile(name)).click()


def run_button(pg, role):
    return pg.locator(".rec-run", has_text=re.compile(rf"^{role}"))


def predict(pg, role, answer):
    run_button(pg, role).click()
    pg.get_by_label(answer, exact=True).check()
    pg.get_by_role("button", name="Reveal the recorded decision").click()


def test_learn_explains_the_operation_attacker_boundary_and_rule_and_labels_the_lab_replay(page, root):
    for lab, needles in (("LAB-MCP-003", ("lookup_policy", "policy:read", "requested scope")),
                         ("LAB-MCP-004", ("lending-basics", "resource", "never widen")),
                         ("LAB-MCP-005", ("first hop", "tool result", "never create permission"))):
        seen = watch(page)
        page.goto(root + lab)
        text = page.locator("main, .page").first.inner_text().lower()
        for h in ("the legitimate operation", "what the attacker controls", "the trust boundary", "the authorization rule"):
            assert h in text, (lab, h)
        for n in needles:
            assert n.lower() in text, (lab, n)
        assert "replay" in text and page.get_by_text("Full guided lesson not yet available").count() == 0
        assert seen == [], "Learn calls no backend"


def test_prediction_gates_the_events_and_a_wrong_or_right_guess_is_never_called_evidence(page, root):
    seen = watch(page)
    page.goto(root + "LAB-MCP-003"); tab(page, "Practice")
    wb = page.get_by_test_id("recorded-workbench")
    assert "RECORDED — NOT RE-RUN" in wb.inner_text()
    assert page.locator(".rec-event").count() == 0 and "YOUR PREDICTION IS NOT EVIDENCE" in wb.inner_text()
    setup = wb.locator(".rec-setup").inner_text()
    assert "policy:read" in setup and "ALLOW" not in setup and "tool_granted" not in wb.inner_text(), "decision and reason stay hidden before the reveal"
    assert page.get_by_role("button", name="Reveal the recorded decision").is_disabled()
    predict(page, "ATTACK", "DENY")                               # the vulnerable profile fails open: the guess is wrong
    reveal = wb.locator(".rec-reveal").inner_text()
    assert "You predicted DENY" in reveal and "did not match" in reveal and "vulnerable_profile_fail_open:scope_not_granted" in reveal
    assert page.locator(".rec-event").count() == 7
    assert seen == [], "no launch, no backend call"


def test_events_are_the_committed_pack_in_order_and_handler_execution_comes_only_from_mcp_started(page, root):
    page.goto(root + "LAB-MCP-003"); tab(page, "Practice")
    predict(page, "ATTACK", "ALLOW")
    rows = page.locator(".rec-event")
    assert "matched" in page.locator(".rec-reveal").inner_text()
    names = [rows.nth(i).locator("summary code").inner_text() for i in range(rows.count())]
    src = DATA["LAB-MCP-003"]["runs"][1]
    assert names == [e["event.name"].replace("agentsec.", "") for e in src["events"]]
    assert "Handler began: yes. mcp.started is recorded at sequence 4" in page.get_by_test_id("recorded-workbench").inner_text()
    rows.nth(2).locator("summary").click()                         # the ALLOW decision event records executed=false: it is not execution
    d = rows.nth(2).text_content()                                 # text_content: the field names are upper-cased by CSS in inner_text
    assert "agentsec.operation.executed" in d and "false" in d and "agentsec.control.reason" in d
    predict(page, "RETEST", "DENY")
    assert "Handler began: no mcp.started event is in this pack" in page.get_by_test_id("recorded-workbench").inner_text()
    assert page.get_by_text("not proof that the handler never ran", exact=False).count() == 1


def test_compare_shows_only_revealed_runs_and_only_recorded_differences(page, root):
    page.goto(root + "LAB-MCP-003"); tab(page, "Practice")
    wb = page.get_by_test_id("recorded-workbench")
    assert "Reveal at least two runs" in wb.inner_text()
    predict(page, "ATTACK", "ALLOW")
    assert "Reveal at least two runs" in wb.inner_text() and wb.locator("table").count() == 0
    predict(page, "RETEST", "DENY")
    t = wb.locator("table")
    assert t.count() == 1 and "UNKNOWN" not in t.inner_text() and "BASELINE" not in t.inner_text(), "unrevealed runs are not spoiled"
    differs = {t.locator("tbody tr").nth(i).locator("th").text_content() for i in range(t.locator("tbody tr").count()) if t.locator("tbody tr").nth(i).locator("th small").count()}
    assert {"Profile", "Testbed mode", "Decision", "Reason", "Handler began (mcp.started events)", "How the run ended"} <= {d.replace(" (differs)", "") for d in differs}
    assert not ({"Requested scope", "Tool"} & {d.replace(" (differs)", "") for d in differs}), "the same request was recorded on both"
    assert "name the same tool, scope and resource" in wb.inner_text()


def test_mcp_005_shows_the_overlay_authority_the_truncated_preview_and_the_follow_on_denial(page, root):
    page.goto(root + "LAB-MCP-005"); tab(page, "Practice")
    wb = page.get_by_test_id("recorded-workbench")
    run_button(page, "ATTACK").click()
    assert "SECURITY_OVERRIDE" in wb.inner_text(), "the first tool call's recorded result is shown as setup"
    assert "result-derived overlay" not in wb.inner_text(), "the authority label is part of the answer and stays hidden until the reveal"
    page.get_by_label("ALLOW", exact=True).check(); page.get_by_role("button", name="Reveal the recorded decision").click()
    rows = page.locator(".rec-event")
    assert rows.count() == 13
    rows.nth(8).locator("summary").click()
    assert "result-derived overlay" in rows.nth(8).inner_text() and "lookup_customer_tie" in rows.nth(8).inner_text(), "preview shown verbatim, cut off exactly as recorded"
    predict(page, "RETEST", "DENY")
    assert "tool_not_granted" in page.locator(".rec-reveal").inner_text()
    predict(page, "BASELINE", "OBSERVE")
    assert "result_is_data" in page.locator(".rec-reveal").inner_text()
    assert wb.locator("table").count() == 1 and "server-owned" in wb.locator("table").inner_text() and "result-derived overlay" in wb.locator("table").inner_text()


def test_prove_names_the_decisive_event_provenance_spl_and_makes_no_verification_claim(page, root):
    for lab in DATA:
        page.goto(root + lab); tab(page, "Prove")
        p = page.get_by_test_id("recorded-prove")
        text = p.inner_text()
        assert "RECORDED — NOT RE-RUN" in text and "Verification status: not verified here" in text
        assert "SPLUNK-VERIFIED" not in text and "INDEXED" not in text, "no verified or indexed label is shown"
        assert "makes no claim that they are Splunk-verified" in text
        for run in DATA[lab]["runs"]:
            assert run["run_id"] in text
        p.locator("summary", has_text="Provenance of each pack").click()
        assert DATA[lab]["runs"][0]["sha256"] in p.inner_text() and DATA[lab]["runs"][0]["pack"] in p.inner_text()
        for q in DATA[lab]["spl"]:
            assert p.locator("summary code", has_text=q["name"]).count() == 1
        assert page.get_by_text("cannot", exact=False).count() >= 1 and page.locator(".m-rules li").count() > 0


def test_other_replay_labs_keep_the_generic_lab_page(page, root):
    page.goto(root + "LAB-MCP-006"); tab(page, "Practice")
    assert page.get_by_test_id("recorded-workbench").count() == 0
    assert "Recorded evidence only" in page.locator("main, .page").first.inner_text()


def test_keyboard_only_journey_and_390px_layout(browser, root):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    ok = "document.documentElement.scrollWidth <= window.innerWidth + 1"
    for lab in DATA:
        pg.goto(root + lab); assert pg.evaluate(ok), (lab, "learn")
        tab(pg, "Practice"); assert pg.evaluate(ok), (lab, "practice")
        for role in [r["role"] for r in DATA[lab]["runs"]][:2]:
            run_button(pg, role).click()
            pg.get_by_role("button", name="Skip the prediction and show the evidence").click()
        assert pg.evaluate(ok), (lab, "events and compare")
        wrap = pg.get_by_role("region", name=re.compile("^Comparison of the revealed runs"))
        wrap.focus(); assert wrap.evaluate("e => e === document.activeElement"), "a sideways-scrolling region must be keyboard-focusable"
        pg.locator(".rec-event summary").first.click(); assert pg.evaluate(ok), (lab, "event detail")
        tab(pg, "Prove"); pg.get_by_test_id("recorded-prove").locator("summary", has_text="Provenance").click()
        assert pg.evaluate(ok), (lab, "prove")
    # keyboard: tab to a run button, activate with Enter, answer with the arrow keys and Space, reveal with Enter
    pg.goto(root + "LAB-MCP-004"); tab(pg, "Practice")
    pg.locator(".rec-run").nth(2).focus(); pg.keyboard.press("Enter")
    assert pg.locator(".rec-run.is-current").inner_text().startswith("RETEST")
    pg.get_by_label("ALLOW", exact=True).focus(); pg.keyboard.press("ArrowDown"); pg.keyboard.press("Space")
    assert pg.get_by_label("DENY", exact=True).is_checked()
    pg.get_by_role("button", name="Reveal the recorded decision").focus(); pg.keyboard.press("Enter")
    assert "resource_not_granted" in pg.locator(".rec-reveal").inner_text()
    pg.locator(".rec-event summary").first.focus(); pg.keyboard.press("Enter")
    assert pg.locator(".rec-event details[open]").count() == 1
    ctx.close()


def test_nothing_on_the_page_gives_away_the_decision_before_the_reveal(page, root):
    """The lab's own README line for a run states the decision, reason and handler count; it must appear only after the reveal."""
    for lab in DATA:
        for run in DATA[lab]["runs"]:
            page.goto(root + lab); tab(page, "Practice")           # a fresh page per run: earlier reveals must not be on screen
            wb = page.get_by_test_id("recorded-workbench")
            run_button(page, run["role"]).click()
            d = run["events"][run["decisive"] - 1]
            before = wb.inner_text()
            for secret in (d["agentsec.control.reason"], "handler=", run["documented_as"]["text"][:30]):
                assert secret not in before, (lab, run["role"], secret)
            assert not re.search(rf"\b{d['agentsec.control.decision']}\b", wb.locator(".rec-setup").inner_text()), (lab, run["role"])
            page.get_by_role("button", name="Skip the prediction and show the evidence").click()
            assert run["documented_as"]["text"][:30] in wb.inner_text(), "the lab's own line appears after the reveal"
