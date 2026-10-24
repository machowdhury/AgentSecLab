"""Increment 11C in a real browser: MCP-006, MCP-CATALOG, Scanner, Blue Team, Multi-stage and Capstone recorded-evidence labs.

Each lab is exercised on its own. The pages must load their evidence on demand, launch nothing and call no lab API. SKIPPED, not passed, without
Playwright and a Chromium (set AGENTSEC_CHROMIUM).
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
from tests.test_recorded_investigations import EXPECTED  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_recorded_workbench_browser import run_button, tab, watch  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "academy-ui/src/content/recorded"
DECISION = ("LAB-MCP-006", "LAB-MCP-CATALOG")
INVESTIGATION = tuple(EXPECTED)


def data(lab):
    return json.loads((FILES / f"{lab}.json").read_text(encoding="utf-8"))


@pytest.fixture
def root(settings):
    bank = make_server("127.0.0.1", 0, create_bank(build_runtime(settings, otel_enabled=False)), threaded=True)
    attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(f"http://127.0.0.1:{bank.server_port}")), threaded=True)
    for s in (bank, attack):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{attack.server_port}/learn/lab/"
    for s in (bank, attack):
        s.shutdown()


def chunks(pg):
    seen = []
    pg.on("request", lambda r: seen.append(r.url) if "/assets/LAB-" in r.url else None)
    return seen


@pytest.mark.parametrize("lab", DECISION + INVESTIGATION)
def test_learn_has_the_scenario_and_objective_loads_no_evidence_and_calls_no_backend(page, root, lab):
    seen, loaded = watch(page), chunks(page)
    page.goto(root + lab)
    text = page.locator("main, .page").first.inner_text().lower()
    for h in ("the legitimate operation" if lab in DECISION else "the report" if lab != "LAB-ADVANCED-CAPSTONE-MASTERY-001" and lab != "LAB-SCANNER-RUNTIME-EVIDENCE" else "the scenario", "replay"):
        assert h in text, (lab, h)
    assert page.get_by_text("Full guided lesson not yet available").count() == 0
    assert loaded == [] and seen == [], "Learn loads no recorded evidence and calls no lab API"
    tab(page, "Practice")
    page.get_by_role("heading", level=4).first.wait_for()
    assert any(lab in u for u in loaded), "the evidence chunk loads when Practice opens"
    assert seen == []


@pytest.mark.parametrize("lab", DECISION)
def test_decision_labs_predict_reveal_explore_compare_and_prove(page, root, lab):
    d = data(lab)
    page.goto(root + lab); tab(page, "Practice")
    wb = page.get_by_test_id("recorded-workbench")
    assert "RECORDED — NOT RE-RUN" in wb.inner_text() and page.locator(".rec-event").count() == 0
    for run in d["runs"]:
        run_button(page, run["role"]).click()
        dec = run["events"][run["decisive"] - 1]["agentsec.control.decision"]
        assert dec not in wb.locator(".rec-setup").inner_text().split() and run["events"][run["decisive"] - 1]["agentsec.control.reason"] not in wb.inner_text()
        page.get_by_label("ALLOW" if dec != "ALLOW" else "DENY", exact=True).check()
        page.get_by_role("button", name="Reveal the recorded decision").click()
        assert f"The recorded decision is {dec}" in wb.locator(".rec-reveal").inner_text().replace("\n", " ") or dec in wb.locator(".rec-reveal").inner_text()
        assert page.locator(".rec-event").count() == len(run["events"])
        started = [e for e in run["events"] if e["event.name"] == "agentsec.mcp.started" and e["agentsec.operation.executed"] is True]
        assert (f"Handler began: yes. mcp.started is recorded at sequence {', '.join(str(e['agentsec.sequence']) for e in started)}" if started else "Handler began: no mcp.started event is in this pack") in wb.inner_text()
    assert wb.locator("table").count() == 1 and "(differs)" in wb.locator("table").text_content()
    tab(page, "Prove")
    p = page.get_by_test_id("recorded-prove").inner_text()
    assert "Verification status: not verified here" in p and all(r["run_id"] in p for r in d["runs"])


@pytest.mark.parametrize("lab", INVESTIGATION)
def test_investigation_answers_are_computed_from_the_packs_and_match(page, root, lab):
    d = data(lab)
    seen = watch(page)
    page.goto(root + lab); tab(page, "Practice")
    iw = page.get_by_test_id("investigation-workbench")
    assert "RECORDED — NOT RE-RUN" in iw.inner_text() and "YOUR ANSWER IS NOT EVIDENCE" in iw.inner_text()
    assert d["brief"]["paragraphs"][0][:40] in iw.inner_text()
    for i, q in enumerate(d["questions"]):
        li = iw.locator(".rec-q").nth(i)
        assert li.locator(".rec-reveal").count() == 0
        wrong = next(c for c in q["choices"] if c != EXPECTED[lab][q["id"]])
        li.locator(f"input[value='{wrong}']").check()
        li.get_by_role("button", name="Check against the recorded evidence").click()
        r = li.locator(".rec-reveal").inner_text()
        assert f"Recorded: {EXPECTED[lab][q['id']]}" in r.replace("\n", " ") and "did not match" in r and q["quote"]["text"] in r
        assert "Read from:" in r
    assert seen == [], "no launch and no lab API call"


@pytest.mark.parametrize("lab", INVESTIGATION)
def test_timeline_filters_comparison_and_pack_counts(page, root, lab):
    d = data(lab)
    page.goto(root + lab); tab(page, "Practice")
    iw = page.get_by_test_id("investigation-workbench")
    for s in d["scenarios"]:
        iw.locator(".rec-runs .rec-run", has_text=re.compile("^" + re.escape(s["label"]))).click()
        assert iw.locator(".rec-stage").count() == len(s["runs"])
        assert iw.locator(".rec-stage .rec-event").count() == sum(len(r["events"]) for r in s["runs"])
        iw.get_by_label("Control decisions").check()
        assert iw.locator(".rec-stage .rec-event").count() == sum(1 for r in s["runs"] for e in r["events"] if e["event.name"] == "agentsec.control.decision")
        iw.get_by_label("Handler events (mcp.*)").check()
        assert iw.locator(".rec-stage .rec-event").count() == sum(1 for r in s["runs"] for e in r["events"] if e["event.name"].startswith("agentsec.mcp."))
        iw.get_by_label("All events").check()
    t = iw.get_by_role("region", name=re.compile("^Scenario comparison"))
    body = t.text_content()
    assert "(differs)" in body and "Control decisions" in body and "Handler starts (mcp.started)" in body
    if d["external"]:
        scanner = iw.get_by_text("The scanner's own records").locator("xpath=..")
        assert scanner.locator(".rec-event").count() == sum(len(x["records"]) for x in d["external"])
        scanner.locator(".rec-event summary").first.click()
        assert "OBSERVED_SCANNER" in scanner.text_content() and d["external"][0]["records"][0]["artifact"]["description_sha256"] in scanner.text_content()


@pytest.mark.parametrize("lab", ("LAB-BLUE-TEAM-INCIDENT-001", "LAB-MULTI-STAGE-INCIDENT-001"))
def test_hints_are_disclosed_one_at_a_time_in_the_labs_order(page, root, lab):
    hints = next(b for b in data(lab)["blocks"] if b["group"] == "hints")["items"]
    page.goto(root + lab); tab(page, "Practice")
    iw = page.get_by_test_id("investigation-workbench")
    assert hints[0] not in iw.inner_text()
    iw.get_by_role("button", name=re.compile(r"^Show hint 1 of")).click()
    assert hints[0] in iw.inner_text() and hints[1] not in iw.inner_text()
    iw.get_by_role("button", name=re.compile(r"^Show hint 2 of")).click()
    assert hints[1] in iw.inner_text()


@pytest.mark.parametrize("lab", INVESTIGATION)
def test_prove_shows_provenance_verification_status_limits_and_the_labs_searches(page, root, lab):
    d = data(lab)
    page.goto(root + lab); tab(page, "Prove")
    p = page.get_by_test_id("investigation-prove")
    text = p.inner_text()
    assert "RECORDED — NOT RE-RUN" in text and "Verification status: not verified here" in text and "makes no claim that they are Splunk-verified" in text
    assert "SPLUNK-VERIFIED" not in text and "INDEXED" not in text
    for b in d["blocks"]:
        if b["group"] in ("prove", "limits", "rules"):
            assert b["title"] in text and b["items"][0][:60] in text
    if "graph" in d:
        assert p.get_by_role("region", name=re.compile("^Evidence graph nodes")).locator("tbody tr").count() == len(d["graph"]["nodes"])
        assert d["graph"]["scope"] in text and p.locator("li", has_text="CORRELATES_WITH").count() >= 1
    if "control_analysis" in d:
        assert p.get_by_role("region", name=re.compile("^Control analysis")).locator("tbody tr").count() == len(d["control_analysis"]["controls"])
    p.locator("summary", has_text="Provenance of each pack").click()
    assert all(r["sha256"] in p.inner_text() for s in d["scenarios"] for r in s["runs"]) and all(x["sha256"] in p.inner_text() for x in d["external"])
    for q in d["spl"]:
        assert p.locator("summary code", has_text=q["name"]).count() == 1
    if lab == "LAB-ADVANCED-CAPSTONE-MASTERY-001":
        assert "SELF-ASSESSED" in text
        box = p.get_by_role("checkbox").first
        box.focus(); page.keyboard.press("Space")
        assert box.is_checked()


def test_blocked_labs_keep_the_generic_page_and_the_other_labs_still_load(page, root):
    for lab in ("LAB-SPLUNK-DEFENDER-BRIDGE", "LAB-DETECTION-ENGINEERING"):
        page.goto(root + lab)
        assert page.get_by_role("tab", name=re.compile("Practice")).count() == 0, "these labs have no recorded evidence of their own, so there is no Practice step"
        assert page.get_by_test_id("recorded-workbench").count() == 0 and page.get_by_test_id("investigation-workbench").count() == 0
    for lab in ("LAB-MCP-003", "LAB-PI-001", "LAB-MEMORY-001"):
        assert page.goto(root + lab).status == 200
    page.goto(root + "LAB-MCP-004"); tab(page, "Practice")
    assert page.get_by_test_id("recorded-workbench").count() == 1


@pytest.mark.parametrize("lab", DECISION + INVESTIGATION)
def test_keyboard_and_390px_layout(browser, root, lab):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    ok = "document.documentElement.scrollWidth <= window.innerWidth + 1"
    pg.goto(root + lab); assert pg.evaluate(ok), "learn"
    tab(pg, "Practice")
    if lab in DECISION:
        pg.get_by_role("button", name="Skip the prediction and show the evidence").click()
        run_button(pg, data(lab)["runs"][1]["role"]).click(); pg.get_by_role("button", name="Skip the prediction and show the evidence").click()
        wrap = pg.get_by_role("region", name=re.compile("^Comparison of the revealed runs"))
    else:
        iw = pg.get_by_test_id("investigation-workbench")
        iw.get_by_role("button", name="Show the answer without predicting").first.click()
        iw.locator(".rec-event summary").first.click()
        wrap = iw.get_by_role("region", name=re.compile("^Scenario comparison"))
    assert pg.evaluate(ok), "practice"
    wrap.focus(); assert wrap.evaluate("e => e === document.activeElement"), "a sideways-scrolling region is keyboard-focusable"
    tab(pg, "Prove")
    for s in pg.locator("details > summary").all()[:1]:
        s.click()
    assert pg.evaluate(ok), "prove"
    # keyboard: a question's radios and button work without a mouse
    if lab in INVESTIGATION:
        tab(pg, "Practice")
        first = pg.locator(".rec-q").first
        first.locator("input[type=radio]").first.focus(); pg.keyboard.press("Space")
        assert first.locator("input[type=radio]").first.is_checked()
        first.get_by_role("button", name="Check against the recorded evidence").focus(); pg.keyboard.press("Enter")
        assert first.locator(".rec-reveal").count() == 1
    ctx.close()
