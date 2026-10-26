"""Increment 11E in a real browser: the Privacy, Threat Modeling and Garak study checkpoints.

The sources load on demand, nothing is launched and no lab API is called. SKIPPED, not passed, without Playwright and a Chromium (set AGENTSEC_CHROMIUM).
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
from tests.test_study_checkpoints import GARAK, PRIV, STUDY, TM, answers, cp  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_recorded_workbench_browser import tab, watch  # noqa: E402

LEARN_HEADINGS = ("the legitimate workflow", "the threat", "the trust boundary", "the security control", "what the evidence can and cannot show")
LABEL = {TM: "NOT AN ASSESSMENT", PRIV: "NOT A LIVE RUN", GARAK: "NOT RE-RUN"}


@pytest.fixture
def root(settings):
    bank = make_server("127.0.0.1", 0, create_bank(build_runtime(settings, otel_enabled=False)), threaded=True)
    attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(f"http://127.0.0.1:{bank.server_port}")), threaded=True)
    for s in (bank, attack):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{attack.server_port}/learn/lab/"
    for s in (bank, attack):
        s.shutdown()


def question(wb, q):
    return wb.locator(".rec-q", has_text=q["prompt"])


def choose(li, options):
    for o in options:
        li.get_by_label(o, exact=True).check()


@pytest.mark.parametrize("lab", STUDY)
def test_learn_covers_the_five_headings_and_loads_no_source_until_practice(page, root, lab):
    seen, loaded = watch(page), []
    page.on("request", lambda r: loaded.append(r.url) if "/assets/LAB-" in r.url else None)
    page.goto(root + lab)
    text = page.locator("main, .page").first.inner_text().lower()
    for h in LEARN_HEADINGS:
        assert h in text, (lab, h)
    assert page.get_by_text("Full guided lesson not yet available").count() == 0
    assert loaded == [] and seen == []
    tab(page, "Practice")
    page.get_by_test_id("checkpoint-workbench").wait_for()
    assert any(lab in u for u in loaded) and seen == []


@pytest.mark.parametrize("lab", STUDY)
def test_correct_answers_match_and_nothing_is_revealed_before_checking(page, root, lab):
    seen = watch(page)
    page.goto(root + lab); tab(page, "Practice")
    wb = page.get_by_test_id("checkpoint-workbench")
    assert LABEL[lab] in wb.inner_text() and "YOUR ANSWER IS NOT EVIDENCE" in wb.inner_text()
    assert wb.locator(".rec-reveal").count() == 0
    for q in answers(lab).values():
        li = question(wb, q)
        choose(li, q["answer"])
        li.get_by_role("button", name="Check against the sources").click()
        r = li.locator(".rec-reveal").inner_text()
        assert "that matches" in r and "does not match" not in r, q["id"]
        assert all(a in r for a in q["answer"])
        if "quote" in q:
            assert q["quote"]["text"] in r
    assert seen == []


@pytest.mark.parametrize("lab", STUDY)
def test_a_wrong_answer_is_marked_wrong_and_shows_the_sources_answer(page, root, lab):
    page.goto(root + lab); tab(page, "Practice")
    wb = page.get_by_test_id("checkpoint-workbench")
    for q in answers(lab).values():
        li = question(wb, q)
        choose(li, [next(c for c in q["candidates"] if c not in q["answer"])])
        assert li.get_by_role("button", name="Check against the sources").is_enabled()
        li.get_by_role("button", name="Check against the sources").click()
        r = li.locator(".rec-reveal").inner_text()
        assert "does not match" in r and all(a in r for a in q["answer"]), q["id"]
        assert li.locator("input").first.is_disabled()


@pytest.mark.parametrize("lab", STUDY)
def test_check_is_disabled_until_an_option_is_chosen(page, root, lab):
    page.goto(root + lab); tab(page, "Practice")
    q = next(iter(answers(lab).values()))
    assert question(page.get_by_test_id("checkpoint-workbench"), q).get_by_role("button", name="Check against the sources").is_disabled()


def test_privacy_compare_shows_both_records_and_the_documented_authorization(page, root):
    d = cp(PRIV); dm = d["packet"]["data_map"]
    page.goto(root + PRIV); tab(page, "Practice")
    wb = page.get_by_test_id("checkpoint-workbench"); wb.wait_for()
    t = wb.get_by_role("region", name=re.compile("^Full record and minimized record"))
    rows = t.locator("tbody tr")
    assert rows.count() == len(dm["full_record"])
    for k, v in dm["full_record"].items():
        row = [r for r in rows.all() if r.locator("th").text_content().startswith(k)][0]
        assert v in row.text_content()
        assert ("(differs)" in row.text_content() or "only in the" in row.text_content()) == (k not in dm["minimized_record"])
        assert dm["minimized_record"].get(k, "—") in row.text_content()
    text = wb.text_content()
    for x in d["spec"]["documented"]:
        assert x["text"] in text, x["label"]
    assert "documented statements; nothing was re-run" in text


@pytest.mark.parametrize("lab", STUDY)
def test_prove_says_not_verified_shows_provenance_limits_and_no_live_claim(page, root, lab):
    d = cp(lab); spec = d["spec"]
    page.goto(root + lab); tab(page, "Prove")
    p = page.get_by_test_id("checkpoint-prove"); p.wait_for(); text = p.text_content()
    assert LABEL[lab] in text and "Verification status: not verified here" in text and spec["verification"] in text
    assert "SPLUNK-VERIFIED" not in text
    for x in spec["limits"]:
        assert x["text"] in text
    for t in spec.get("tables", []):
        assert p.get_by_role("region", name=re.compile("^" + re.escape(t["title"]))).locator("tbody tr").count() >= 1
    for l in spec.get("lists", []):
        assert all(x in text for x in dig(d["packet"], l["path"]))
    p.locator("summary", has_text="Provenance of each source file").click()
    for f in d["files"]:
        assert f["sha256"] in p.text_content() and f["file"] in p.text_content()
    for q in d["spl"]:
        assert p.locator("summary code", has_text=q["name"]).count() == 1


def dig(o, path):
    for k in path.split("."):
        o = o[int(k)] if isinstance(o, list) else o[k]
    return o


def test_threat_modeling_prove_lists_every_catalog_threat_and_makes_no_assessment_claim(page, root):
    d = cp(TM)
    page.goto(root + TM); tab(page, "Prove")
    p = page.get_by_test_id("checkpoint-prove"); p.wait_for()
    rows = p.get_by_role("region", name=re.compile("^Catalog threats")).locator("tbody tr")
    assert rows.count() == len(d["packet"]["catalog"]["threats"]) == 9
    for t in d["packet"]["catalog"]["threats"]:
        row = [r for r in rows.all() if r.locator("td").first.text_content() == t["id"]][0]
        assert t["gap"] in row.text_content() and t["residual_risk"] in row.text_content()
    text = p.text_content()
    assert "REASONING PROMPTS / NOT A COMPLETED THREAT MODEL" in text and "numerical risk score" in text


def test_garak_prove_shows_model_probe_result_hash_response_and_the_narrow_scope(page, root):
    d = cp(GARAK); man = d["packet"]["manifest"]
    page.goto(root + GARAK); tab(page, "Prove")
    p = page.get_by_test_id("checkpoint-prove"); p.wait_for(); text = p.text_content()
    for v in (man["target"]["model"], man["execution"]["probe"], man["execution"]["detector"], man["provenance"]["raw_evidence_sha256"], man["native_evaluation_id"], "garak", "0.17.0"):
        assert v in text, v
    ev = d["packet"]["raw"]["eval"][0]
    row = p.get_by_role("region", name=re.compile("^The native result rows")).locator("tbody tr")
    assert row.count() == 1 and all(str(ev[k]) in row.text_content() for k in ("passed", "fails", "total_evaluated"))
    reply = d["packet"]["raw"]["attempt"][0]["outputs"][0]["text"]
    assert reply in text
    assert "One local model, one probe, one generation, and one detector." in text and "Universal model safety: NOT PROVEN" in text
    assert "not re-run here" in text and "does not recompute" in text
    page.goto(root + GARAK)
    assert "not a comprehensive" in page.locator("main, .page").first.inner_text().lower()


def test_earlier_checkpoints_are_unchanged(page, root):
    page.goto(root + "LAB-ASSET-INVENTORY"); tab(page, "Practice")
    assert "DOCUMENTED — NOT A LIVE RUN" in page.get_by_test_id("checkpoint-workbench").inner_text()
    page.goto(root + "LAB-HITL-APPROVAL"); tab(page, "Practice")
    page.get_by_test_id("checkpoint-workbench").get_by_role("button", name="Skip the predictions and show the record").wait_for()


@pytest.mark.parametrize("lab", STUDY)
def test_keyboard_and_390px_layout(browser, root, lab):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    ok = "document.documentElement.scrollWidth <= window.innerWidth + 1"
    pg.goto(root + lab); assert pg.evaluate(ok), "learn"
    tab(pg, "Practice"); wb = pg.get_by_test_id("checkpoint-workbench"); wb.wait_for()
    assert pg.evaluate(ok), "practice"
    q = next(iter(answers(lab).values())); li = question(wb, q)
    box = li.locator("input").first
    box.focus(); pg.keyboard.press("Space"); assert box.is_checked(), "options work from the keyboard"
    li.get_by_role("button", name="Check against the sources").focus(); pg.keyboard.press("Enter")
    assert li.locator(".rec-reveal").count() == 1
    assert pg.evaluate(ok), "after interaction"
    if lab == PRIV:
        region = wb.get_by_role("region", name=re.compile("^Full record and minimized record"))
        region.focus(); assert region.evaluate("e => e === document.activeElement"), "sideways-scrolling regions are keyboard-focusable"
    tab(pg, "Prove"); pr = pg.get_by_test_id("checkpoint-prove")
    pr.locator("summary").first.click()
    assert pg.evaluate(ok), "prove"
    region = pr.get_by_role("region").first
    region.focus(); assert region.evaluate("e => e === document.activeElement")
    ctx.close()
