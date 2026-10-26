"""Increment 11G in a real browser: the three recorded-Splunk labs.

The recorded evidence loads on demand, nothing is searched, launched or sent to Splunk, and no lab API is called. SKIPPED, not passed, without Playwright and a Chromium.
"""
from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")
from tests.test_splunk_workbench import BR, DE, ID, SPLUNK, ans, cp, rows  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_recorded_workbench_browser import tab, watch  # noqa: E402
from tests.ui.test_study_browser import choose, question, root  # noqa: E402,F401

HEADINGS = ("the legitimate workflow", "the threat", "the trust boundary", "the security control", "what the evidence can and cannot show")
LABEL = "RECORDED SPLUNK OBSERVATION — NOT RE-RUN"
CHECK = "Check against the sources"


def stage(pg, title):
    pg.locator(".rec-runs button", has_text=re.compile("^" + re.escape(title))).click()


def searches(lab):
    return {s["id"]: s for s in cp(lab)["packet"]["searches"]["searches"]}


def answer_stage(pg, wb, st, right=True):
    for q in st["questions"]:
        li = question(wb, q)
        choose(li, q["answer"] if right else [next(c for c in q["candidates"] if c not in q["answer"])])
        li.get_by_role("button", name=CHECK).click()
        assert ("that matches" in li.locator(".rec-reveal").inner_text()) == right, q["id"]


def open_practice(pg, root, lab):
    pg.goto(root + lab); tab(pg, "Practice")
    wb = pg.get_by_test_id("splunk-workbench"); wb.wait_for()
    return wb


@pytest.mark.parametrize("lab", SPLUNK)
def test_learn_has_the_five_headings_and_loads_no_evidence_until_practice(page, root, lab):
    seen, loaded = watch(page), []
    page.on("request", lambda r: loaded.append(r.url) if "/assets/LAB-" in r.url else None)
    page.goto(root + lab)
    text = page.locator("main, .page").first.inner_text().lower()
    assert all(h in text for h in HEADINGS) and page.get_by_text("Full guided lesson not yet available").count() == 0
    assert loaded == [] and seen == []
    tab(page, "Practice"); page.get_by_test_id("splunk-workbench").wait_for()
    assert any(lab in u for u in loaded) and seen == []


@pytest.mark.parametrize("lab", SPLUNK)
def test_predictions_hide_the_results_until_reveal_then_rows_and_metadata_match_the_recording(page, root, lab):
    seen = watch(page); wb = open_practice(page, root, lab); spec = cp(lab)["spec"]; by = searches(lab)
    assert LABEL in wb.inner_text() and "YOUR PREDICTION IS NOT EVIDENCE" in wb.inner_text()
    for st in spec["stages"]:
        s = by[st["search"]]
        stage(page, st["title"])
        before = wb.inner_text()
        assert s["sid"] not in before and wb.locator(".rec-predict table").count() == 0, st["search"]
        btn = wb.get_by_role("button", name="Show the recorded results", exact=True)
        assert btn.is_disabled(), "results need every prediction checked, or an explicit skip"
        answer_stage(page, wb, st)
        assert btn.is_enabled(); btn.click()
        res = wb.locator(".rec-predict .rec-reveal").last
        text = res.inner_text()
        assert s["sid"] in text and s["submitted_at"] in text and s["dispatch_state"] in text and f"result count{s['result_count']}" in text.lower().replace("\n", "")
        if s["rows"]:
            t = res.get_by_role("region", name=re.compile("^Rows returned by"))
            assert t.locator("tbody tr").count() == len(s["rows"]) == int(s["result_count"])
            first = t.locator("tbody tr").first.inner_text()
            for k, v in s["rows"][0].items():
                if not k.startswith("_") and isinstance(v, str):
                    assert v in first, (s["id"], k)
        else:
            assert "Zero rows returned" in text and "executed successfully" in text and "does not by itself prove" in text
        assert "none recorded" in text
    assert seen == []


@pytest.mark.parametrize("lab", SPLUNK)
def test_wrong_predictions_are_marked_wrong_and_skip_still_shows_the_recording(page, root, lab):
    wb = open_practice(page, root, lab); spec = cp(lab)["spec"]
    st = spec["stages"][0]
    answer_stage(page, wb, st, right=False)
    wb.get_by_role("button", name="Show the recorded results", exact=True).click()
    assert searches(lab)[st["search"]]["sid"] in wb.inner_text()
    stage(page, spec["stages"][1]["title"])
    wb.get_by_role("button", name="Skip the predictions and show the recorded results").click()
    assert searches(lab)[spec["stages"][1]["search"]]["sid"] in wb.inner_text()


def test_detection_compare_needs_both_searches_and_computes_the_difference(page, root):
    wb = open_practice(page, root, DE); spec = cp(DE)["spec"]
    assert "Show the recorded results of Q-DET-BROAD and Q-DET-TUNED to compare them" in wb.inner_text()
    for sid in ("Q-DET-BROAD", "Q-DET-TUNED"):
        stage(page, next(s["title"] for s in spec["stages"] if s["search"] == sid))
        wb.get_by_role("button", name="Skip the predictions and show the recorded results").click()
    t = wb.inner_text()
    assert "Q-DET-BROAD returned 2 rows and Q-DET-TUNED returned 0" in t and "not in Q-DET-TUNED: 2 of 2" in t


def test_identity_compare_keeps_committed_packs_and_the_current_observation_apart(page, root):
    wb = open_practice(page, root, ID); spec = cp(ID)["spec"]
    stage(page, spec["stages"][1]["title"]); wb.get_by_role("button", name="Skip the predictions and show the recorded results").click()
    t = wb.inner_text()
    assert "Committed specimen evidence" in t and "Current Splunk observation" in t and "different populations" in t
    committed = cp(ID)["packet"]["manifest"]["three_kinds_of_evidence"]["committed_specimen_evidence"]["runs"]
    region = wb.get_by_role("region", name=re.compile("^Committed specimen evidence"))
    for r in committed:
        assert r["run_id"] in region.inner_text()


@pytest.mark.parametrize("lab", SPLUNK)
def test_provenance_table_appears_after_the_questions_and_counts_pack_backed_and_unmatched_runs(page, root, lab):
    wb = open_practice(page, root, lab); pm = cp(lab)["packet"]["matching"]; spec = cp(lab)["spec"]
    assert wb.get_by_role("region", name=re.compile("^Runs this lab's recorded searches depend on")).count() == 0
    for q in spec["provenance"]["questions"]:
        li = question(wb, q); choose(li, q["answer"]); li.get_by_role("button", name=CHECK).click()
    t = wb.get_by_role("region", name=re.compile("^Runs this lab's recorded searches depend on"))
    assert t.locator("tbody tr").count() == len(pm["runs"])
    assert t.get_by_text("no committed pack").count() == sum(1 for r in pm["runs"] if not r["committed_pack"])
    w = pm["index_wide"]
    assert f"{w['otel_runs_in_index']} runs are indexed. {w['runs_with_committed_pack']} have a committed pack and {w['runs_without_committed_pack']} do not." in wb.inner_text()
    assert "not all indexed runs are independently reproducible" in wb.inner_text().lower()


@pytest.mark.parametrize("lab", SPLUNK)
def test_prove_shows_exact_spl_hashes_metadata_provenance_limits_and_not_verified(page, root, lab):
    d = cp(lab); spec = d["spec"]; man = d["packet"]["manifest"]
    page.goto(root + lab); tab(page, "Prove")
    p = page.get_by_test_id("splunk-prove"); p.wait_for(); text = p.text_content()
    assert LABEL in text and "Verification status: NOT_VERIFIED" in text and spec["verification"] in text
    for s in d["packet"]["searches"]["searches"]:
        assert s["spl_sha256"] in text and s["spl_file"] in text and s["sid"] in text and s["submitted_at"] in text
        assert s["spl_text"].strip().split("\n")[0].strip() in text
    for f in d["files"]:
        assert f["sha256"] in text and f["file"] in text
    assert man["collection_sha256"] in text and man["splunk"]["version"] in text
    for x in man["limitations"] + [l["text"] for l in spec["limits"]]:
        assert x in text, x
    w = d["packet"]["matching"]["index_wide"]
    assert f"{w['runs_without_committed_pack']} do not" in text
    outside = text.replace(p.get_by_role("heading", name=spec["conclusion"]["title"]).locator("xpath=..").text_content(), "")
    assert "SPLUNK-VERIFIED" not in outside and "SPLUNK_VERIFIED" not in text


@pytest.mark.parametrize("lab", SPLUNK)
def test_conclusion_exercise_accepts_the_supported_claims_only(page, root, lab):
    q = ans(lab)["z1"]
    page.goto(root + lab); tab(page, "Prove"); p = page.get_by_test_id("splunk-prove"); p.wait_for()
    li = question(p, q)
    choose(li, q["candidates"])           # claiming everything must be wrong
    li.get_by_role("button", name=CHECK).click()
    r = li.locator(".rec-reveal").inner_text()
    assert "does not match" in r and all(a in r for a in q["answer"])
    page.goto(root + lab); tab(page, "Prove"); p = page.get_by_test_id("splunk-prove"); p.wait_for()
    li = question(p, q); choose(li, q["answer"]); li.get_by_role("button", name=CHECK).click()
    assert "that matches" in li.locator(".rec-reveal").inner_text()


def test_identity_prove_keeps_three_kinds_of_evidence_apart(page, root):
    d = cp(ID); three = d["packet"]["manifest"]["three_kinds_of_evidence"]
    page.goto(root + ID); tab(page, "Prove"); p = page.get_by_test_id("splunk-prove"); p.wait_for(); text = p.text_content()
    for h in ("Committed specimen evidence", "Current Splunk observations", "Historical documented expectations"):
        assert h in text
    assert "do not reproduce every current identity run" in text and "not part of the current observation" in text
    for x in three["historical_documented_expectations"]["statements"]:
        assert x["text"] in text
    for rid in three["current_splunk_observations"]["identity_runs_without_committed_pack"]:
        assert rid in text
    assert "not in the current index" in text


def test_bridge_prove_lists_external_events_and_unmatched_runs(page, root):
    d = cp(BR)
    page.goto(root + BR); tab(page, "Prove"); p = page.get_by_test_id("splunk-prove"); p.wait_for()
    ext = p.get_by_role("region", name=re.compile("^External events found in the index"))
    assert ext.locator("tbody tr").count() == len(d["packet"]["matching"]["external_events"]) == 7
    assert ext.get_by_text("none: not attributable to a committed file").count() == 2
    assert p.get_by_role("region", name=re.compile("^Runs behind this lab")).get_by_text("no committed pack").count() == 5


@pytest.mark.parametrize("lab", SPLUNK)
def test_keyboard_and_390px_layout(browser, root, lab):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    ok = "document.documentElement.scrollWidth <= window.innerWidth + 1"
    pg.goto(root + lab); assert pg.evaluate(ok), "learn"
    tab(pg, "Practice"); wb = pg.get_by_test_id("splunk-workbench"); wb.wait_for(); assert pg.evaluate(ok), "practice"
    st = cp(lab)["spec"]["stages"][0]; q = st["questions"][0]; li = question(wb, q)
    box = li.locator("input").first; box.focus(); pg.keyboard.press("Space"); assert box.is_checked()
    li.get_by_role("button", name=CHECK).focus(); pg.keyboard.press("Enter"); assert li.locator(".rec-reveal").count() == 1
    wb.get_by_role("button", name="Skip the predictions and show the recorded results").focus(); pg.keyboard.press("Enter")
    region = wb.get_by_role("region", name=re.compile("^Rows returned by")).first if searches(lab)[st["search"]]["rows"] else None
    assert pg.evaluate(ok), "after reveal"
    if region is not None:
        region.focus(); assert region.evaluate("e => e === document.activeElement"), "sideways-scrolling regions are keyboard-focusable"
    tab(pg, "Prove"); pr = pg.get_by_test_id("splunk-prove"); pr.wait_for()
    for sm in pr.locator("summary").all()[:4]:
        sm.click()
    assert pg.evaluate(ok), "prove"
    reg = pr.get_by_role("region").first; reg.focus(); assert reg.evaluate("e => e === document.activeElement")
    ctx.close()
