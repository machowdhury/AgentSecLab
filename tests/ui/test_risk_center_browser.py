"""Phase 12C in a real browser: the Risk Center.

The draft lives in this browser only; nothing is sent anywhere. SKIPPED, not passed, without Playwright and a Chromium (AGENTSEC_CHROMIUM). Only headless Chromium on the
local build is exercised; the deployed app has not been browser-tested.
"""
from __future__ import annotations

import itertools
import json
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import risk_model as R  # noqa: E402
from tests.risk_corpus import CASES, SEED, SEED_IDS, assessed  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_recorded_workbench_browser import watch  # noqa: E402
from tests.ui.test_study_browser import root as lab_root  # noqa: E402,F401

CANDS = {c["id"]: c for c in SEED["candidates"]}
FILE_LABEL = "Choose a risk assessment JSON file to import"


@pytest.fixture
def base(lab_root):
    return lab_root.replace("/lab/", "/risk")


def go(pg, base, path=""):
    pg.goto(base + path)
    pg.get_by_role("navigation", name="Risk Center").wait_for()
    pg.get_by_role("region", name="Your local draft").wait_for()


def text(pg):
    return pg.locator("main").inner_text()


def form(pg, name):
    return pg.get_by_role("form", name=name)


def judge(f, impact, like, why, save):
    f.get_by_label("Impact").select_option(impact) if impact else f.get_by_label("Impact").select_option("")
    f.get_by_label("Likelihood").select_option(like) if like else f.get_by_label("Likelihood").select_option("")
    f.get_by_label("Rationale").fill(why)
    f.get_by_role("button", name=save).click()


def inherent(pg, impact="HIGH", like="POSSIBLE", why="Recorded vulnerable runs executed; judged by the analyst."):
    judge(form(pg, "Inherent risk assessment"), impact, like, why, "Save inherent assessment")


def problems(pg):
    return {c for c in pg.locator(".rk-errors code").all_inner_texts() if re.fullmatch(r"[A-Z_]+", c)}


def import_doc(pg, d, name="draft.json"):
    pg.get_by_label(FILE_LABEL).set_input_files({"name": name, "mimeType": "application/json", "buffer": json.dumps(d).encode()})


def export_file(pg):
    with pg.expect_download() as dl:
        pg.get_by_role("button", name="Export JSON").click()
    return json.loads(Path(dl.value.path()).read_text(encoding="utf-8")), dl.value.suggested_filename


def test_overview_counts_describe_only_this_draft_with_denominators(page, base):
    seen = watch(page); go(page, base)
    t = text(page)
    assert "Every count below describes this local draft of 9 risks" in t and "not an enterprise total" in t
    n_find = sum(1 for c in CANDS.values() if c["derived"]["has_linked_findings"]); n_gap = sum(1 for c in CANDS.values() if (not c["derived"]["has_linked_evidence"]) or c["derived"]["controls_without_recorded_evidence"])
    cards = {h.inner_text(): h.locator("xpath=..").inner_text() for h in page.locator(".wk-card h3").all()}
    assert "9 of 9" in cards["Risks with no inherent assessment"] and f"{n_find} of 9" in cards["Risks with supporting evaluation findings"] and f"{n_gap} of 9" in cards["Risks with an evidence or control gap"]
    assert "0 of 9" in cards["Risks with a treatment chosen"] and "0 of 9" in cards["Assessments awaiting review"]
    assert not re.search(r"\d\s*%|compliance|score:|rating:", t, re.I) or "no overall score or compliance percentage" in t
    assert "LOCAL DRAFT" in page.get_by_role("region", name="Your local draft").inner_text() and "not approved" in page.get_by_role("region", name="Your local draft").inner_text()
    assert seen == []


def test_register_views_filter_search_and_empty_state(page, base):
    go(page, base, "/register")
    assert "Showing 9 of 9 risks in this draft." in text(page)
    nav = page.get_by_role("navigation", name="Register views")
    for label, path, n in (("Not assessed", "unassessed", 9), ("With evaluation findings", "with-findings", 4), ("Awaiting review", "awaiting-review", 0), ("Treatment status", "treatment", 9), ("Evidence and control gaps", "gaps", None)):
        nav.get_by_role("link", name=label).click(); page.wait_for_url(re.compile(f"/risk/register/{path}$"))
        assert nav.get_by_role("link", name=label).get_attribute("aria-current") == "page"
        if n is not None: assert f"Showing {n} of 9 risks in this draft." in text(page), label
    assert "No risk matches this view." in (page.goto(base + "/register/awaiting-review") and (page.get_by_role("navigation", name="Risk Center").wait_for() or text(page)))
    go(page, base, "/register"); page.get_by_label("Search").fill("memory")
    assert "Showing 1 of 9 risks in this draft." in text(page)
    page.get_by_label("Search").fill("zzz")
    assert "No risk matches this view." in text(page)
    page.goto(base + "/register/nope"); page.wait_for_selector("h1")
    assert "That page does not exist" in text(page)


def test_detail_separates_source_facts_derived_evidence_and_missing_values(page, base):
    go(page, base, "/TM-T04")
    c = CANDS["TM-T04"]; t = text(page)
    assert c["threat_scenario"] in t and c["documented_gap"] in t and c["documented_residual_risk"] in t
    facts = page.locator(".rk-facts")
    assert facts.get_by_text("SOURCE-BACKED FACT").count() >= 7 and "not an assessment" in t.lower()
    for a in c["assets"]:
        assert a["id"] in t and a["reason"] in t
    findings = page.get_by_role("region", name=re.compile("^Findings derived from the linked experiments"))
    assert findings.locator("tbody tr").count() == len(c["evidence"]["findings"]) == 4
    assert "NOT ASSESSED" in findings.inner_text() and "NOT_VERIFIED" in findings.inner_text()
    assert page.get_by_role("region", name=re.compile("^Framework relationships")).locator("tbody tr").count() == len(c["evidence"]["mappings"]) == 3
    assert "A recorded decision is not a residual-risk assessment." in t and "DERIVED" in t
    ctl = page.get_by_role("region", name=re.compile("^Controls named by the threat catalog"))
    assert "CTRL-MCP-001" in ctl.inner_text() and "decision event(s)" in ctl.inner_text() and "No recorded decision for this control" in ctl.inner_text()
    dl = page.locator("dl.wk-kv").first.inner_text()
    assert "NOT ASSESSED" in dl and "None recorded" in dl and "Draft" in dl
    assert "NOT ASSIGNED" in text(page)
    go(page, base, "/TM-T02")
    assert "No linked evidence." in text(page) and "No experiment in the EVAL Center tests this threat" in text(page)
    go(page, base, "/TM-T07")
    assert CANDS["TM-T07"]["inventory"]["owner_not_recorded"][0] in text(page) and "not an AI-BOM" in text(page)


def test_inherent_form_requires_human_input_and_looks_up_the_level(page, base):
    go(page, base, "/TM-T04")
    f = form(page, "Inherent risk assessment")
    assert "NOT ASSESSED" in f.inner_text()
    f.get_by_role("button", name="Save inherent assessment").click()
    assert problems(page) == {"IMPACT", "LIKELIHOOD", "RATIONALE"}
    f.get_by_label("Impact").select_option("HIGH")
    f.get_by_role("button", name="Save inherent assessment").click()
    assert problems(page) == {"LIKELIHOOD", "RATIONALE"}
    f.get_by_label("Likelihood").select_option("POSSIBLE")
    assert "HIGH" in f.inner_text().split("Level looked up from your entries:")[1].split("\n")[0] or "HIGH" in f.inner_text()
    f.get_by_role("button", name="Save inherent assessment").click()
    assert problems(page) == {"RATIONALE"}, "a judgment without a rationale is not saved"
    go(page, base, "/register")
    assert page.get_by_role("row").filter(has_text="TM-T04").inner_text().count("NOT ASSESSED") == 2, "nothing was saved"
    go(page, base, "/TM-T04")
    inherent(page)
    assert "saved to this browser" in text(page).lower() and "entered by you in this browser; not verified" in text(page)
    go(page, base, "/register")
    assert "HIGH" in page.get_by_role("row").filter(has_text="TM-T04").inner_text()


def test_every_matrix_cell_in_the_form_matches_the_methodology(page, base):
    go(page, base, "/TM-T04")
    f = form(page, "Inherent risk assessment")
    for i, l in itertools.product(R.IMPACT, R.LIKELIHOOD):
        f.get_by_label("Impact").select_option(i); f.get_by_label("Likelihood").select_option(l)
        p = f.locator("p", has_text="Level looked up from your entries:").inner_text()
        assert R.level(i, l) in p, (i, l, p)
    f.get_by_label("Impact").select_option("")
    assert "NOT ASSESSED" in f.locator("p", has_text="Level looked up from your entries:").inner_text()


def test_residual_is_gated_human_and_never_set_by_control_evidence(page, base):
    go(page, base, "/TM-T04")
    r = form(page, "Residual risk assessment")
    assert r.get_by_label("Impact").is_disabled() and r.get_by_role("button", name="Save residual assessment").is_disabled() and "Save an inherent assessment first" in text(page)
    inherent(page, "HIGH", "POSSIBLE")
    go(page, base, "/TM-T04")
    r = form(page, "Residual risk assessment")
    assert r.get_by_label("Impact").is_enabled()
    r.get_by_label("CTRL-MCP-001").check()
    assert "NOT ASSESSED" in r.locator("p", has_text="Level looked up").inner_text(), "ticking a control sets no level"
    r.get_by_role("button", name="Save residual assessment").click()
    assert problems(page) == {"IMPACT", "LIKELIHOOD", "RATIONALE"}
    judge(r, "HIGH", "UNLIKELY", "Defended retests denied the request in the recorded runs; this is my judgment.", "Save residual assessment")
    go(page, base, "/register")
    row = page.get_by_role("row").filter(has_text="TM-T04").inner_text()
    assert "MEDIUM" in row and "HIGH" in row
    go(page, base, "/TM-T01")
    assert page.get_by_role("form", name="Residual risk assessment").get_by_label("Impact").is_disabled()
    go(page, base, "/TM-T01"); inherent(page, "LOW", "UNLIKELY", "Low on this analyst's reading.")
    go(page, base, "/TM-T01")
    r = form(page, "Residual risk assessment")
    r.get_by_label("Impact").select_option("HIGH"); r.get_by_label("Likelihood").select_option("POSSIBLE")
    assert "higher than the inherent level" in r.inner_text(), "a residual level above the inherent level is flagged, not blocked"
    judge(r, "HIGH", "POSSIBLE", "Raised on purpose to see the warning.", "Save residual assessment")
    assert "HIGH" in page.locator("dl.wk-kv").first.inner_text()


def test_treatment_owner_actions_and_approval_are_recorded_never_assumed(page, base):
    go(page, base, "/TM-T04")
    t = form(page, "Risk owner and treatment")
    assert "Owner: NOT ASSIGNED" in text(page)
    t.get_by_role("combobox", name=re.compile("^Treatment")).select_option("ACCEPT"); t.get_by_label("Risk owner").fill("Head of platform"); t.get_by_role("button", name="Save treatment").click()
    assert "Treatment saved to this browser." in text(page) or "kept in memory" in text(page) and "NO APPROVAL RECORDED" in text(page) and "approval recorded by" not in text(page)
    ap = form(page, "Acceptance approval record")
    ap.get_by_role("button", name="Record acceptance approval").click()
    assert "An approval record needs who, their role and a note." in text(page)
    ap.get_by_label("Approved by").fill("A. Approver"); ap.get_by_label("Their role").fill("Risk committee chair"); ap.get_by_label("Note").fill("Accepted for the workshop lab only.")
    ap.get_by_role("button", name="Record acceptance approval").click()
    t = text(page)
    assert "approval recorded by A. Approver (Risk committee chair)" in t and "entered locally, not verified" in t
    go(page, base, "/register/treatment")
    assert "Of 1 chosen to accept, 1 have an approval record (entered locally, not verified)." in text(page)
    go(page, base, "/TM-T04")
    t = form(page, "Risk owner and treatment"); t.get_by_role("combobox", name=re.compile("^Treatment")).select_option("MITIGATE"); t.get_by_role("button", name="Save treatment").click()
    assert "approval recorded by" not in text(page) and page.get_by_role("form", name="Acceptance approval record").count() == 0, "an approval belongs only to an ACCEPT treatment"
    na = form(page, "Propose an action")
    na.get_by_role("button", name="Add action").click()
    assert "Describe the action." in text(page)
    na.get_by_label("New action").fill("Add row-level authorization checks"); na.get_by_role("button", name="Add action").click()
    row = page.locator(".rk-action").first
    assert "A1: Add row-level authorization checks" in row.inner_text()
    row.get_by_label("Status").select_option("COMPLETED")
    row.get_by_role("button", name="Save action A1").click()
    assert "A completed action needs the evidence it rests on." in text(page)
    row.get_by_label("Evidence the completion rests on").fill("Change ticket 123 merged.")
    row.get_by_role("button", name="Save action A1").click()
    assert "Completion claimed. Evidence note: Change ticket 123 merged.. Not verified by this page." in text(page)
    assert "approved" not in page.locator("#r-treatment").inner_text().lower().replace("approved by", "").replace("not approved", "")


def test_review_workflow_needs_an_assessment_and_names_the_reviewer(page, base):
    go(page, base, "/TM-T04")
    assert page.get_by_role("button", name="Mark as awaiting review").is_disabled() and "Save an inherent assessment before asking for review." in text(page)
    inherent(page)
    go(page, base, "/TM-T04")
    page.get_by_role("button", name="Mark as awaiting review").click()
    assert "AWAITING REVIEW" in text(page)
    go(page, base, "/register/awaiting-review")
    assert "Showing 1 of 9 risks in this draft." in text(page)
    go(page, base, "/TM-T04")
    rv = form(page, "Record a review")
    rv.get_by_role("button", name="Record the review").click()
    assert "A recorded review needs the reviewer's name and a note." in text(page)
    rv.get_by_label("Reviewer").fill("R. Reviewer"); rv.get_by_label("Review note").fill("Read the evidence and the rationale.")
    rv.get_by_role("button", name="Record the review").click()
    t = text(page)
    assert "review recorded by r. reviewer" in t.lower() and "entered locally; not verified." in t.lower()
    hist = page.get_by_role("region", name=re.compile("^Review and change history")).inner_text()
    assert "Inherent assessment saved" in hist and "Marked awaiting review" in hist and "Review recorded" in hist
    page.get_by_role("button", name="Return to draft").click()
    assert "DRAFT" in text(page).upper() and page.get_by_role("form", name="Record a review").count() == 0


def test_draft_persists_across_reload_and_reset_is_predictable(page, base):
    go(page, base, "/TM-T04"); inherent(page)
    page.reload(); page.get_by_role("region", name="Your local draft").wait_for()
    assert "HIGH" in page.locator("dl.wk-kv").first.inner_text()
    bar = page.get_by_role("region", name="Your local draft")
    bar.get_by_role("button", name="Reset draft").click()
    assert bar.get_by_role("group", name="Confirm reset").is_visible()
    bar.get_by_role("button", name="Cancel").click()
    assert "HIGH" in page.locator("dl.wk-kv").first.inner_text(), "cancel keeps the draft"
    bar.get_by_role("button", name="Reset draft").click(); bar.get_by_role("button", name="Yes, reset").click()
    assert "reset to the source-backed starting point" in bar.inner_text() and "NOT ASSESSED" in page.locator("dl.wk-kv").first.inner_text()
    page.reload(); page.get_by_role("region", name="Your local draft").wait_for()
    assert "NOT ASSESSED" in page.locator("dl.wk-kv").first.inner_text(), "the reset persists"


def test_when_the_browser_will_not_store_a_draft_it_says_so_and_still_works(browser, base):
    ctx = browser.new_context(); pg = ctx.new_page()
    pg.add_init_script("Object.defineProperty(window, 'localStorage', { get() { throw new Error('blocked'); } });")
    go(pg, base, "/TM-T04")
    assert "kept in memory only" in pg.get_by_role("region", name="Your local draft").inner_text()
    inherent(pg)
    bar = pg.get_by_role("region", name="Your local draft").inner_text()
    assert "kept in memory" in bar and "will be lost on reload" in bar and "HIGH" in pg.locator("dl.wk-kv").first.inner_text()
    ctx.close()


def test_export_is_valid_checksummed_and_round_trips(page, base):
    go(page, base, "/TM-T04"); inherent(page)
    go(page, base, "/TM-T04")
    judge(form(page, "Residual risk assessment"), "MODERATE", "UNLIKELY", "Judged by the analyst with the named control.", "Save residual assessment")
    d, name = export_file(page)
    assert name == "risk-assessment-draft.json" and d["schema"] == R.SCHEMA and d["status"] == R.STATUS and d["seed_sha256"] == SEED["canonical_sha256"]
    assert R.validate_assessment(d, SEED_IDS) == [], R.validate_assessment(d, SEED_IDS)
    assert d["integrity"]["risks_sha256"] == R.risks_sha256(d["risks"]), "the browser's SHA-256 equals Python's"
    r = next(x for x in d["risks"] if x["id"] == "TM-T04")
    assert (r["assessment"]["inherent"]["impact"], r["assessment"]["residual"]["impact"], r["derived"]) == ("HIGH", "MODERATE", {"inherent_level": "HIGH", "residual_level": "LOW"})
    assert len(d["risks"]) == 9 and "approved" not in json.dumps(d).lower().replace("local_draft_not_approved", "")
    bar = page.get_by_role("region", name="Your local draft")
    bar.get_by_role("button", name="Reset draft").click(); bar.get_by_role("button", name="Yes, reset").click()
    import_doc(page, d)
    bar.get_by_text("Imported 9 risks (9 source-backed, 0 custom).").wait_for()
    go(page, base, "/register")
    row = page.get_by_role("row").filter(has_text="TM-T04").inner_text()
    assert "HIGH" in row and "LOW" in row
    d2, _ = export_file(page)
    assert d2["risks"] == d["risks"] and d2["integrity"] == d["integrity"], "round trip is exact"


def test_import_rejects_every_invalid_document_with_the_same_codes_as_python_and_changes_nothing(page, base):
    go(page, base, "/TM-T04"); inherent(page)
    before, _ = export_file(page)
    bar = page.get_by_role("region", name="Your local draft")
    for name, d in CASES:
        want = {c for c, _, _ in R.validate_assessment(d, SEED_IDS)}
        import_doc(page, d, name + ".json")
        if want:
            page.locator(".rk-errors").wait_for(); assert "not imported and your draft is unchanged" in bar.inner_text(), name
            assert problems(page) == want, (name, problems(page), want)
        else:
            page.get_by_text("Imported ").first.wait_for(); assert problems(page) == set(), name
            # put the original draft back so the next cases start from the same state
            import_doc(page, before); page.get_by_text("Imported ").first.wait_for()
    import_doc(page, before); page.get_by_text("Imported ").first.wait_for()
    after, _ = export_file(page)
    assert after["risks"] == before["risks"]


def test_import_of_unreadable_files_and_stale_evidence(page, base):
    go(page, base, "/register")
    page.get_by_label(FILE_LABEL).set_input_files({"name": "x.json", "mimeType": "application/json", "buffer": b"{ not json"})
    page.locator(".rk-errors").wait_for()
    assert "JSON" in {c for c in page.locator(".rk-errors code").all_inner_texts()} and "is not valid JSON" in text(page)
    d = assessed()
    from tests.risk_corpus import doc
    stale = doc(d, seed_sha256="a" * 64)
    import_doc(page, stale)
    page.get_by_text("Imported ").first.wait_for()
    assert "The source evidence changed after this file was exported" in text(page)
    go(page, base, "/register")
    assert "custom-1" in text(page).lower() and "plugin supply risk" in text(page).lower()


def test_custom_risk_is_labelled_unsourced_and_can_be_deleted(page, base):
    go(page, base, "/register")
    page.get_by_role("link", name="Add a risk of your own").click(); page.wait_for_url(re.compile(r"/risk/new$"))
    f = form(page, "Add a risk of your own")
    f.get_by_role("button", name="Create the risk").click()
    assert "A risk needs a title." in text(page)
    f.get_by_label("Title").fill("Third-party plugin changes behaviour"); f.get_by_label("Threat scenario").fill("An update alters tool output."); f.get_by_role("button", name="Create the risk").click()
    page.wait_for_url(re.compile(r"/risk/custom-1$"))
    t = text(page)
    assert "YOUR OWN RISK, NO SOURCE" in t and "No source backs this risk." in t and "ANALYST JUDGMENT" in t.upper().replace("ANALYST", "ANALYST")
    assert page.locator("#r-evidence").count() == 0 and page.locator("#r-controls").count() == 0
    go(page, base, "/register")
    assert "Showing 10 of 10 risks in this draft." in text(page) and "0 (no source)" in text(page)
    go(page, base, "/register/gaps")
    assert "custom-1" in text(page).lower()
    go(page, base, "/custom-1"); page.get_by_role("button", name="Delete this risk").click()
    page.wait_for_url(re.compile(r"/register$")); assert "Showing 9 of 9 risks in this draft." in text(page)
    go(page, base, "/nope-risk"); assert "There is no risk called nope-risk" in text(page)


def test_method_page_documents_the_qualitative_method_exactly(page, base):
    go(page, base, "/method")
    m = SEED["methodology"]
    t = text(page)
    assert m["statement"] in t and m["source_rule"]["text"] in t
    for x in m["impact"] + m["likelihood"]:
        assert x["label"].lower() in t.lower() and x["definition"] in t
    mx = page.get_by_role("region", name=re.compile("^Risk level for each impact and likelihood"))
    for i in m["impact"]:
        row = mx.locator("tbody tr").filter(has_text=i["label"]).first.inner_text().upper()
        for l, lv in zip(m["likelihood"], [m["matrix"][i["id"]][l["id"]] for l in m["likelihood"]]):
            assert lv in row
    for r in m["rules"]:
        assert r in t
    assert not re.search(r"\d\s*%", t)


def test_loading_failed_chunk_and_unknown_pages(page, base):
    import time
    page.route(re.compile(r"RiskCenter-.*\.js"), lambda r: (time.sleep(1.0), r.continue_()))
    page.goto(base, wait_until="commit")
    page.get_by_role("status").filter(has_text="Loading the Risk Center").wait_for()
    page.get_by_role("navigation", name="Risk Center").wait_for()
    page.unroute(re.compile(r"RiskCenter-.*\.js"))
    page.route(re.compile(r"seed-.*\.js"), lambda r: r.abort())
    page.goto(base + "/TM-T04")
    alert = page.get_by_role("alert"); alert.wait_for()
    assert "could not be loaded" in alert.inner_text() and "your draft is untouched" in alert.inner_text()
    page.unroute(re.compile(r"seed-.*\.js")); alert.get_by_role("button", name="Reload the page").click()
    page.get_by_role("region", name="Your local draft").wait_for()


def test_nothing_posts_or_calls_the_backend_and_code_loads_only_on_demand(page, base):
    reqs = []
    page.on("request", lambda r: reqs.append((r.method, r.url)))
    page.goto(base.replace("/risk", "")); page.wait_for_selector("h1")
    assert not any("RiskCenter" in u or "/seed-" in u for _, u in reqs)
    seen = watch(page)
    for p in ("", "/register", "/TM-T04", "/method", "/new"):
        go(page, base, p)
    assert any("RiskCenter" in u for _, u in reqs) and any("/seed-" in u for _, u in reqs) and all(m == "GET" for m, _ in reqs) and seen == []


def test_keyboard_completes_an_assessment_without_a_mouse(page, base):
    go(page, base, "/TM-T04")
    f = form(page, "Inherent risk assessment")
    f.get_by_label("Impact").focus(); page.keyboard.type("H")       # type-ahead on a focused native select
    f.get_by_label("Likelihood").focus(); page.keyboard.type("P")
    assert f.get_by_label("Impact").input_value() == "HIGH" and f.get_by_label("Likelihood").input_value() == "POSSIBLE"
    f.get_by_label("Rationale").focus(); page.keyboard.type("Typed with the keyboard only.")
    b = f.get_by_role("button", name="Save inherent assessment"); b.focus(); page.keyboard.press("Enter")
    assert "saved to this browser" in text(page).lower()
    page.get_by_role("navigation", name="Risk Center").get_by_role("link", name="Register").focus(); page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/register$"))
    page.get_by_role("link", name=re.compile("^TM-T04")).focus(); page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/TM-T04$"))


@pytest.mark.parametrize("path", ["", "/register", "/register/treatment", "/TM-T04", "/TM-T02", "/method", "/new"])
def test_390px_layout_has_no_sideways_page_scroll(browser, base, path):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    go(pg, base, path)
    for sm in pg.locator("main summary").all()[:6]:
        sm.click()
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), path
    for r in pg.locator("main [role=region][tabindex='0']").all()[:2]:
        r.focus(); assert r.evaluate("e => e === document.activeElement")
    ctx.close()


def test_390px_layout_with_saved_state_and_error_messages(browser, base):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    go(pg, base, "/TM-T04")
    form(pg, "Inherent risk assessment").get_by_role("button", name="Save inherent assessment").click()
    inherent(pg); go(pg, base, "/TM-T04")
    judge(form(pg, "Residual risk assessment"), "HIGH", "LIKELY", "Raised to show the warning on a narrow screen.", "Save residual assessment")
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    import_doc(pg, dict(CASES)["integrity-mismatch"])
    pg.locator(".rk-errors").wait_for()
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    ctx.close()


def test_existing_navigation_eval_center_and_assurance_are_unchanged(page, base):
    page.goto(base.replace("/risk", "")); page.wait_for_selector("h1")
    nav = page.get_by_role("navigation", name="Primary navigation")
    for name in ("Home", "Your Path", "Curriculum Explorer", "AI & Agent Foundations", "Loan Desk Mission", "MCP Tool Authorization", "Mastery", "Security Assurance", "EVAL Center", "Risk Center"):
        assert nav.get_by_role("link", name=name).count() == 1, name
    page.goto(base.replace("/risk", "/evals")); page.get_by_role("navigation", name="Evaluation Center").wait_for()
    page.goto(base.replace("/risk", "/assurance/study")); page.wait_for_selector("h1")
    assert page.get_by_role("link", name="Start the workshop").count() == 1
    go(page, base)
    assert nav.get_by_role("link", name="Risk Center").get_attribute("aria-current") == "page"
