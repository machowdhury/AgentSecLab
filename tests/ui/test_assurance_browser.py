"""Increment 12A in a real browser: the Security Assurance hub and the six-step workshop journey.

Nothing is searched, launched or sent anywhere; the journey is one on-demand evidence file. SKIPPED, not passed, without Playwright and a Chromium (AGENTSEC_CHROMIUM).
Only headless Chromium on the local build is exercised. The deployed Academy has not been browser-tested.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_recorded_workbench_browser import watch  # noqa: E402
from tests.ui.test_study_browser import root as lab_root  # noqa: E402,F401

ROOT = Path(__file__).resolve().parents[2]
J = json.loads((ROOT / "academy-ui/src/content/assurance/mcp-unauthorized-scope.json").read_text(encoding="utf-8"))
STEPS = [s["id"] for s in J["steps"]]
TITLE = {"learn": "Learn", "practice": "Practice", "evaluate": "Evaluate", "risk": "Assess Risk", "controls": "Map Controls", "prove": "Prove"}
CHECK = "Check against the sources"


@pytest.fixture
def base(lab_root):
    return lab_root.replace("/lab/", "/assurance")      # the study journey (recorded evidence) lives under /assurance; its hub is /assurance/study, /assurance itself is the live overview


def go(pg, base, step=None):
    pg.goto(base + (f"/mcp-unauthorized-scope/{step}" if step else ""))
    pg.wait_for_selector("h1")


def progress(pg):
    return int(pg.get_by_role("progressbar", name="Workshop progress").get_attribute("aria-valuenow"))


def answer(pg, prompt_part, options, check=True):
    li = pg.locator(".rec-q", has_text=prompt_part)
    for o in options:
        li.get_by_label(o, exact=True).check()
    if check:
        li.get_by_role("button", name=CHECK).click()
    return li


def kind_label(o):
    return {"runtime_decision": "A recorded control decision from a committed pack", "provenance_check": "A comparison of a Splunk copy with a committed pack", "evaluation_result": "A recorded external model evaluation"}[o["kind"]]


def test_hub_explains_the_evidence_labels_and_marks_unbuilt_tracks_as_not_implemented(page, base):
    seen = watch(page); go(page, base + "/study")
    assert page.get_by_role("heading", level=1).inner_text().startswith("From a security result")
    nav = page.get_by_role("navigation", name="Primary navigation").get_by_role("link", name="Security Assurance")
    assert nav.get_attribute("aria-current") == "page"                      # the study journey lives under /assurance, so the sidebar entry stays active
    text = page.locator("main").inner_text()
    for w in ("LIVE", "RECORDED", "SIMULATED", "DOCUMENTED", "NOT_VERIFIED", "Nothing is run, searched or scored"):
        assert w in text, w
    cards = page.locator(".wk-card--idle")
    assert cards.count() == 3 and all("NOT IMPLEMENTED" in c.inner_text() for c in cards.all())
    assert all(c.locator("a, button").count() == 0 for c in cards.all()), "an unbuilt track is never a control"
    assert not re.search(r"\d\s*%", text)
    assert seen == []


def test_start_opens_step_one_and_the_workshop_runs_through_all_six_steps(page, base):
    seen = watch(page); go(page, base + "/study")
    page.get_by_role("link", name="Start the workshop").click()
    page.wait_for_url(re.compile(r"/mcp-unauthorized-scope/learn$"))
    for i, sid in enumerate(STEPS):
        page.wait_for_selector(".wk-steps")
        assert page.locator("main strong", has_text=f"Step {i + 1} of 6: {TITLE[sid]}").count() == 1
        cur = page.get_by_role("navigation", name="Workshop steps").locator("[aria-current=step]")
        assert cur.count() == 1 and TITLE[sid] in cur.inner_text()
        assert J["steps"][i]["instruction"] in page.get_by_role("region", name="What to do here").inner_text()
        nxt = page.locator(".wk-actions a").last
        assert nxt.inner_text().strip() == J["steps"][i]["next_action"]
        nxt.click()
    page.wait_for_url(re.compile(r"/learn/assurance/study$"))      # the last action returns to the workshop home: no dead end
    assert seen == []


def test_every_step_has_a_back_and_a_next_action_and_unknown_urls_are_not_found(page, base):
    for sid in STEPS:
        go(page, base, sid)
        acts = page.locator(".wk-actions a")
        assert acts.count() == 2 and all(a.get_attribute("href") for a in acts.all())
    page.goto(base + "/mcp-unauthorized-scope/nope"); page.wait_for_selector("h1")
    assert "That page does not exist" in page.locator("main").inner_text()


def test_evaluate_is_gated_by_the_exercise_and_progress_survives_reload_until_reset(page, base):
    go(page, base, "evaluate")
    start = progress(page)
    wrong_first = [o for o in J["observations"]][0]
    others = [kind_label(o) for o in J["observations"] if kind_label(o) != kind_label(wrong_first)]
    li = answer(page, f"“{wrong_first['title']}”" if False else wrong_first["title"], [others[0]])
    assert "does not match" in li.locator(".rec-reveal").inner_text() and kind_label(wrong_first) in li.locator(".rec-reveal").inner_text()
    for o in J["observations"][1:]:
        answer(page, o["title"], [kind_label(o)])
    assert progress(page) == start + 1, "only checking every exercise completes the step"
    page.reload(); page.wait_for_selector(".wk-steps")
    assert page.locator(".rec-reveal").count() == len(J["observations"]), "checked answers persist in this browser"
    page.get_by_role("button", name="Reset workshop").click()
    assert page.url.endswith("/evaluate"), "reset keeps your place"
    assert progress(page) == 0 and "Workshop progress cleared" in page.locator("main").inner_text()
    assert page.locator(".rec-reveal").count() == 0 and page.locator(".rec-q input").first.is_enabled()
    page.reload(); page.wait_for_selector(".wk-steps")
    assert page.locator(".rec-reveal").count() == 0, "the cleared state persists"


def test_risk_step_never_scores_and_reveals_assessments_only_after_checking(page, base):
    go(page, base, "risk")
    t = page.locator("main").inner_text()
    r = J["risks"][0]
    assert r["statement"] in t and "AUTHORED STATEMENT, NOT EVIDENCE" in t and r["gap"] in t and r["residual_risk"] in t
    assert t.count("NOT ASSESSED") >= 2 and "NOT ASSIGNED" in t
    assert not re.search(r"\d\s*%|score|likelihood:\s*(low|medium|high)", t, re.I)
    assert page.get_by_role("region", name=re.compile("^Assessments and their basis")).count() == 0
    supported = [a["statement"] for a in J["assessments"] if a["status"] == "SUPPORTED"]
    unsupported = next(a["statement"] for a in J["assessments"] if a["status"] != "SUPPORTED")
    li = answer(page, "Which statements does the recorded evidence support?", [unsupported])
    assert "does not match" in li.locator(".rec-reveal").inner_text()
    page.reload(); page.wait_for_selector(".wk-steps")
    li = page.locator(".rec-q", has_text="Which statements")
    assert li.locator("input").first.is_disabled(), "a checked answer stays checked"
    tbl = page.get_by_role("region", name=re.compile("^Assessments and their basis"))
    rows = tbl.locator("tbody tr")
    assert rows.count() == len(J["assessments"])
    for a in J["assessments"]:
        row = [x for x in rows.all() if a["statement"].lower() in x.locator("th").inner_text().lower()][0]
        assert a["status"].replace("_", " ").lower() in row.inner_text().lower() and a["basis"] in row.inner_text()


def test_correct_risk_answer_matches(page, base):
    go(page, base, "risk")
    supported = [a["statement"] for a in J["assessments"] if a["status"] == "SUPPORTED"]
    li = answer(page, "Which statements does the recorded evidence support?", supported)
    assert "that matches" in li.locator(".rec-reveal").inner_text()


def test_controls_step_shows_exact_mappings_four_separate_facts_and_no_compliance_claim(page, base):
    go(page, base, "controls")
    t = page.locator("main").inner_text()
    tbl = page.get_by_role("region", name=re.compile("^Framework relationships"))
    rows = tbl.locator("tbody tr")
    assert rows.count() == len(J["mappings"]) == 3
    for m in J["mappings"]:
        row = [x for x in rows.all() if m["id"] in x.inner_text()][0]
        rt = row.inner_text().lower()
        assert m["framework"].lower() in rt and m["name"].lower() in rt and m["relationship"].lower() in rt and m["rationale"].lower() in rt
        assert m["verification_status"].replace("_", " ").lower() in rt
    assert "Compliance assertions: none." in t and J["compliance_statement"] in t
    for c in J["coverage"]:
        assert c["notion"].lower() in t.lower() and c["statement"] in t
    assert J["coverage_note"] in t and not re.search(r"\d\s*%", t)
    for c in J["controls"]:
        assert c["id"] in t
    mm = J["mapping_meaning"]
    li = answer(page, mm["question"], mm["answer"])
    assert "that matches" in li.locator(".rec-reveal").inner_text() and mm["quote"]["text"] in li.locator(".rec-reveal").inner_text()


def test_prove_step_lists_hashes_verification_and_open_work_without_claiming_verification(page, base):
    go(page, base, "prove")
    t = page.locator("main").inner_text()
    low = t.lower()
    assert "Verification status: NOT_VERIFIED" in t
    for allowed in ("nothing here is claimed to be splunk-verified", "before calling them splunk-verified"):
        low = low.replace(allowed, "")
    assert "splunk-verified" not in low
    files = {s["file"]: s["sha256"] for o in J["observations"] for s in o["sources"]}
    tbl = page.get_by_role("region", name=re.compile("^Source files and SHA-256"))
    assert tbl.locator("tbody tr").count() == len(files)
    for f, h in files.items():
        assert f.lower() in tbl.inner_text().lower() and h in tbl.inner_text()
    rem = page.get_by_role("region", name=re.compile("^Remediation actions")).locator("tbody tr")
    assert rem.count() == len(J["remediation"]) == 3
    assert all("NOT ASSIGNED" in r.inner_text() and "NOT STARTED" in r.inner_text() for r in rem.all())
    for x in J["remediation"]:
        assert x["basis_quote"]["text"] in t
    sup = sum(1 for a in J["assessments"] if a["status"] == "SUPPORTED")
    assert f"{sup} supported, {len(J['assessments']) - sup} not supported" in t.lower() and "compliance assertions" in t.lower()
    assert not re.search(r"\d\s*%", t)


def test_practice_step_reuses_the_existing_lab_and_the_self_report_is_labelled(page, base):
    go(page, base, "practice")
    link = page.get_by_role("link", name=f"Open the {J['lab_id']} lab")
    assert link.get_attribute("href").endswith(f"/learn/lab/{J['lab_id']}")
    box = page.get_by_label("I completed the Practice workbench")
    assert "self-reported; it is not evidence" in page.locator("main").inner_text() and not box.is_checked()
    box.check()
    assert "Marked complete on this browser only" in page.locator("main").inner_text()
    page.reload(); page.wait_for_selector(".wk-steps")
    assert page.get_by_label("I completed the Practice workbench").is_checked()
    link.click(); page.wait_for_url(re.compile(f"/learn/lab/{J['lab_id']}$"))
    assert page.get_by_role("tab", name=re.compile("Practice")).count() == 1


def test_loading_error_and_retry_states(page, base):
    gate = {"fail": True}
    def handler(route):
        route.abort() if gate["fail"] else route.continue_()
    page.route(re.compile(r"mcp-unauthorized-scope-.*\.js"), handler)
    page.goto(base + "/mcp-unauthorized-scope/learn")
    alert = page.get_by_role("alert"); alert.wait_for()
    assert "could not be loaded" in alert.inner_text() and "Nothing was changed" in alert.inner_text()
    assert alert.get_by_role("link", name="Back to the workshop home").get_attribute("href").endswith("/learn/assurance/study")
    gate["fail"] = False
    alert.get_by_role("button", name="Reload the page").click()
    page.wait_for_selector(".wk-steps")
    assert page.locator("main strong", has_text="Step 1 of 6").count() == 1


def test_slow_load_shows_a_loading_status_first(page, base):
    import time
    page.route(re.compile(r"mcp-unauthorized-scope-.*\.js"), lambda r: (time.sleep(1.2), r.continue_()))
    page.goto(base + "/mcp-unauthorized-scope/learn")
    assert page.get_by_role("status").filter(has_text="Loading the recorded evidence").count() == 1
    page.wait_for_selector(".wk-steps")


def test_no_step_calls_the_backend_or_posts_anything(page, base):
    posts = []
    page.on("request", lambda r: posts.append(r.url) if r.method != "GET" else None)
    seen = watch(page)
    for sid in STEPS:
        go(page, base, sid)
    assert posts == [] and seen == []


@pytest.mark.parametrize("step", ["hub"] + STEPS)
def test_390px_layout_has_no_sideways_page_scroll_and_regions_are_keyboard_focusable(browser, base, step):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    pg.goto(base if step == "hub" else base + f"/mcp-unauthorized-scope/{step}"); pg.wait_for_selector("h1")
    for sm in pg.locator("main summary").all()[:6]:
        sm.click()
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), step
    for r in pg.locator("main [role=region][tabindex='0']").all()[:2]:
        r.focus(); assert r.evaluate("e => e === document.activeElement")
    ctx.close()


def test_keyboard_drives_the_step_bar_and_next_action(page, base):
    go(page, base, "learn")
    page.get_by_role("navigation", name="Workshop steps").get_by_role("link", name=re.compile("Evaluate")).focus()
    page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/evaluate$"))
    page.locator(".wk-actions a").last.focus(); page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/risk$"))
    li = page.locator(".rec-q").first
    li.locator("input").first.focus(); page.keyboard.press("Space"); assert li.locator("input").first.is_checked()
    li.get_by_role("button", name=CHECK).focus(); page.keyboard.press("Enter"); assert li.locator(".rec-reveal").count() == 1


def test_existing_academy_pages_and_navigation_are_unchanged(page, base):
    page.goto(base.replace("/assurance", "")); page.wait_for_selector("h1")
    nav = page.get_by_role("navigation", name="Primary navigation")
    for name in ("Home", "Your Path", "Curriculum Explorer", "AI & Agent Foundations", "Loan Desk Mission", "MCP Tool Authorization", "Mastery", "Security Assurance"):
        assert nav.get_by_role("link", name=name).count() == 1, name
    page.goto(base.replace("/assurance", "/lab/LAB-MCP-003")); page.wait_for_selector("h1")
    assert page.get_by_role("tab", name=re.compile("Practice")).count() == 1
