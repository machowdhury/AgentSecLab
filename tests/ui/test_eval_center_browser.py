"""Phase 12B in a real browser: the EVAL Center.

Everything shown is read from on-demand evidence files; the report is built in the page and downloaded as a file. Nothing is searched, launched or sent anywhere.
SKIPPED, not passed, without Playwright and a Chromium (AGENTSEC_CHROMIUM). Only headless Chromium on the local build is exercised; the deployed app has not been browser-tested.
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
OUT = ROOT / "academy-ui/src/content/evals"
IDX = json.loads((OUT / "index.json").read_text(encoding="utf-8"))
EXPS = {e["id"]: json.loads((OUT / f"exp-{e['id']}.json").read_text(encoding="utf-8")) for e in IDX["experiments"]}
VIEWS = ["", "/catalog", "/results/mcp-003", "/compare/mcp-003", "/findings", "/export"]
TAB = {"Overview": "", "Catalog": "/catalog", "Results": "/results", "Compare": "/compare", "Findings": "/findings", "Export": "/export"}


@pytest.fixture
def base(lab_root):
    return lab_root.replace("/lab/", "/evals")


def go(pg, base, path=""):
    pg.goto(base + path)
    pg.get_by_role("navigation", name="Evaluation Center").wait_for()


def main_text(pg):
    return pg.locator("main").inner_text()


def test_overview_shows_only_derived_counts_with_denominators_and_scope(page, base):
    seen = watch(page); go(page, base)
    t = main_text(page)
    cards = page.locator(".wk-card", has=page.locator(".ev-figure"))
    assert cards.count() == len(IDX["metrics"]) == 8
    for m in IDX["metrics"]:
        card = cards.filter(has_text=m["label"])
        assert f"{m['numerator']} of {m['denominator']}" in card.inner_text() and m["scope"] in card.inner_text()
        card.locator("summary").click()
        assert m["derivation"] in card.inner_text()
    assert not re.search(r"\d\s*%|success rate:|risk score:|score:\s*\d", t, re.I)
    rows = page.get_by_role("region", name=re.compile("^Every experiment")).locator("tbody tr")
    assert rows.count() == len(IDX["experiments"]) == 11
    for e in IDX["experiments"]:
        r = rows.filter(has_text=e["title"])
        assert f"{e['verified']} of {e['cases']} verified".lower() in r.inner_text().lower()
    assert "Prompt injection against the loan pipeline" in page.locator("#ov-findings").locator("xpath=..").inner_text() and "does not name the observed decision" in t
    assert str(len(IDX["gaps"]["not_implemented"])) + " capabilities" in t and "31 test cases" in t
    for lab in IDX["gaps"]["evidence_exists_but_not_included"]:
        assert lab in t
    assert seen == []


def test_tabs_navigate_mark_the_current_view_and_the_sidebar_item_is_active(page, base):
    go(page, base)
    nav = page.get_by_role("navigation", name="Evaluation Center")
    for name, suffix in TAB.items():
        nav.get_by_role("link", name=name).click()
        page.wait_for_url(re.compile(re.escape("/learn/evals" + suffix) + r"$"))
        assert nav.get_by_role("link", name=name).get_attribute("aria-current") == "page" and nav.locator("[aria-current=page]").count() == 1
        assert page.get_by_role("navigation", name="Primary navigation").get_by_role("link", name="EVAL Center").get_attribute("aria-current") == "page"
    page.goto(base + "/nope"); page.wait_for_selector("h1")
    assert "That page does not exist" in main_text(page)


def test_catalog_filters_by_status_and_shows_sources_for_every_gap(page, base):
    go(page, base, "/catalog")
    cats = IDX["categories"]; total = sum(len(c["capabilities"]) for c in cats)
    assert page.get_by_role("status").filter(has_text="Showing").inner_text() == f"Showing {total} of {total} capabilities in 6 categories."
    for s, label in (("NOT_IMPLEMENTED", "NOT IMPLEMENTED"), ("DOCUMENTED_ONLY", "DOCUMENTED ONLY"), ("AVAILABLE_WITH_EVIDENCE", "AVAILABLE WITH EVIDENCE")):
        page.get_by_label(label, exact=True).check()
        n = sum(1 for c in cats for x in c["capabilities"] if x["status"] == s)
        k = sum(1 for c in cats if any(x["status"] == s for x in c["capabilities"]))
        assert f"Showing {n} of {total} capabilities in {k} categories." in main_text(page)
    page.get_by_label("NOT IMPLEMENTED", exact=True).check()
    t = main_text(page)
    for g in IDX["gaps"]["not_implemented"]:
        assert g["capability"] in t and (g["quote"]["text"] in t if g["quote"] else g["note"] in t)
    page.get_by_label("All", exact=True).check()
    assert "a category's status only says whether any experiment" in main_text(page).lower() or "does not mean a complete evaluation suite exists" in main_text(page)


def test_results_explorer_filters_selection_cases_events_and_provenance(page, base):
    go(page, base, "/results")
    assert "Showing 11 of 11 experiments." in main_text(page)
    page.get_by_label("Evidence class").select_option("SIMULATED")
    assert "Showing 1 of 11 experiments." in main_text(page)
    page.get_by_label("Evidence class").select_option("all"); page.get_by_label("Category").select_option("tool-authorization")
    assert "Showing 5 of 11 experiments." in main_text(page)
    page.get_by_label("Search").fill("zzz-nothing")
    assert "No experiment matches these filters." in main_text(page)
    page.get_by_role("button", name="Clear the filters").click()
    assert "Showing 11 of 11 experiments." in main_text(page)
    page.get_by_role("link", name=re.compile("^Scope escalation on a granted tool")).click()
    page.wait_for_url(re.compile(r"/results/mcp-003$"))
    e = EXPS["mcp-003"]
    reg = page.get_by_role("region", name=e["title"]); reg.wait_for()
    assert e["target"]["description"] in reg.inner_text() and e["threat"]["id"] in reg.inner_text()
    for role in ("BASELINE", "ATTACK", "RETEST"):
        page.get_by_role("button", name=re.compile(f"^{role}")).click()
        c = next(x for x in e["cases"] if x["role"] == role)
        card = page.get_by_role("article", name=c["title"]); text = card.inner_text()
        assert c["statement"] in text and c["expected"]["quote"]["text"] in text
        for d in c["facts"]["decisions"]:
            assert d["reason"].lower() in text.lower() and d["decision"] in text
        assert "NOT_VERIFIED" in text and "RECORDED" in text
        card.locator("summary", has_text="The recorded events").click()
        assert card.locator(".rec-events > li").count() == len(c["timeline"])
        card.locator("summary", has_text="Where this comes from").click()
        assert c["sources"][0]["sha256"] in card.text_content() and c["sources"][0]["file"] in card.text_content()
        assert "byte for byte" in text
    atk = card_atk = next(x for x in e["cases"] if x["role"] == "ATTACK")
    page.get_by_role("button", name=re.compile("^ATTACK")).click()
    ev = page.locator(".rec-events > li").nth(2); ev.locator("summary").click()
    d = [x for x in atk["timeline"] if x["event.name"] == "agentsec.control.decision"][0]
    for k in ("agentsec.control.reason", "gen_ai.tool.name", "agentsec.mcp.requested_scope"):
        assert str(d[k]) in ev.inner_text()
    assert page.get_by_role("region", name=re.compile("^Framework relationships")).locator("tbody tr").count() == len(e["mappings"]) == 3
    assert "Every case is a single recorded run." in main_text(page)


def test_simulated_and_external_experiments_are_labelled_and_never_look_live(page, base):
    go(page, base, "/results/component-provenance")
    t = page.get_by_role("region", name=EXPS["component-provenance"]["title"]).inner_text()
    assert "SIMULATED" in t and "SIMULATED — NOT A LIVE RUN" in t and "No finding is derived from simulated evidence" in t and "No indexed copy" in t or "A simulated packet has no indexed copy" in t
    go(page, base, "/results/garak-dan")
    g = EXPS["garak-dan"]["cases"][0]
    t = page.get_by_role("region", name=EXPS["garak-dan"]["title"]).inner_text()
    assert g["facts"]["model"] in t and g["facts"]["probe"] in t and g["statement"] in t and "No framework relationship is recorded" in t
    assert "One local model, one probe, one generation and one detector." in t


def test_compare_requires_a_controlled_pair_and_never_compares_unrelated_runs(page, base):
    go(page, base, "/compare/mcp-003")
    t = main_text(page)
    assert "Controlled pair: YES" in t and "2 of the 3 recorded cases" in t
    chk = EXPS["mcp-003"]["comparison"]["same_request_check"]
    tbl = page.get_by_role("region", name="Is the request the same in both runs?")
    for f in ("gen_ai.tool.name", "agentsec.mcp.requested_scope"):
        assert str(chk["attack"][f]) in tbl.inner_text() and f in tbl.text_content()
    assert "absent in both" in tbl.inner_text()
    sbs = page.get_by_role("region", name="The recorded runs side by side").inner_text()
    assert "defended" in sbs and "vulnerable" in sbs and "DENY" in sbs and "ALLOW" in sbs
    assert "does not measure how often the control holds" in t and "not evidence of control effectiveness" in t
    go(page, base, "/compare/mcp-006")
    t = main_text(page)
    assert "agentsec.content.hash" in t and "These reported fields differ" in t
    go(page, base, "/compare/garak-dan")
    assert "No comparison is offered" in main_text(page) and "not a robustness evaluation" in main_text(page)
    go(page, base, "/compare/component-provenance")
    assert "No comparison is offered" in main_text(page)
    go(page, base, "/compare/scanner-catalog")
    sc = EXPS["scanner-catalog"]["comparison"]
    t = main_text(page)
    assert "does not show a shared request or process" in t
    for r in sc["rows"]:
        assert r["description_sha256"] in t


def test_findings_filters_cards_and_unassessed_fields(page, base):
    go(page, base, "/findings")
    assert "Showing 9 of 9 findings." in main_text(page)
    page.get_by_label("Documented line").select_option("no")
    assert "Showing 1 of 9 findings." in main_text(page)
    page.get_by_label("Documented line").select_option("all"); page.get_by_role("combobox", name=re.compile("^Evaluation")).select_option("mcp-003")
    assert "Showing 1 of 9 findings." in main_text(page)
    f = next(x for x in IDX["findings"] if x["id"] == "F-mcp-003-execution")
    card = page.get_by_role("article", name=f["title"]); t = card.inner_text()
    assert f["observed"] in t and f["expected"]["quote"]["text"] in t and "NOT_VERIFIED" in t and "SEVERITY NOT ASSESSED" in t
    assert "NOT ASSIGNED · NOT ASSIGNED" in t and "NOT ASSESSED · NOT ASSESSED" in t and "TM-T04" in t and "Yes" in t
    card.locator("summary", has_text="Target, conditions").click()
    assert f["evidence"][0] in card.inner_text() and "ATTACK run in the vulnerable profile" in card.inner_text()
    page.get_by_role("combobox", name=re.compile("^Evaluation")).select_option("all"); page.get_by_label("Search").fill("zzzz")
    assert "No finding matches these filters." in main_text(page)
    page.get_by_role("button", name="Clear the filters").click()
    assert "Showing 9 of 9 findings." in main_text(page)


def read_download(page, name_part="Download the report"):
    with page.expect_download() as d:
        page.get_by_role("button", name=name_part).click()
    dl = d.value
    return dl.suggested_filename, Path(dl.path()).read_text(encoding="utf-8")


def test_export_markdown_and_json_reports_match_the_evidence(page, base):
    go(page, base, "/export")
    page.get_by_text("Preview").wait_for()
    name, md = read_download(page)
    assert name == "eval-report-mcp-003.md"
    for h in ("# AI Security Evaluation Report", "## 1. Scope", "## 2. Observations", "## 3. Interpretations", "## 4. Not assessed", "## 5. Provenance", "## 6. Limitations"):
        assert h in md, h
    e = EXPS["mcp-003"]
    assert md.index("## 2. Observations") < md.index("## 3. Interpretations") < md.index("## 4. Not assessed")
    for c in e["cases"]:
        assert c["statement"] in md and c["sources"][0]["sha256"] in md and c["sources"][0]["file"] in md
    f = next(x for x in IDX["findings"] if x["id"] == "F-mcp-003-execution")
    assert f["observed"] in md and f["expected"]["quote"]["text"] in md and "Severity: NOT ASSESSED" in md and "Owner: NOT ASSIGNED" in md
    assert e["comparison"]["reading"] in md and "NOT_VERIFIED" in md
    obs_part = md.split("## 3. Interpretations")[0]
    assert "Finding F-" not in obs_part and e["comparison"]["reading"] not in obs_part, "observations carry no interpretation"
    page.get_by_label("JSON (structured)").check()
    name, js = read_download(page)
    j = json.loads(js)
    assert name == "eval-report-mcp-003.json" and j["schema"] == "agentsec.eval_report.v1"
    assert [o["case"] for o in j["observations"]] == [c["id"] for c in e["cases"]]
    assert [o["statement"] for o in j["observations"]] == [c["statement"] for c in e["cases"]]
    assert [x["id"] for x in j["interpretations"]["findings"]] == ["F-mcp-003-execution"]
    assert {c["sources"][0]["file"]: c["sources"][0]["sha256"] for c in e["cases"]}.items() <= {p["file"]: p["sha256"] for p in j["provenance"]}.items()
    for p in j["provenance"]:
        assert re.fullmatch(r"[0-9a-f]{64}", p["sha256"]) and (ROOT / p["file"]).is_file()
        assert __import__("hashlib").sha256((ROOT / p["file"]).read_bytes()).hexdigest() == p["sha256"]
    assert j["not_assessed"]["severity"] == "NOT ASSESSED" and j["not_assessed"]["owner"] == "NOT ASSIGNED" and j["not_assessed"]["findings"] == 1
    assert "No test case has a host-verifier receipt" in " ".join(j["limitations"]) and not re.search(r"score|percent", js, re.I)


def test_export_selection_all_none_and_deterministic_output(page, base):
    go(page, base, "/export")
    page.get_by_role("button", name="Select all").click()
    page.get_by_text("Preview").wait_for()
    name, md1 = read_download(page)
    assert name == "eval-report-all.md"
    for e in EXPS.values():
        assert e["title"] in md1
    j = [e for e in EXPS.values()]
    assert md1.count("Finding F-") == len(IDX["findings"]) and "SIMULATED" in md1 and "no comparison" in md1.lower()
    page.get_by_role("button", name="Clear").click()
    assert "Select at least one experiment" in main_text(page) and page.get_by_role("button", name="Download the report").count() == 0
    page.get_by_role("button", name="Select all").click(); page.get_by_text("Preview").wait_for()
    _, md2 = read_download(page)
    assert md1 == md2, "the report is deterministic"
    assert "Downloaded eval-report-all.md" in main_text(page)


def test_loading_error_unknown_and_failed_chunk_states(page, base):
    page.goto(base + "/results/nope"); page.get_by_role("navigation", name="Evaluation Center").wait_for()
    assert "There is no experiment called nope." in main_text(page)
    page.route(re.compile(r"exp-mcp-003-.*\.js"), lambda r: r.abort())
    page.goto(base + "/results/mcp-003")
    alert = page.get_by_role("alert"); alert.wait_for()
    assert "could not be loaded" in alert.inner_text() and "Nothing was changed" in alert.inner_text()
    assert alert.get_by_role("button", name="Reload the page").is_enabled()
    page.unroute(re.compile(r"exp-mcp-003-.*\.js"))
    alert.get_by_role("button", name="Reload the page").click()
    page.get_by_role("region", name=EXPS["mcp-003"]["title"]).wait_for()


def test_slow_chunk_shows_a_loading_status_first(page, base):
    import time
    page.route(re.compile(r"EvalCenter-.*\.js"), lambda r: (time.sleep(1.2), r.continue_()))
    page.goto(base, wait_until="commit")
    page.get_by_role("status").filter(has_text="Loading the EVAL Center").wait_for()
    page.get_by_role("navigation", name="Evaluation Center").wait_for()


def test_nothing_posts_or_calls_the_backend_and_the_code_is_a_separate_chunk(page, base):
    reqs = []
    page.on("request", lambda r: reqs.append((r.method, r.url)))
    page.goto(base.replace("/evals", "")); page.wait_for_selector("h1")
    assert not any("EvalCenter" in u or "/exp-" in u for _, u in reqs), "the EVAL code and evidence load only when the Center opens"
    seen = watch(page)
    for p in VIEWS:
        go(page, base, p)
    assert any("EvalCenter" in u for _, u in reqs) and any("/exp-mcp-003" in u for _, u in reqs)
    assert all(m == "GET" for m, _ in reqs) and seen == []


def test_keyboard_tabs_cases_filters_and_export(page, base):
    go(page, base, "/results/mcp-003")
    nav = page.get_by_role("navigation", name="Evaluation Center")
    page.get_by_role("region", name=EXPS["mcp-003"]["title"]).wait_for()
    b = page.get_by_role("button", name=re.compile("^RETEST")); b.focus(); page.keyboard.press("Enter")
    assert b.get_attribute("aria-pressed") == "true"
    b = page.get_by_role("button", name=re.compile("^ATTACK")); b.focus(); page.keyboard.press("Space")
    assert b.get_attribute("aria-pressed") == "true"
    nav.get_by_role("link", name="Findings").focus(); page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/findings$"))
    sel = page.get_by_role("combobox", name=re.compile("^Evaluation")); sel.focus(); page.keyboard.press("ArrowDown")
    assert "Showing" in main_text(page)
    nav.get_by_role("link", name="Export").focus(); page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/export$"))
    box = page.get_by_label(EXPS["pi-001"]["title"] + " (RECORDED)", exact=False); box.focus(); page.keyboard.press("Space")
    assert box.is_checked()
    for r in page.locator("main [role=region][tabindex='0']").all()[:1]:
        r.focus(); assert r.evaluate("e => e === document.activeElement")


@pytest.mark.parametrize("path", VIEWS + ["/results/pi-001", "/compare/scanner-catalog", "/results/component-provenance"])
def test_390px_layout_has_no_sideways_page_scroll(browser, base, path):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    pg.goto(base + path); pg.get_by_role("navigation", name="Evaluation Center").wait_for(); pg.wait_for_timeout(600)
    for sm in pg.locator("main summary").all()[:8]:
        sm.click()
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), path
    for r in pg.locator("main [role=region][tabindex='0']").all()[:2]:
        r.focus(); assert r.evaluate("e => e === document.activeElement")
    ctx.close()


def test_existing_academy_and_assurance_navigation_are_unchanged(page, base):
    page.goto(base.replace("/evals", "")); page.wait_for_selector("h1")
    nav = page.get_by_role("navigation", name="Primary navigation")
    for name in ("Home", "Your Path", "Curriculum Explorer", "AI & Agent Foundations", "Loan Desk Mission", "MCP Tool Authorization", "Mastery", "Security Assurance", "EVAL Center"):
        assert nav.get_by_role("link", name=name).count() == 1, name
    page.goto(base.replace("/evals", "/assurance")); page.wait_for_selector("h1")
    assert page.get_by_role("link", name="Start the workshop").count() == 1
    page.goto(base.replace("/evals", "/lab/LAB-MCP-003")); page.wait_for_selector("h1")
    assert page.get_by_role("tab", name=re.compile("Practice")).count() == 1


def test_guided_demonstration_steps_each_lead_to_a_working_view(page, base):
    steps = IDX["demo"]["steps"]
    assert len(steps) == 5 and steps[0]["to"] == "results/mcp-003"
    for s in steps:
        go(page, base)
        li = page.locator(".ev-demo li", has_text=s["title"])
        assert s["text"] in li.inner_text()
        li.get_by_role("link", name="Go to this step").click()
        page.wait_for_url(re.compile(re.escape("/learn/evals/" + s["to"]) + r"$"))
        page.get_by_role("navigation", name="Evaluation Center").wait_for()
        assert "That page does not exist" not in main_text(page) and page.get_by_role("alert").count() == 0
