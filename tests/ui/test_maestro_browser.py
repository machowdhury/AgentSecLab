"""The MAESTRO workbench in the threat-modeling lab, in a real browser: build a model from blank, load the worked example, check it against the rubric, persist it,
download the report, and keep a narrow screen free of sideways scroll. Nothing is launched and nothing is sent. SKIPPED without Playwright and a Chromium."""
from __future__ import annotations

import json
import re
import threading

import pytest

pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_rag_workbench_browser import launches, tab  # noqa: E402

LAB = "LAB-THREAT-MODELING-001"


@pytest.fixture
def url():
    srv = make_server("127.0.0.1", 0, create_app(AcmeBankClient("http://127.0.0.1:9")), threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/learn/lab/{LAB}"
    srv.shutdown()


def open_wb(pg, url):
    pg.goto(url); tab(pg, "Practice")
    wb = pg.get_by_test_id("maestro-workbench"); wb.wait_for()
    return wb


def check(pg):
    pg.get_by_role("button", name="Check my model").click()
    return pg.get_by_test_id("maestro-result")


def test_a_blank_model_fails_every_criterion_and_the_example_meets_them_all(page, url):
    sent = launches(page)
    wb = open_wb(page, url)
    assert "LOCAL DRAFT, NOT AN ASSESSMENT" in wb.inner_text() and sent == []
    res = check(page)
    assert "not complete yet" in res.inner_text() and res.locator("li[data-state='NOT MET']").count() == 8
    page.get_by_role("button", name="Load the worked example").click()
    res = check(page)
    assert "structure MAESTRO asks for is present" in res.inner_text() and res.locator("li[data-state='MET']").count() == 8
    assert sent == [], "the workbench launches nothing"


def test_building_a_model_by_hand_moves_the_criteria(page, url):
    wb = open_wb(page, url)
    page.get_by_label("Layer for Ollama-hosted language model", exact=True).select_option("1")
    page.get_by_label("Layer for Exact-ID local RAG retriever", exact=True).select_option("1")      # a wrong placement
    page.locator("summary", has_text="1. Foundation Models").click()
    page.get_by_role("button", name="Add a Layer 1 threat").click()
    page.get_by_label("T1: threat label").select_option("Adversarial Examples")
    page.get_by_label("T1 inherent risk (no control works): impact").select_option("HIGH")
    page.get_by_label("T1 inherent risk (no control works): likelihood").select_option("LIKELY")
    assert "HIGH" in wb.locator("[aria-label='Threat T1']").inner_text()
    res = check(page)
    r1, r3, r5 = (res.locator("li", has_text=f"{r} ").first for r in ("R1", "R3", "R5"))
    assert r1.get_attribute("data-state") == "NOT MET" and r3.get_attribute("data-state") == "NOT MET" and r5.get_attribute("data-state") == "NOT MET"
    assert "1 of 7 layers" in r3.inner_text()
    page.get_by_label("T1: threat label").select_option("__custom")
    page.get_by_label("T1: custom threat name").fill("My own threat")
    res = check(page)
    assert "neither an official label" in res.locator("li", has_text="R3 ").first.inner_text(), "a custom threat needs a written reason"


def test_the_draft_survives_a_reload_and_clear_removes_it(page, url):
    open_wb(page, url)
    page.get_by_role("textbox", name="Scope", exact=True).fill("My scope for AcmeBank")
    page.get_by_role("button", name="Load the worked example").click()
    page.reload(); tab(page, "Practice")
    assert page.get_by_role("textbox", name="Scope", exact=True).input_value().startswith("AcmeBank's lending-policy assistant")
    assert page.get_by_label("EX-T01: threat label").count() == 1
    page.get_by_role("button", name="Clear my draft").click()
    assert page.get_by_role("textbox", name="Scope", exact=True).input_value() == "" and page.locator("[aria-label='Threat EX-T01']").count() == 0


def test_the_report_downloads_with_every_section_and_escapes_what_you_typed(page, url):
    open_wb(page, url)
    page.get_by_role("button", name="Load the worked example").click()
    page.get_by_role("textbox", name="Scope", exact=True).fill("# injected | <script>alert(1)</script>")
    with page.expect_download() as d:
        page.get_by_role("button", name="Download report (Markdown)").click()
    assert d.value.suggested_filename == "acmebank-maestro-threat-model.md"
    md = open(d.value.path(), encoding="utf-8").read()
    for h in ("## 2. Decomposition by layer", "## 4. Threat register", "## 5. Cross-layer attack paths", "## 7. Self-check", "## 8. Compare with the official MAESTRO Threat Analyzer", "## 9. Limits"):
        assert h in md, h
    assert "<script>" not in md and "LOCAL_DRAFT_NOT_APPROVED" in md and "EX-T13" in md and "Agent Tool Misuse" in md
    with page.expect_download() as d2:
        page.get_by_role("button", name="Download model (JSON)").click()
    doc = json.loads(open(d2.value.path(), encoding="utf-8").read())
    assert doc["status"] == "LOCAL_DRAFT_NOT_APPROVED" and len(doc["model"]["threats"]) == 16 and re.fullmatch(r"[0-9a-f]{64}", doc["integrity"]["model_sha256"])


def test_the_paths_editor_and_scenario_links_work(page, url):
    open_wb(page, url)
    page.get_by_role("button", name="Load the worked example").click()
    assert page.locator("[aria-label='Path EX-P2'] li").count() == 4
    assert page.get_by_role("link", name="LAB-MCP-001").first.get_attribute("href").endswith("/learn/lab/LAB-MCP-001")
    page.get_by_label("New path name").fill("Mine")
    page.get_by_role("button", name="Add a path").click()
    assert page.locator("[aria-label='Path P5']").count() == 1


def test_narrow_screens_do_not_scroll_sideways_with_the_example_loaded(browser, url):
    ctx = browser.new_context(viewport={"width": 390, "height": 800}); pg = ctx.new_page()
    pg.goto(url); tab(pg, "Practice"); pg.get_by_role("button", name="Load the worked example").click()
    check(pg)
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    ctx.close()


@pytest.mark.parametrize("width", [1280, 390])
def test_no_serious_or_critical_accessibility_violation_with_the_example_and_results_shown(browser, url, width):
    axe_mod = pytest.importorskip("axe_playwright_python.sync_playwright")
    ctx = browser.new_context(viewport={"width": width, "height": 900}); pg = ctx.new_page()
    pg.goto(url); tab(pg, "Practice"); pg.get_by_role("button", name="Load the worked example").click()
    for s in pg.locator("details.mx-layer summary").all():
        s.click() if s.evaluate("e => !e.parentElement.open") else None
    check(pg)
    out = axe_mod.Axe().run(pg).response
    bad = [(v["id"], v["impact"], [n["target"] for n in v["nodes"]][:3]) for v in out["violations"] if v["impact"] in ("serious", "critical")]
    ctx.close()
    assert not bad, bad


@pytest.mark.parametrize("saved", [
    '{"v":1,"model":{"scope":5,"threats":"x","paths":[],"placements":{},"boundaries":{}}}',
    '{"v":1,"model":{"scope":"s","threats":[null,1,{"layer":99,"elements":"no","inherent":7,"controls":[1,{}]}],"paths":[{"steps":"x"},null],"placements":{"__proto__":9,"CMP-APP":"x"},"boundaries":{"TB-01":{"layers":"no"},"__proto__":{}}}}',
    '{"v":1,"model":{"scope":"","placements":null,"boundaries":{},"threats":[],"paths":[]}}',
    '{"v":1,"model":{"scope":"","placements":{},"boundaries":{},"threats":[{"id":5,"inherent":null,"controls":"x"}],"paths":[{"steps":null}]}}',
    "not json at all",
])
def test_a_tampered_saved_draft_never_breaks_the_page_and_can_be_cleared(page, url, saved):
    page.goto(url)
    page.evaluate("s => window.localStorage.setItem('agentsec.maestro.v1', s)", saved)
    page.reload(); tab(page, "Practice")
    page.get_by_test_id("maestro-workbench").wait_for()
    assert page.evaluate("Object.prototype.hasOwnProperty.call({}, 'CMP-APP') === false && ({}).polluted === undefined")
    page.get_by_role("button", name="Clear my draft").click()
    assert page.get_by_role("textbox", name="Scope", exact=True).input_value() == ""
    check(page)       # the rubric still runs on whatever was recovered


def _fill_threat(pg, tid, label, desc, elements, scenarios, control, mitigation, inh=("HIGH", "LIKELY"), res=("MODERATE", "POSSIBLE")):
    pg.get_by_label(f"{tid}: threat label").select_option(label)
    pg.get_by_label(f"{tid}: description").fill(desc)
    pg.get_by_label(f"{tid}: elements").select_option(elements)
    pg.get_by_label(f"{tid}: evidence status").select_option("DEMONSTRATED")
    pg.get_by_label(f"{tid}: scenarios").select_option(scenarios)
    pg.get_by_label(f"{tid}: controls").select_option([control])
    for kind, (imp, lik) in (("inherent risk (no control works)", inh), ("residual risk (with the controls you named)", res)):
        pg.get_by_label(f"{tid} {kind}: impact").select_option(imp)
        pg.get_by_label(f"{tid} {kind}: likelihood").select_option(lik)
        pg.get_by_label(f"{tid} {kind}: reason").fill(f"My reasoning for {tid}: {kind}.")
    pg.get_by_label(f"{tid}: mitigation").fill(mitigation)


def test_a_learner_can_complete_the_whole_workflow_by_hand_and_get_the_report(page, url):
    """Blank draft to finished report with no worked example: architecture decomposition, trust boundaries, one threat on each of the seven layers
    with scenarios, controls, risk and mitigation, two cross-layer paths, the self-check, and a downloaded report that carries what was typed."""
    sent = launches(page)
    wb = open_wb(page, url)
    data = json.loads((__import__("pathlib").Path(__file__).resolve().parents[2] / "learning/level_1/LAB-THREAT-MODELING-001/maestro.json").read_text(encoding="utf-8"))
    ab, fw = data["acmebank"], data["framework"]
    page.get_by_role("textbox", name="Scope", exact=True).fill("My scope: the AcmeBank lending-policy assistant, in scope; production banking, out of scope.")
    for e in ab["elements"]:                                                                  # step 2: decompose the architecture into the layers
        page.get_by_label(f"Layer for {e['name']}", exact=True).select_option(str(e["layer"]))
    for b in ab["boundaries"]:                                                                # step 2b: trust boundaries
        page.get_by_label(f"Identified {b['name']}", exact=True).check()
        page.get_by_label(f"{b['name']}: layer 1", exact=True).select_option(str(b["layers"][0]))
        page.get_by_label(f"{b['name']}: layer 2", exact=True).select_option(str(b["layers"][1]))
    by_layer = {}
    for e in ab["elements"]:
        by_layer.setdefault(e["layer"], e["id"])
    scen = {"MCP": "LAB-MCP-001", "prompt injection": "LAB-PI-001", "memory": "LAB-MEMORY-001", "RAG": "LAB-RAG-CONTEXT", "delegation": "LAB-MCP-006"}
    fam = list(scen.values())
    ctl = ab["controls"][0]["id"]
    for n in range(1, 8):                                                                     # step 3: a threat on every layer from the article's list
        page.locator("summary", has_text=re.compile(rf"^{n}\. ")).click()
        page.get_by_role("button", name=f"Add a Layer {n} threat").click()
        _fill_threat(page, f"T{n}", fw["layers"][n - 1]["official_threats"][0], f"What could happen on layer {n} in AcmeBank.", [by_layer[n]], [fam[(n - 1) % 5]], ctl,
                     f"Mitigation for layer {n}: restrict and monitor it.")
    for p in (1, 2):                                                                          # step 4: two cross-layer attack paths over three layers each
        page.get_by_label("New path name").fill(f"My path {p}")
        page.get_by_role("button", name="Add a path").click()
        page.get_by_label(f"P{p}: narrative").fill(f"Path {p}: an attacker moves from one layer to the next.")
        for i, layer in enumerate((1, 2, 3) if p == 1 else (4, 5, 6), start=1):
            page.get_by_role("button", name=f"Add a step to P{p}").click()
            page.get_by_label(f"P{p} step {i} layer").select_option(str(layer))
            page.get_by_label(f"P{p} step {i} threat").select_option(f"T{layer}")
            page.get_by_label(f"P{p} step {i} note").fill(f"step {i} of path {p}")
    res = check(page)
    states = {li.get_attribute("data-state") for li in res.locator("li").all() if li.get_attribute("data-state")}
    assert "structure MAESTRO asks for is present" in res.inner_text(), res.inner_text()
    for r in ("R1", "R2", "R3", "R4", "R5", "R7", "R8"):
        assert res.locator("li", has_text=f"{r} ").first.get_attribute("data-state") == "MET", (r, res.inner_text())
    ranked = wb.get_by_role("region", name=re.compile("Ranked threats"))
    assert ranked.locator("tbody tr").count() == 7
    with page.expect_download() as d:
        page.get_by_role("button", name="Download report (Markdown)").click()
    md = open(d.value.path(), encoding="utf-8").read()
    for want in ("My scope: the AcmeBank lending-policy assistant", "My path 2", "My reasoning for T7: residual risk", "Mitigation for layer 4", "LOCAL_DRAFT_NOT_APPROVED"):
        assert want in md, want
    assert sent == [] and states
