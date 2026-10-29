"""RC2 integration: memory, delegation and MCP-wizard launches, AcmeBank's real workflow, Academy/scenario-card links.

In-process fixtures only (real attack app + in-process AcmeBank double, no Docker, no model). Screenshots of final states are
written to docs/reviews/rc2/ui/integration/. SKIPPED without Playwright/Chromium.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from tests.ui.test_loan_desk_mission_browser import browser, page, stack  # noqa: E402,F401

OUT = Path(__file__).resolve().parents[2] / "docs/reviews/rc2/ui/integration"
NO_HSCROLL = "document.documentElement.scrollWidth <= document.documentElement.clientWidth"


def root(stack):
    return stack().split("/academy")[0]




def final_checks(page, name, allow=frozenset()):
    """Axe (serious/critical) + no horizontal scroll + screenshot at 768 and 1280, on the page's current final state."""
    axe_mod = pytest.importorskip("axe_playwright_python.sync_playwright")
    OUT.mkdir(parents=True, exist_ok=True)
    for w in (768, 1280):
        page.set_viewport_size({"width": w, "height": 900})
        page.wait_for_timeout(200)
        assert page.evaluate(NO_HSCROLL), f"{name}@{w} scrolls horizontally"
        bad = [(v["id"], n["target"][0]) for v in axe_mod.Axe().run(page).response["violations"] if v["impact"] in ("serious", "critical") for n in v["nodes"]]
        bad = [b for b in bad if b not in allow]
        assert not bad, (name, w, bad)
        page.screenshot(path=str(OUT / f"{name}-{w}.png"), full_page=True)


MEMORY = ("/labs/LAB-MEMORY-001", "chain-recall")
DELEG = ("/labs/LAB-AGENT-DELEGATION-001", None)


@pytest.mark.parametrize("path,chain", [MEMORY, DELEG], ids=["memory", "delegation"])
def test_memory_and_delegation_attack_then_retest(page, stack, path, chain):
    page.goto(root(stack) + path)
    assert page.locator("h1").count() == 1 and page.locator(".scenario-card[aria-current=page]").count() == 1
    assert page.inner_text("#primary-run-id").strip() == "Not launched" and page.inner_text("#result-mode").strip() == "NOT RUN"
    page.click("#attack-button")
    page.wait_for_function("document.getElementById('primary-run-id').textContent.trim() !== 'Not launched'", timeout=30000)
    atk = page.inner_text("#primary-run-id").strip()
    assert re.fullmatch(r"[0-9a-f-]{36}", atk), atk
    page.wait_for_function("document.getElementById('result-mode').textContent.trim() !== 'NOT RUN'", timeout=30000)
    assert "ATTACK" in page.inner_text("#result-mode").upper()
    assert page.inner_text("#result-authz").strip() != "NOT RUN" and page.inner_text("#result-fingerprint").strip() != "NOT RUN"
    page.click("#retest-button")
    page.wait_for_function("(document.getElementById('retest-response')||{}).textContent !== 'Not run'", timeout=30000)
    page.wait_for_function("document.getElementById('result-mode').textContent.toUpperCase().includes('RETEST')", timeout=30000)
    assert page.inner_text("#primary-run-id").strip() != atk  # the retest minted its own server-owned run id
    assert page.text_content("#attack-response").strip() not in ("", "Not run") and page.text_content("#retest-response").strip() not in ("", "Not run")
    cmp = page.inner_text("#comparison-body").upper()
    assert cmp.count("NOT RUN") < 3, cmp
    if chain:
        assert page.inner_text("#chain-write").strip() != "NOT RUN" and page.locator("#memory-run-grid").is_visible()
        assert re.fullmatch(r"[0-9a-f-]{36}", page.inner_text("#memory-write-id").strip())
        assert page.inner_text("#memory-source-id").strip()
    name = "memory" if chain else "delegation"
    final_checks(page, name)  # strict, evidence drawer closed
    page.locator("#advanced > summary").click()
    final_checks(page, name + "-evidence")      # strict: the response blocks are keyboard-focusable regions


def test_mcp_wizard_end_to_end(page, stack):
    page.goto(root(stack) + "/labs/LAB-MCP-001")
    rail = lambda: page.eval_on_selector_all("#phase-rail li[aria-current=step]", "e => e.map(x => x.dataset.phase)")
    cur = lambda: page.eval_on_selector("[data-step]:not([hidden])", "e => e.dataset.step")
    assert cur() == "start" and rail() == ["0"] and "Start here" in page.inner_text("#stepline-left")
    page.click("#start-lab")
    assert cur() == "baseline" and rail() == ["0"] and "Step 1 of 8" in page.inner_text("#stepline-left")
    page.click("#explore-baseline")
    page.wait_for_selector("#baseline-evidence:not([hidden])", timeout=30000)
    page.click("#baseline-continue")
    assert cur() == "predict" and rail() == ["1"]
    assert page.get_attribute("#record-prediction", "aria-disabled") == "true"
    page.click("label.opt:has(input[name=predict-control][value=DENY])")  # the radio itself is visually replaced; learners click the label
    page.click("label.opt:has(input[name=predict-execution][value=NO])")
    page.click("#record-prediction")
    assert cur() == "attack" and rail() == ["1"]
    assert "(done)" in page.inner_text("#phase-rail li[data-phase='0']")
    page.click("#fire-attack")
    page.wait_for_selector("#attack-complete:not([hidden])", timeout=30000)
    assert "control DENY" in page.inner_text("#complete-prediction") and "tool runs NO" in page.inner_text("#complete-prediction")
    # evidence in the technical drawer: five measured states and a real run id
    page.locator("#technical-details > summary").click()
    assert re.fullmatch(r"[0-9a-f-]{36}", page.inner_text("#run-id").strip())
    assert page.inner_text("#ui-status").strip() != "READY" and page.inner_text("#http-status").strip() != "NOT MEASURED"
    assert page.inner_text("#chain-decision").strip() != "NOT MEASURED" and page.inner_text("#fact-decision-value").strip() != "NOT MEASURED"
    with page.expect_popup() as pop:  # the Splunk notebook opens in a new tab and this tab advances to Investigate
        page.click("#open-notebook-primary")
    assert "layout_investigate" in pop.value.url and "run" in pop.value.url.lower()
    pop.value.close()
    assert cur() == "investigate" and rail() == ["2"]
    page.click("#investigate-continue")
    assert cur() == "defend" and rail() == ["3"]
    page.click("#goto-retest")
    assert cur() == "retest" and rail() == ["3"]
    page.click("#fire-retest")
    page.wait_for_selector("#retest-complete:not([hidden])", timeout=30000)
    page.click("#goto-compare")
    assert cur() == "compare" and rail() == ["4"]
    cmp_text = page.inner_text("#compare-body")
    assert "Run ATTACK and RETEST to fill" not in cmp_text and "ATTACK" in page.inner_text("#compare-table").upper() and "RETEST" in page.inner_text("#compare-table").upper()
    page.click("#goto-explain")
    assert cur() == "explain" and rail() == ["4"] and "Step 8 of 8" in page.inner_text("#stepline-left")
    page.fill("#ex1", "ATTACK ran, RETEST was denied.")
    assert "Run ATTACK and RETEST" not in page.inner_text("#claims-supported")
    final_checks(page, "mcp-wizard-explain")


# --- AcmeBank: its only workflow is the home-loan form + status panel; /acmebank is read-only -----------------------------

def _bank_page(page, stack):
    stack()
    return stack.bank_url + "/"


@pytest.mark.parametrize("terminal,state,step", [("completed_allowed", "COMPLETED", "3"), ("completed_denied", "DENIED", None)])
def test_acmebank_loan_outcomes_and_step_tracker(page, stack, terminal, state, step):
    url = _bank_page(page, stack)
    page.route("**/process", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps({"run_id": "run-" + state.lower(), "terminal": terminal})))
    page.goto(url)
    assert page.locator("#loan-form").count() == 1 and page.get_attribute("#ab-steps", "data-outcome") is None
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function(f"document.getElementById('ui-status').dataset.state==='{state}'")
    assert page.get_attribute("#ab-steps", "data-outcome") == state
    if step:
        assert page.get_attribute("#ab-steps", "data-step") == step
    assert page.input_value("#run-id") == "run-" + state.lower() and terminal in page.inner_text("#result-summary")
    final_checks(page, f"acmebank-{state.lower()}")


def test_acmebank_error_path_and_http_failure(page, stack):
    url = _bank_page(page, stack)
    page.route("**/process", lambda r: r.abort())
    page.goto(url)
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function("document.getElementById('ui-status').dataset.state==='ERROR'")
    assert "not a control DENY" in page.inner_text("#result-summary") and page.is_enabled("#submit-loan")
    page.unroute("**/process")
    page.route("**/process", lambda r: r.fulfill(status=500, content_type="application/json", body='{"error":"boom"}'))
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function("document.getElementById('ui-status').dataset.state==='ERROR'")
    assert page.get_attribute("#loan-form", "aria-busy") == "false"
    final_checks(page, "acmebank-error")


def test_acmebank_real_stack_submit_and_readonly_view(page, stack):
    base = root(stack)  # real in-process AcmeBank (PostureAwareModel double): no mocked /process
    page.goto(stack.bank_url + "/")
    page.get_by_role("button", name="Submit loan").click()
    page.wait_for_function("document.getElementById('ui-status').dataset.state!=='READY' && document.getElementById('ui-status').dataset.state!=='RUNNING'", timeout=60000)
    assert page.input_value("#run-id")
    final_checks(page, "acmebank-real")
    page.goto(base + "/acmebank")
    assert page.locator("#loan-form").count() == 0 and "DOCUMENTED" in page.inner_text("#readonly-notice")
    assert page.locator("#go-workbench").count() == 1
    page.locator("#behind-the-ai summary").click()
    final_checks(page, "acmebank-readonly")


# --- Academy navigation and scenario-card links --------------------------------------------------------------------------

LABS = ["/labs/LAB-PI-001", "/labs/LAB-MCP-001", "/labs/LAB-RAG-CONTEXT", "/labs/LAB-MEMORY-001", "/labs/LAB-AGENT-GOAL-INTEGRITY-001",
        "/labs/LAB-AGENT-DELEGATION-001", "/labs/LAB-AGENTSEC-CAPSTONE-001"]


def test_every_scenario_card_href_is_200_via_test_client_and_browser(page, stack, settings):
    from agentsec.attack_app import AcmeBankClient, create_app
    client = create_app(AcmeBankClient("http://127.0.0.1:9")).test_client()
    hrefs = set()
    for lab in LABS:
        r = client.get(lab)
        assert r.status_code == 200, lab
        found = re.findall(r'<a class="scenario-card" href="([^"]+)"', r.get_data(as_text=True))
        assert len(found) == 7, (lab, found)
        hrefs.update(found)
    assert hrefs == set(LABS)
    for h in hrefs:
        assert client.get(h).status_code == 200, h
    base = root(stack)
    for lab in LABS:  # in a real browser: click each card from this page, final URL + h1 + aria-current
        for h in sorted(hrefs):
            page.goto(base + lab)
            with page.expect_navigation():
                page.click(f'.scenario-cards a[href="{h}"]')
            assert page.url == base + h and page.locator("h1").count() == 1
            assert page.locator(".scenario-card[aria-current=page]").get_attribute("href") == h
    page.set_viewport_size({"width": 1280, "height": 900})
    page.screenshot(path=str(OUT / "scenario-cards-1280.png"), full_page=True)
    page.set_viewport_size({"width": 768, "height": 900})
    page.screenshot(path=str(OUT / "scenario-cards-768.png"), full_page=True)


# --- Gateway mode: is the classic Attack UI reachable? (no Docker: the production nginx rules are evaluated as written) -----

GW = Path(__file__).resolve().parents[2]
_NGINX = (GW / "gateway/templates/gateway.conf.template").read_text()
_ATTACK = (GW / "gateway/attack-enabled.conf").read_text()
_READ = re.compile(re.search(r"location ~ (\^/\(learn.*?\$\))\s*\{", _NGINX, re.S).group(1))
_OPS = re.compile(re.search(r"location ~ (\^/api/.*?)\s*\{", _ATTACK).group(1))


def routed(path):
    return bool(_READ.match(path) or _OPS.match(path))


@pytest.mark.parametrize("path", LABS + ["/acmebank", "/academy", "/academy/status", "/academy/path", "/academy/labs/LAB-MCP-001", "/academy/missions/loan-desk", "/api/attacks"])
def test_gateway_does_not_route_any_classic_page(path):
    assert not routed(path), path  # falls to `location / { return 404; }`
    assert "location / { return 404; }" in _NGINX


def test_gateway_routes_only_the_react_academy_and_its_apis():
    for ok in ("/learn", "/learn/lab/LAB-PI-001", "/static/attack-console.css", "/api/learn/config", "/api/labs/LAB-PI-001", "/api/launch", "/api/launches/abc"):
        assert routed(ok), ok
    # `/` is a redirect, not a classic page
    assert "location = / { return 302 /learn; }" in _NGINX


def test_attack_console_partial_is_only_reachable_through_unrouted_lab_pages():
    """_attack_console.html is {% include %}d only by the /labs/<id> templates; /static/ serves files, never templates."""
    users = sorted(p.name for p in (GW / "src/agentsec/templates").glob("*.html") if "_attack_console.html" in p.read_text())
    assert users == ["attack.html", "attack_authority.html", "attack_capstone.html", "attack_context.html", "attack_mcp.html"]
    assert not (GW / "src/agentsec/static/_attack_console.html").exists() and not routed("/templates/_attack_console.html")
    # its scenario cards (ac_cards) all point at /labs/*, none of which the gateway routes
    assert not any(routed(h) for h in LABS)


def test_react_academy_classic_links_are_all_gated_by_config_gateway():
    """Every literal link from the React Academy to a classic page is rendered only when config.gateway is false."""
    src = GW / "academy-ui/src"
    pat = re.compile(r"""["'`](/academy/[^"'`]*|/labs/[^"'`]*|/acmebank[^"'`]*)["'`]""")
    seen = []
    for f in sorted(src.rglob("*.ts*")):
        if ".test." in f.name:
            continue
        lines = f.read_text().splitlines()
        for i, line in enumerate(lines, 1):
            if pat.search(line) and "href" in line:
                seen.append(f"{f.name}:{i}")
                assert "config.gateway" in " ".join(lines[max(0, i - 2):i]), f"ungated classic link {f.name}:{i}"  # same or enclosing line
    assert len(seen) >= 3, seen  # the scan still matches the source (Lab.tsx, Home.tsx, shell.tsx)


def test_gateway_mode_config_reports_prefixed_classic_urls(monkeypatch):
    from agentsec.attack_app import AcmeBankClient, create_app
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    cfg = create_app(AcmeBankClient("http://127.0.0.1:9")).test_client().get("/api/learn/config").get_json()
    assert cfg["gateway"] is True and cfg["urls"]["splunk_web"] is None and cfg["urls"]["acmebank"] == "/attack-service/acmebank"   # the read-only view, never the real bank
    monkeypatch.delenv("AGENTSEC_GATEWAY_MODE")
    cfg = create_app(AcmeBankClient("http://127.0.0.1:9")).test_client().get("/api/learn/config").get_json()
    assert cfg["gateway"] is False and cfg["urls"]["acmebank"]
