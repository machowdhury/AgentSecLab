"""P1.4 Academy in a real Chromium browser against the real Flask app.

The app, templates, static files and committed REPLAY packs are real; the
AcmeBank runtime is a stub (health only). Nothing here launches a LIVE run. The
duplicate-launch test intercepts POST /api/launch in the browser, so it is a
MOCKED client test, not a live integration test.

Viewport sizes stand in for zoom: 1920x1080 at 200% is a 960x540 CSS viewport
and at 400% is 480x270. Genuine browser zoom is qualified separately.
"""

from __future__ import annotations

import json
import threading

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402

ATTACK_REPLAY = "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49"
RETEST_REPLAY = "7a1d37b5-d589-4dfd-8322-25ebd0152dbc"
PAGES = ("/academy", "/academy/foundations", "/academy/path", "/academy/status", "/academy/labs/LAB-MCP-001")
VIEWPORTS = ((1920, 1080), (1024, 768), (960, 540), (480, 270), (320, 568))


def _healthy(_path):
    return 200, {"status": "healthy", "security.profile": "defended"}


@pytest.fixture(scope="module")
def base_url(tmp_path_factory):
    app = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=_healthy),
                     launch_kwargs={"artifacts_dir": tmp_path_factory.mktemp("artifacts")})
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as pw:
        try:
            instance = pw.chromium.launch()
        except Exception as exc:  # browser binary not installed
            pytest.skip(f"Chromium unavailable: {exc}")
        yield instance
        instance.close()


@pytest.fixture()
def page_factory(browser):
    contexts = []

    def make(width=1920, height=1080):
        context = browser.new_context(viewport={"width": width, "height": height})
        contexts.append(context)
        page = context.new_page()
        page.errors = []
        page.on("console", lambda m: m.type == "error" and page.errors.append(m.text))
        page.on("pageerror", lambda e: page.errors.append(str(e)))
        return page

    yield make
    for context in contexts:
        context.close()


def _overflow(page):
    return page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")


def _clipped(page):
    """Visible elements whose content is wider than their box and cut off.

    Screen-reader-only content (CSS clip set) is hidden on purpose and skipped."""
    return page.evaluate("""() => Array.from(document.querySelectorAll('main *')).filter(n => {
        const s = getComputedStyle(n);
        if (s.clip && s.clip !== 'auto') return false;
        if (s.display === 'none' || s.visibility === 'hidden' || !n.offsetParent) return false;
        return (s.overflowX === 'hidden' || s.overflowX === 'clip') && n.scrollWidth > n.clientWidth + 1;
    }).map(n => n.tagName + '.' + n.className)""")


@pytest.mark.parametrize("width,height", VIEWPORTS)
def test_every_page_reflows_without_horizontal_scroll_or_clipping(page_factory, base_url, width, height):
    page = page_factory(width, height)
    for path in PAGES:
        page.goto(base_url + path)
        page.wait_for_load_state("networkidle")
        assert _overflow(page) <= 1, f"{path} scrolls horizontally at {width}x{height}"
        assert _clipped(page) == [], f"{path} clips content at {width}x{height}"
    assert page.errors == []


def test_card_layout_tables_keep_table_semantics(page_factory, base_url):
    page = page_factory(320, 568)
    for path in ("/academy/path", "/academy/status", "/academy/labs/LAB-MCP-001"):
        page.goto(base_url + path)
        page.wait_for_load_state("networkidle")
        missing = page.evaluate("""() => Array.from(document.querySelectorAll('table.data-table'))
            .filter(t => t.getAttribute('role') !== 'table' || t.querySelector('td:not([role=cell])')).length""")
        assert missing == 0, path


def test_csp_blocks_nothing_the_academy_needs(page_factory, base_url):
    page = page_factory()
    for path in PAGES:
        page.goto(base_url + path)
        page.wait_for_load_state("networkidle")
    assert not [e for e in page.errors if "Content Security Policy" in e]
    assert page.errors == []


def test_locked_steps_cannot_be_reached_before_their_prerequisites(page_factory, base_url):
    page = page_factory()
    page.goto(base_url + "/academy/labs/LAB-MCP-001")
    link = page.locator('[data-step-link="attack"]')
    assert link.get_attribute("aria-disabled") == "true"
    link.click(force=True)
    gate = page.locator("[data-gate-message]")
    assert gate.is_visible() and "Lock your prediction" in gate.inner_text()
    assert page.locator("#step-attack").is_hidden()
    page.goto(base_url + "/academy/labs/LAB-MCP-001#compare")
    assert page.locator("#step-start").is_visible()
    assert page.locator("#step-compare").is_hidden()


def test_full_replay_workflow_with_mouse_matches_the_committed_evidence(page_factory, base_url):
    page = page_factory()
    page.goto(base_url + "/academy/labs/LAB-MCP-001")
    page.get_by_role("button", name="Continue to Baseline").click()
    page.get_by_role("button", name="Load the recorded baseline").click()
    page.locator('[data-evidence-slot="baseline"] table').wait_for()
    assert "163d11e2-e751-4282-9406-19b490542ed4" in page.locator('[data-evidence-slot="baseline"]').inner_text()
    page.get_by_role("button", name="Continue to Predict").click()

    page.get_by_label("DENY", exact=True).check()
    page.get_by_label("No", exact=True).check()
    page.get_by_role("button", name="Lock prediction and continue").click()
    assert page.locator("#step-attack").is_visible()

    page.get_by_role("button", name="Use the recorded ATTACK (REPLAY)").click()
    card = page.locator('[data-run-card="ATTACK"]')
    card.locator("h3").wait_for()
    assert ATTACK_REPLAY in card.locator("p").first.inner_text()
    assert "REPLAY" in card.inner_text()
    assert page.get_by_role("button", name="Use the recorded ATTACK (REPLAY)").is_disabled()
    assert page.get_by_role("button", name="Launch LIVE ATTACK").is_disabled()
    search = card.get_by_role("link", name="Search this run in Splunk").get_attribute("href")
    assert ":8000/" in search and ATTACK_REPLAY in search and "earliest%3D1789182029" in search

    page.get_by_role("button", name="Continue to Investigate").click()
    page.locator("[data-questions] fieldset").first.wait_for()
    q1 = page.locator("[data-questions] li").nth(0)
    q1.get_by_label("ALLOW", exact=True).check()
    q1.get_by_role("button", name="Check against the evidence").click()
    assert "Matches the evidence" in q1.inner_text()
    q2 = page.locator("[data-questions] li").nth(1)
    q2.get_by_label("No", exact=True).check()
    q2.get_by_role("button", name="Check against the evidence").click()
    assert "The evidence shows something different" in q2.inner_text()
    assert "You predicted: control DENY" in q2.inner_text()
    q5 = page.locator("[data-questions] li").nth(4)
    q5.get_by_label("0", exact=True).check()
    q5.get_by_role("button", name="Check against the evidence").click()
    assert "Matches the evidence" in q5.inner_text()

    page.get_by_role("button", name="Continue to Defend").click()
    page.get_by_role("button", name="Continue to Retest").click()
    assert page.get_by_role("button", name="Launch LIVE RETEST").is_disabled()
    page.get_by_role("button", name="Use the recorded RETEST (REPLAY)").click()
    retest_card = page.locator('[data-run-card="RETEST"]')
    retest_card.locator("h3").wait_for()
    assert RETEST_REPLAY in retest_card.locator("p").first.inner_text()

    page.get_by_role("button", name="Continue to Compare").click()
    table = page.locator("[data-compare-slot] table")
    table.wait_for()
    decision_row = table.locator("tr", has_text="CTRL-MCP-001 decision")
    assert "ALLOW" in decision_row.inner_text() and "DENY" in decision_row.inner_text()
    assert "DIFFERENT" in decision_row.inner_text()
    slot = page.locator("[data-compare-slot]").inner_text()
    assert "OBSERVED" in slot and "INFERRED" in slot

    page.get_by_role("button", name="Continue to Explain").click()
    page.locator("[data-explain-recap] li").first.wait_for()
    page.get_by_role("button", name="Mark workflow complete").click()
    assert "Write a short explanation" in page.locator("[data-complete-feedback]").inner_text()
    page.locator("[data-explanation]").fill("The vulnerable profile allowed an out-of-grant tool; the defended profile denied it before the handler.")
    page.get_by_role("button", name="Mark workflow complete").click()
    assert "Workflow complete" in page.locator("[data-complete-feedback]").inner_text()

    page.goto(base_url + "/academy/path")
    assert page.locator('[data-progress-for="LAB-MCP-001"]').first.inner_text() == "Workflow complete"
    assert page.errors == []


def test_keyboard_only_skip_link_prediction_and_visible_focus(page_factory, base_url):
    page = page_factory(1024, 768)
    page.goto(base_url + "/academy/labs/LAB-MCP-001")
    page.keyboard.press("Tab")
    focused = page.evaluate("document.activeElement.textContent.trim()")
    assert focused.lower().startswith("skip to")
    outline = page.evaluate("getComputedStyle(document.activeElement).outlineStyle")
    assert outline not in ("none", "")
    page.keyboard.press("Enter")
    assert page.evaluate("document.activeElement.id") == "main"
    assert page.locator("#step-start").is_visible()

    page.goto(base_url + "/academy/labs/LAB-MCP-001#predict")
    assert page.evaluate("document.activeElement.id") == "h-predict"
    page.focus('input[name="predict-control"][value="ALLOW"]')
    page.keyboard.press("ArrowDown")
    assert page.evaluate("document.activeElement.value") == "DENY"
    page.focus('input[name="predict-execution"][value="YES"]')
    page.keyboard.press("Space")
    page.focus("[data-lock-prediction]")
    assert page.evaluate("getComputedStyle(document.activeElement).outlineStyle") not in ("none", "")
    page.keyboard.press("Enter")
    assert page.evaluate("document.activeElement.id") == "h-attack"
    assert "Step 4 of 9" in page.locator("[data-step-announcer]").inner_text()


def test_narrow_menu_disclosure_opens_and_escape_returns_focus(page_factory, base_url):
    page = page_factory(320, 568)
    page.goto(base_url + "/academy")
    nav = page.locator("#primary-nav")
    toggle = page.locator("[data-menu-toggle]")
    assert nav.is_hidden() and toggle.is_visible()
    toggle.focus()
    page.keyboard.press("Enter")
    assert toggle.get_attribute("aria-expanded") == "true" and nav.is_visible()
    page.keyboard.press("Tab")
    page.keyboard.press("Escape")
    assert toggle.get_attribute("aria-expanded") == "false" and nav.is_hidden()
    assert page.evaluate("document.activeElement.hasAttribute('data-menu-toggle')")


def test_recovered_live_pair_can_switch_this_tab_to_replay(page_factory, base_url):
    """Durable LIVE slots must not silently replace the recorded REPLAY pair.

    The switch changes this browser tab only. It does not delete server LIVE index rows.
    """
    page = page_factory()

    def handle_live_runs(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "slots": {
                        "ATTACK": {
                            "run_id": "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
                            "status": "complete",
                        },
                        "RETEST": {
                            "run_id": "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
                            "status": "complete",
                        },
                    }
                }
            ),
        )

    page.route("**/api/academy/live-runs", handle_live_runs)
    page.goto(base_url + "/academy/labs/LAB-MCP-001")
    _wait_status(page, "ATTACK", "LIVE")
    page.get_by_role("button", name="Continue to Baseline").click()
    page.get_by_role("button", name="Continue to Predict").click()
    page.get_by_label("ALLOW", exact=True).check()
    page.get_by_label("Yes", exact=True).check()
    page.get_by_role("button", name="Lock prediction and continue").click()
    switch = page.get_by_role("button", name="Use the recorded pair in this tab (REPLAY)")
    assert switch.is_visible()
    switch.click()
    card = page.locator('[data-run-card="ATTACK"]')
    card.locator("h3").wait_for()
    assert ATTACK_REPLAY in card.inner_text()
    assert "badge--replay" in card.locator(".badge").first.get_attribute("class")
    note = page.locator("[data-replay-switch-note]")
    assert "committed REPLAY" in note.inner_text()
    assert "not a live launch" in note.inner_text().lower()
    page.locator("[data-switch-replay]").wait_for(state="hidden")


def _wait_status(page, mode, text):
    # The Academy CSP forbids eval, so string wait_for_function predicates fail whenever they must poll.
    sync_api.expect(page.locator(f'[data-run-status="{mode}"]')).to_contain_text(text)


def _live_slots(attack_at, retest_at):
    def handle(route):
        route.fulfill(status=200, content_type="application/json", body=json.dumps({"slots": {
            "ATTACK": {"run_id": "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", "status": "complete", "recorded_at": attack_at},
            "RETEST": {"run_id": "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb", "status": "complete", "recorded_at": retest_at},
        }}))
    return handle


def _lock_prediction(page):
    page.goto(page.url.split("#")[0] + "#predict")
    page.locator('input[name="predict-control"][value="ALLOW"]').check()
    page.locator('input[name="predict-execution"][value="YES"]').check()
    page.get_by_role("button", name="Lock prediction and continue").click()


def test_recovered_live_pair_does_not_block_a_fresh_live_launch_mocked(page_factory, base_url):
    """MOCKED live-runs index. Regression: recovered slots used to disable both LIVE launch buttons forever."""
    page = page_factory()
    page.route("**/api/academy/live-runs", _live_slots("2026-10-09T21:36:05Z", "2026-10-09T21:36:05Z"))
    page.goto(base_url + "/academy/labs/LAB-MCP-001")
    _wait_status(page, "ATTACK", "LIVE")
    _lock_prediction(page)
    assert page.get_by_role("button", name="Launch LIVE ATTACK").is_disabled()
    fresh = page.get_by_role("button", name="Clear this tab and launch a fresh LIVE pair")
    fresh.click()
    assert page.get_by_role("button", name="Launch LIVE ATTACK").is_enabled()
    assert page.evaluate("document.activeElement.getAttribute('data-launch')") == "ATTACK"
    assert page.locator('[data-run-card="ATTACK"]').is_hidden()
    assert page.locator('[data-run-status="ATTACK"]').inner_text() == "No ATTACK run yet."
    assert "Server LIVE evidence is unchanged" in page.locator("[data-replay-switch-note]").inner_text()
    assert fresh.is_hidden()
    page.reload()
    page.wait_for_load_state("networkidle")
    page.goto(base_url + "/academy/labs/LAB-MCP-001#attack")
    assert page.locator('[data-run-status="ATTACK"]').inner_text() == "No ATTACK run yet."
    assert page.get_by_role("button", name="Launch LIVE ATTACK").is_enabled()


def test_older_recovered_retest_is_not_paired_with_a_newer_attack_mocked(page_factory, base_url):
    """MOCKED live-runs index: the RETEST slot predates the ATTACK slot, so it is not this ATTACK's retest."""
    page = page_factory()
    page.route("**/api/academy/live-runs", _live_slots("2026-10-09T22:00:00Z", "2026-10-09T18:25:57Z"))
    page.goto(base_url + "/academy/labs/LAB-MCP-001")
    _wait_status(page, "ATTACK", "LIVE")
    assert page.locator('[data-run-status="RETEST"]').inner_text() == "No RETEST run yet."
    stored = page.evaluate("JSON.parse(sessionStorage.getItem('agentsec.academy.mcp.v1')).runs")
    assert "RETEST" not in stored and stored["ATTACK"]["run_id"].startswith("aaaaaaaa")


def test_live_launch_double_click_sends_one_request_mocked(page_factory, base_url):
    """MOCKED: /api/launch is intercepted in the browser and answers with an ERROR."""
    page = page_factory()
    posts = []

    def handle(route):
        posts.append(route.request.post_data_json)
        route.fulfill(status=502, content_type="application/json",
                      body='{"error_class": "ERROR", "detail": "stubbed runtime unavailable"}')

    page.route("**/api/launch", handle)
    page.goto(base_url + "/academy/labs/LAB-MCP-001#predict")
    page.locator('input[name="predict-control"][value="UNSURE"]').check()
    page.locator('input[name="predict-execution"][value="UNSURE"]').check()
    page.get_by_role("button", name="Lock prediction and continue").click()
    page.get_by_role("button", name="Launch LIVE ATTACK").dblclick()
    status = page.locator('[data-run-status="ATTACK"]')
    _wait_status(page, "ATTACK", "Launch failed")
    assert len(posts) == 1
    assert posts[0] == {"lab_id": "LAB-MCP-001", "specimen_id": posts[0]["specimen_id"], "mode": "ATTACK", "execution": "live"}
    assert "ERROR, not a control decision" in status.inner_text()
    assert page.locator('[data-run-card="ATTACK"]').is_hidden()
    assert page.get_by_role("button", name="Launch LIVE ATTACK").is_enabled()
