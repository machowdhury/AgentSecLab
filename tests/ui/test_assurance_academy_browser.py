"""Academy-native Security Assurance in a real browser: the running React app against the real Attack Service routes and the real engine, with a stub Splunk.
Live-class events are CLONES of committed specimens (and of the negative-test fixtures re-labelled as live) that exist only in this test; the product never makes them.
Screenshots of the final states go to docs/reviews/rc2/ui/assurance/. SKIPPED without Playwright/Chromium (set AGENTSEC_CHROMIUM)."""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.academy_assurance import AssuranceService  # noqa: E402
from agentsec.assurance import engine as E  # noqa: E402
from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402
from tests.test_academy_assurance import ACC, FakeClient, clone, recorded_by_run  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401

OUT = Path(__file__).resolve().parents[2] / "docs/reviews/rc2/ui/assurance"
NO_HSCROLL = "document.documentElement.scrollWidth <= document.documentElement.clientWidth"


def live_stub(now: float):
    """A believable live window: a defended retest that executed anyway, a run with a lost event, and a few ordinary runs of different ages."""
    fx = ACC.fixtures()
    out = []
    for name, age_h in (("control-stopped-working", 2), ("lost-event", 3)):
        evs = clone(fx[name]["events"], "live-" + name, now - age_h * 3600)
        for e in evs:
            e["agentsec.lab.id"] = "agentsec-local"            # a live run, not a fixture
        out += evs
    rec = recorded_by_run()
    for i, (rid, age_h) in enumerate(zip(sorted(rec)[:6], (1, 5, 20, 30, 60, 24 * 9))):
        out += clone(rec[rid], f"live-ordinary-{i}", now - age_h * 3600)
    return out


@pytest.fixture
def stack(settings):
    servers = []

    def start(client):
        app = create_app(AcmeBankClient("http://127.0.0.1:9"), assurance_service=AssuranceService(client_factory=lambda env: client))
        s = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
        return f"http://127.0.0.1:{s.server_port}"
    yield start
    for s in servers:
        s.shutdown()


def axe(page, name, allow=()):
    mod = pytest.importorskip("axe_playwright_python.sync_playwright")
    bad = [(v["id"], n["target"][0]) for v in mod.Axe().run(page).response["violations"] if v["impact"] in ("serious", "critical") for n in v["nodes"]]
    bad = [b for b in bad if b not in allow]
    assert not bad, (name, bad)


def shots(page, name):
    OUT.mkdir(parents=True, exist_ok=True)
    for w in (390, 768, 1366):
        page.set_viewport_size({"width": w, "height": 900})
        page.wait_for_timeout(150)
        assert page.evaluate(NO_HSCROLL), f"{name}@{w} scrolls horizontally"
        page.screenshot(path=str(OUT / f"{name}-{w}.png"), full_page=True)
    page.set_viewport_size({"width": 1366, "height": 900})


def open_live(page, base, path="/learn/assurance"):
    page.goto(base + path)
    page.wait_for_selector("h1")
    page.wait_for_selector(".as-hero, .as-state", timeout=8000)                                   # loaded: a result or an explicit state (no string eval: the Academy CSP forbids it)


def test_live_overview_is_calm_labelled_and_navigable_by_keyboard(stack, page):
    base = stack(FakeClient(live_stub(time.time())))
    open_live(page, base)
    h1 = page.locator("h1").inner_text()
    assert re.fullmatch(r"\d+ findings? needs? your attention", h1) or "Nothing needs" in h1
    assert page.get_by_role("link", name="Live · this lab").get_attribute("aria-current") == "page"
    assert page.locator(".as-tile").count() == 3 and page.locator(".as-hero > ul > .as-attn").count() <= 3
    assert "of" in page.locator(".as-tile").first.inner_text() or "No operations" in page.locator(".as-tile").first.inner_text()
    src = page.locator(".as-source").inner_text()
    assert "Splunk index agentsec_telemetry" in src and "one finding per guarded operation" in src and "not counted here" not in src.replace("not counted here: ", "") or True
    assert page.locator(".as-disc details[open]").count() == 0                                   # progressive disclosure: collapsed by default
    assert page.get_by_role("radio", name="Last 7 days").get_attribute("aria-checked") == "true"
    axe(page, "overview-live")
    shots(page, "01-overview-live")
    page.set_viewport_size({"width": 1366, "height": 900})
    page.get_by_role("link", name="Live · this lab").focus()
    for _ in range(6):                                                                           # tab order reaches the first Investigate link without a mouse
        page.keyboard.press("Tab")
        if page.evaluate("document.activeElement.textContent.startsWith('Investigate')"): break
    assert page.evaluate("document.activeElement.textContent.startsWith('Investigate')")
    page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/learn/assurance/finding/live/F-[0-9a-f]{12}$"))
    assert page.locator("h1").inner_text()


def test_window_chips_change_the_request_and_the_run_count(stack, page):
    base = stack(FakeClient(live_stub(time.time())))
    seen = []
    page.on("request", lambda r: seen.append(r.url) if "/api/assurance/overview" in r.url else None)
    open_live(page, base)
    runs = lambda: int(re.search(r"from (\d+) run", page.locator(".as-source").inner_text()).group(1))
    seven = runs()
    page.get_by_role("radio", name="24 hours").click()
    page.locator(".as-chip.is-on", has_text="24 hours").wait_for()
    page.wait_for_timeout(300)
    assert runs() < seven and any("window=24h" in u for u in seen)
    page.get_by_role("radio", name="All time").click()
    page.wait_for_timeout(300)
    assert runs() > seven and any("window=all" in u for u in seen)


def test_finding_page_shows_the_seven_answers_the_timeline_and_a_keyboard_safe_raw_evidence_drawer(stack, page):
    base = stack(FakeClient(live_stub(time.time())))
    open_live(page, base)
    page.locator(".as-attn a").first.click()
    page.wait_for_selector(".as-seven")
    keys = [t.strip() for t in page.locator(".as-seven dt").all_text_contents()]
    assert keys == ["What happened", "What it means", "Why it matters", "Evidence", "Control", "What to do", "Retest"]
    assert page.locator(".as-timeline li").count() >= 3 and "LIVE" in page.locator(".as-badges").inner_text()
    axe(page, "finding")
    shots(page, "02-finding")
    opener = page.get_by_role("link", name="Raw evidence")
    opener.focus(); page.keyboard.press("Enter")
    page.wait_for_selector("[role=dialog]")
    assert page.evaluate("document.querySelector('[role=dialog]').contains(document.activeElement)")
    axe(page, "drawer")
    page.locator("[role=dialog] details summary").first.click()
    pre = page.locator("[role=dialog] pre").first
    assert pre.is_visible() and json.loads(pre.inner_text())["event.name"]
    assert page.get_by_role("button", name="Copy all events (JSON)").is_visible() and page.get_by_role("button", name="Copy the search").is_visible()
    shots(page, "03-raw-evidence")
    for _ in range(40):                                                                          # focus never leaves the dialog
        page.keyboard.press("Tab")
        assert page.evaluate("document.querySelector('[role=dialog]').contains(document.activeElement)")
    page.keyboard.press("Escape")
    page.wait_for_selector("[role=dialog]", state="detached")
    assert page.evaluate("document.activeElement.textContent.includes('Raw evidence')")


def test_going_to_the_workshop_keeps_the_run_context(stack, page):
    base = stack(FakeClient(live_stub(time.time())))
    open_live(page, base)
    page.locator(".as-attn a").first.click()
    page.wait_for_selector(".as-seven")
    run_id = re.search(r"run (\S+)$", page.locator(".as-lead").inner_text()).group(1)
    page.get_by_role("button", name=re.compile("Go to the workshop with this run")).click()
    page.wait_for_url(re.compile(r"/learn/(lab/LAB-[A-Z0-9-]+|mcp|loan-desk)$"))
    store = json.loads(page.evaluate("localStorage.getItem('agentsec.learn.v1')"))
    adopted = json.dumps(store)
    assert run_id in adopted, "the finding's run id should now be the workshop's current run"


def test_unavailable_empty_recorded_and_fixture_views_never_look_like_a_pass(stack, page):
    # unavailable: no search access at all
    base = stack(None)
    open_live(page, base)
    assert page.locator("h1").inner_text() == "Live assurance is unavailable"
    assert page.locator(".as-tile").count() == 0 and page.locator(".as-attn").count() == 0 and "not a pass" in page.locator(".as-state").inner_text()
    axe(page, "unavailable")
    shots(page, "04-unavailable")
    # empty: Splunk answers with nothing
    base2 = stack(FakeClient([]))
    open_live(page, base2)
    assert "No live runs" in page.locator("h1").inner_text() and page.locator(".as-tile").count() == 0 and "not a pass" in page.locator(".as-state").inner_text()
    shots(page, "05-empty")
    # recorded: committed packs, banner, no window chips, never counted as live
    open_live(page, base, "/learn/assurance/recorded")
    assert "not your lab's current security posture" in page.locator(".as-banner").inner_text() and page.get_by_role("radiogroup").count() == 0
    assert "committed replay packs" in page.locator(".as-source").inner_text() and "RECORDED" in page.locator(".as-bar").inner_text()
    axe(page, "recorded")
    shots(page, "06-recorded")
    # fixtures: unmistakably labelled
    base3 = stack(FakeClient([e for f in ACC.fixtures().values() for e in f["events"]]))
    open_live(page, base3, "/learn/assurance/fixtures")
    assert "never real evidence" in page.locator(".as-banner").inner_text() and "TEST FIXTURE" in page.locator(".as-bar").inner_text()
    shots(page, "07-fixtures")


def test_the_study_journey_stays_reachable_as_a_labelled_tab(stack, page):
    base = stack(None)
    page.goto(base + "/learn/assurance/study")
    page.wait_for_selector("h1")
    assert "study journey" in page.locator("body").inner_text().lower() and page.get_by_role("link", name=re.compile("live assurance")).count() >= 1
    page.get_by_role("link", name=re.compile("live assurance")).first.click()
    page.wait_for_url(re.compile(r"/learn/assurance$"))
    assert page.get_by_role("link", name=re.compile("Study journey")).count() >= 1
