"""Finding -> investigation notebook -> retest comparison in a real browser: the running React app against the real Attack Service routes, the real engine, a stub Splunk
and a fake search backend. Live-class events are CLONES of committed specimens (test-only). Screenshots go to docs/reviews/rc2/ui/investigation/.
SKIPPED without Playwright/Chromium (set AGENTSEC_CHROMIUM)."""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec import splunk_client as sc  # noqa: E402
from agentsec.academy_assurance import AssuranceService  # noqa: E402
from agentsec.academy_search import SearchService  # noqa: E402
from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402
from agentsec.loan_desk import search as srch  # noqa: E402
from tests.test_academy_assurance import FakeClient, NS  # noqa: E402
from tests.test_academy_investigation import live_pair, pair_run_ids  # noqa: E402
from tests.ui.test_assurance_academy_browser import NO_HSCROLL, axe  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401

OUT = Path(__file__).resolve().parents[2] / "docs/reviews/rc2/ui/investigation"
ROWS = [["1", "agentsec.run.started", "", "", ""], ["2", "agentsec.hop.started", "0", "", ""], ["3", "agentsec.control.decision", "0", "ALLOW", "false"]]


class Backend:
    name = "fake"

    def __init__(self, outcome=None):
        self.outcome = outcome or srch.Outcome(True, ["seq", "event", "hop", "decision", "executed"], ROWS, False, None, 21)
        self.calls = []

    def run(self, spl, *, timeout_s, max_rows):
        self.calls.append(spl)
        return self.outcome


@pytest.fixture
def stack(settings, monkeypatch):
    servers = []

    def start(client, backend="default"):
        b = Backend() if backend == "default" else backend
        monkeypatch.setattr(SearchService, "_default_backend", staticmethod(lambda env: b))
        app = create_app(AcmeBankClient("http://127.0.0.1:9"), assurance_service=AssuranceService(client_factory=lambda env: client))
        s = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
        return f"http://127.0.0.1:{s.server_port}", b
    yield start
    for s in servers:
        s.shutdown()


def live_ids(events):
    svc = AssuranceService(client_factory=lambda env: FakeClient(events))
    ds = svc._splunk("7d")[0]
    attack = next(f for f in ds.findings if f["run_id"] == str(uuid.uuid5(NS, "live-attack")) and f["mode"] == "ATTACK" and f["hop"] is not None)
    return attack


def shots(page, name):
    OUT.mkdir(parents=True, exist_ok=True)
    for w in (390, 768, 1366):
        page.set_viewport_size({"width": w, "height": 900})
        page.wait_for_timeout(150)
        assert page.evaluate(NO_HSCROLL), f"{name}@{w} scrolls horizontally"
        page.screenshot(path=str(OUT / f"{name}-{w}.png"), full_page=True)
    page.set_viewport_size({"width": 1366, "height": 900})


def loaded(page, path, base):
    page.goto(base + path)
    page.wait_for_selector("h1")
    page.wait_for_selector(".as-origin, .as-state, .as-cmp__sides, .as-hero, .as-seven", timeout=8000)


def in_dialog(page):
    return page.evaluate("document.querySelector('[role=dialog]').contains(document.activeElement)")


# ------------------------------------------------------------------ 1. the mobile raw-evidence drawer
def test_the_mobile_drawer_contains_scroll_traps_focus_both_ways_and_keeps_close_reachable(stack, page):
    f = live_ids(live_pair())
    base, _ = stack(FakeClient(live_pair()))
    page.set_viewport_size({"width": 390, "height": 600})
    loaded(page, f"/learn/assurance/finding/live/{f['finding_id']}", base)
    assert page.evaluate("document.documentElement.scrollHeight") > 1000                    # the page is long enough to scroll, so a locked page means something
    opener = page.get_by_role("link", name="Raw evidence")
    opener.focus(); page.keyboard.press("Enter")
    page.wait_for_selector("[role=dialog]")
    # fills the phone screen without overlapping anything, no sideways scroll inside it
    box = page.evaluate("(()=>{const b=document.querySelector('.as-drawer').getBoundingClientRect();return [b.x,b.y,b.width,b.height]})()")
    assert box[0] == 0 and box[2] <= 390 and abs(box[3] - 600) <= 1
    assert page.evaluate("(()=>{const d=document.querySelector('.as-drawer');return d.scrollWidth<=d.clientWidth})()")
    page.wait_for_timeout(500)                                                                  # the route change scrolls to the top; let it settle
    y0 = page.evaluate("window.scrollY")
    # the page behind does not scroll while it is open, and the drawer's own scroll does not chain into it
    assert page.evaluate("getComputedStyle(document.documentElement).overflow") == "hidden"
    page.mouse.move(200, 300); page.mouse.wheel(0, 3000); page.wait_for_timeout(250)
    assert page.evaluate("window.scrollY") == y0
    assert page.evaluate("getComputedStyle(document.querySelector('.as-drawer')).overscrollBehaviorY") == "contain"
    # Close stays reachable after the drawer content scrolls (sticky head), and is a 44px target
    page.locator("[role=dialog] details summary").first.click()
    page.evaluate("document.querySelector('.as-drawer').scrollTop = 99999")
    cb = page.evaluate("(()=>{const b=document.querySelector('.as-drawer__head button').getBoundingClientRect();return [b.top,b.height]})()")
    assert 0 <= cb[0] < 60 and cb[1] >= 40
    # focus never leaves, forward or backward, with every event closed and then with one open
    for combo in ("Tab", "Shift+Tab"):
        for _ in range(45):
            page.keyboard.press(combo)
            assert in_dialog(page), combo
            assert page.evaluate("document.activeElement.getClientRects().length > 0"), f"{combo} focused something hidden"
    axe(page, "drawer-mobile")
    page.screenshot(path=str(OUT.parent / "assurance" / "03-raw-evidence-mobile-open.png")) if (OUT.parent / "assurance").exists() else None
    page.keyboard.press("Escape")
    page.wait_for_selector("[role=dialog]", state="detached")
    assert page.evaluate("getComputedStyle(document.documentElement).overflow") != "hidden"
    assert page.evaluate("document.activeElement.textContent.includes('Raw evidence')")


# ------------------------------------------------------------------ 2. finding -> notebook, run context preserved, exact SPL, results
def test_the_finding_opens_a_notebook_bound_to_its_run_control_hop_and_class_and_runs_only_the_fixed_search(stack, page):
    ev = live_pair()
    f = live_ids(ev)
    base, backend = stack(FakeClient(ev))
    loaded(page, f"/learn/assurance/finding/live/{f['finding_id']}", base)
    page.get_by_role("link", name="Investigate in the notebook").click()
    page.wait_for_selector(".as-origin")
    assert page.url.endswith(f"/finding/live/{f['finding_id']}/investigate")
    txt = page.locator(".as-origin").inner_text()
    assert f["control_id"].lower() in txt.lower() or "guarded by" in txt
    assert "LIVE" in page.locator(".as-badges").inner_text()
    page.locator(".as-origin summary").click()
    ids = page.locator(".as-ids").inner_text()
    assert f["run_id"] in ids and f["control_id"] in ids and f["finding_id"] in ids and "LIVE" in ids
    spl = page.locator(".query-block pre").first.inner_text()
    assert f'"agentsec.run.id"="{f["run_id"]}"' in spl and spl.startswith("index=agentsec_telemetry") and "head 20" in spl
    assert page.locator("textarea[readonly], .query-block textarea").count() == 0                       # the search is not editable
    first = page.locator(".notebook-cell").first
    assert first.locator(".m-nb-state").inner_text().strip() == "READY"
    first.get_by_role("button", name="Run search").click()
    first.locator("table").wait_for(timeout=8000)
    assert first.locator(".m-nb-state").inner_text().strip() == "COMPLETED" and first.locator("tbody tr").count() == len(ROWS)
    assert backend.calls and backend.calls[0] == spl                                                    # exactly the text that was shown
    assert "evidence: LIVE" in first.locator("caption").inner_text()
    assert first.get_by_role("button", name="Copy the SPL").is_visible()
    axe(page, "notebook")
    shots(page, "01-notebook-live")


def test_a_result_with_no_rows_a_failed_search_and_missing_access_are_three_different_states(stack, page):
    ev = live_pair()
    f = live_ids(ev)
    path = f"/learn/assurance/finding/live/{f['finding_id']}/investigate"

    base, _ = stack(FakeClient(ev), Backend(srch.Outcome(True, ["seq"], [], False, None, 4)))
    loaded(page, path, base)
    c = page.locator(".notebook-cell").first
    c.get_by_role("button", name="Run search").click()
    c.locator(".m-nb-state:has-text('EMPTY')").wait_for(timeout=8000)
    assert "not a pass" in c.locator(".m-nb-status").inner_text()

    base, _ = stack(FakeClient(ev), Backend(srch.Outcome(False, error="timeout")))
    loaded(page, path, base)
    c = page.locator(".notebook-cell").first
    c.get_by_role("button", name="Run search").click()
    c.locator(".m-nb-state:has-text('FAILED')").wait_for(timeout=8000)
    assert "too long" in c.locator(".m-nb-status").inner_text() and c.locator("table").count() == 0

    base, _ = stack(FakeClient(ev), None)
    loaded(page, path, base)
    c = page.locator(".notebook-cell").first
    assert c.get_by_role("button", name="Run search").is_disabled()
    assert "not set up" in page.locator(".notebook-cell").first.inner_text() and "not a pass" in page.locator(".notebook-cell").first.inner_text()
    assert c.locator(".m-nb-state").inner_text().strip() == "NOT READY"
    shots(page, "02-notebook-no-access")


def test_an_unreadable_splunk_an_unknown_finding_and_a_bad_id_say_so_and_offer_a_way_back(stack, page):
    base, _ = stack(FakeClient(error=sc.SplunkError("connectivity", "connect_failed")))
    loaded(page, "/learn/assurance/finding/live/F-0123456789ab/investigate", base)
    assert page.locator("h1").inner_text() == "Nothing was read" and "not a pass" in page.locator(".as-state").inner_text()
    loaded(page, "/learn/assurance/finding/live/F-0123456789ab/compare", base)
    assert page.locator("h1").inner_text() == "Nothing was read"
    base, _ = stack(FakeClient(live_pair()))
    loaded(page, "/learn/assurance/finding/live/F-000000000000/investigate", base)
    assert "not in this view" in page.locator("h1").inner_text() and page.get_by_role("link", name="Back to the overview").is_visible()
    page.goto(base + "/learn/assurance/finding/live/not-an-id/investigate")
    page.wait_for_selector("h1")
    assert "does not exist" in page.locator("h1").inner_text()


# ------------------------------------------------------------------ 3. notes persist; workshop defend/retest handoff keeps the run
def test_notes_persist_and_the_workshop_handoff_adopts_the_live_run(stack, page):
    ev = live_pair()
    f = live_ids(ev)
    base, _ = stack(FakeClient(ev))
    path = f"/learn/assurance/finding/live/{f['finding_id']}/investigate"
    loaded(page, path, base)
    c = page.locator(".notebook-cell").first
    c.get_by_label("Before you run it", exact=False).fill("I expect an ALLOW")
    c.get_by_label("What did you notice?", exact=False).fill("the decision came first")
    page.reload(); page.wait_for_selector(".notebook-cell")
    c = page.locator(".notebook-cell").first
    assert c.get_by_label("Before you run it", exact=False).input_value() == "I expect an ALLOW"
    assert c.get_by_label("What did you notice?", exact=False).input_value() == "the decision came first"
    c.get_by_role("button", name="Reset cell").click()
    assert c.get_by_label("Before you run it", exact=False).input_value() == ""
    nxt = page.locator(".as-next").inner_text()
    assert "What to do" in nxt and "How to retest" in nxt
    page.get_by_role("button", name="Go to the workshop with this run").click()
    page.wait_for_selector("h1")
    assert "/learn/lab/" in page.url
    stored = json.loads(page.evaluate("window.localStorage.getItem('agentsec.learn.v1')"))
    runs = next(iter(stored["workbench"].values()))["runs"]
    assert runs["attack"] == f["run_id"]


# ------------------------------------------------------------------ 4. recorded wording and local cells
def test_recorded_evidence_is_findings_to_explore_with_local_cells_and_no_spl(stack, page):
    _, _, rf = pair_run_ids()
    base, _ = stack(FakeClient([]))
    loaded(page, "/learn/assurance/recorded", base)
    h1 = page.locator("h1").inner_text()
    assert "to explore" in h1 and "attention" not in h1.lower()
    body = page.locator(".as-hero").inner_text()
    assert "Investigate" not in body and "Needs a retest" not in body and "Explore" in body
    loaded(page, f"/learn/assurance/finding/recorded/{rf['finding_id']}/investigate", base)
    assert page.locator(".eyebrow").first.text_content() == "Explore the evidence" and "RECORDED" in page.locator(".as-badges").inner_text()
    c = page.locator(".notebook-cell").first
    assert "NO SPL" in c.locator(".query-block").inner_text() and c.get_by_role("button", name="Copy the SPL").count() == 0
    c.get_by_role("button", name="Show the table").click()
    c.locator("table").wait_for(timeout=8000)
    assert "no search ran" in c.locator("caption").inner_text() and "evidence: RECORDED" in c.locator("caption").inner_text()
    assert "defended or retested here" in page.locator(".as-next").inner_text()
    axe(page, "notebook-recorded")
    shots(page, "03-notebook-recorded")


# ------------------------------------------------------------------ 5. retest comparison
def test_the_comparison_shows_both_linked_runs_per_hop_and_repeats_the_rules_outcome(stack, page):
    _, r_id, rf = pair_run_ids()
    base, _ = stack(FakeClient([]))
    loaded(page, f"/learn/assurance/finding/recorded/{rf['finding_id']}/compare", base)
    assert "Attack and retest, side by side" in page.locator("h1").inner_text()
    assert "Outcome by the rules: VALIDATED" in page.locator(".as-badges").inner_text() and "RECORDED" in page.locator(".as-badges").inner_text()
    assert page.locator(".as-cmp__side").count() == 2 and page.locator(".as-cmp__table tbody tr").count() >= 1
    assert r_id[:8] in page.locator(".as-cmp__sides").inner_text()
    assert "No effectiveness figure is computed" in page.inner_text("body")
    page.get_by_role("link", name="Open this finding").nth(1).click()
    page.wait_for_selector(".as-seven")
    assert "RETEST" in page.locator(".as-badges").inner_text()
    axe(page, "compare")
    loaded(page, f"/learn/assurance/finding/recorded/{rf['finding_id']}/compare", base)
    shots(page, "04-compare-recorded")


def test_live_comparison_and_the_missing_or_incomplete_retest_states(stack, page):
    ev = live_pair()
    f = live_ids(ev)
    base, _ = stack(FakeClient(ev))
    loaded(page, f"/learn/assurance/finding/live/{f['finding_id']}/compare", base)
    assert page.locator(".as-cmp__sides").is_visible() and "LIVE" in page.locator(".as-badges").inner_text()
    shots(page, "05-compare-live")
    # a live attack with only recorded retests available: nothing is compared and nothing is claimed
    from tests.test_academy_assurance import clone, recorded_by_run
    from agentsec.academy_assurance import recorded_events
    a_id, _, _ = pair_run_ids()
    base, _ = stack(FakeClient(clone(recorded_by_run()[a_id], "live-attack", time.time() - 3600) + recorded_events()))
    loaded(page, f"/learn/assurance/finding/live/{f['finding_id']}/compare", base)
    assert "No retest to compare yet" in page.locator("h1").inner_text() and "never validates a live attack" in page.locator(".as-state").inner_text()
    shots(page, "06-compare-no-retest")
    # an incomplete retest is flagged and not presented as a comparison
    inc = live_pair(drop_from_retest=1)
    base, _ = stack(FakeClient(inc))
    loaded(page, f"/learn/assurance/finding/live/{live_ids(inc)['finding_id']}/compare", base)
    assert "incomplete" in page.locator("h1").inner_text().lower() and page.locator(".as-gapnote").count() >= 1
    shots(page, "07-compare-incomplete")
    # a baseline run has nothing to compare
    from agentsec.assurance import engine as E
    ds = AssuranceService()._recorded()
    b = next(x for x in ds.findings if x["mode"] == "BASELINE")
    base, _ = stack(FakeClient([]))
    loaded(page, f"/learn/assurance/finding/recorded/{b['finding_id']}/compare", base)
    assert "nothing to compare" in page.locator("h1").inner_text()


def test_keyboard_alone_reaches_every_notebook_control_and_the_finding_links_to_it(stack, page):
    ev = live_pair()
    f = live_ids(ev)
    base, _ = stack(FakeClient(ev))
    loaded(page, f"/learn/assurance/finding/live/{f['finding_id']}", base)
    page.get_by_role("link", name="Investigate in the notebook").focus()
    page.keyboard.press("Enter")
    page.wait_for_selector(".as-origin")
    seen = set()
    for _ in range(80):
        page.keyboard.press("Tab")
        seen.add(page.evaluate("(document.activeElement.id || document.activeElement.textContent || '').trim().slice(0, 30)"))
    assert any("Run search" in s for s in seen) and any("Reset cell" in s for s in seen) and any("Go to the workshop" in s for s in seen) and any("Compare with the retest" in s for s in seen)
    assert any(s.endswith("-hypo") for s in seen) and any(s.endswith("-concl") for s in seen)
