"""Unified Academy experience, in a real browser, for all 33 workshops (the Orientation and the 32 registered labs), against the real Attack Service and AcmeBank in this process.

(1) Every workshop shows its catalog evidence mode and only what that mode supports: LIVE workshops show the eight-stage rail with an in-Academy Investigate stage and no
launch control appears on a RECORDED or SIMULATED one; no workshop links to the legacy Attack UI. (2) The LIVE flow is completed end to end with real launches: predict,
baseline, attack, investigate (the notebook finds the learner's own run through a stub Splunk fed from the run's own event record), defend, retest, explain.
SKIPPED without Playwright and Chromium (set AGENTSEC_CHROMIUM)."""
from __future__ import annotations

import csv
import io
import json
import re
import threading
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.academy_assurance import AssuranceService  # noqa: E402
from agentsec.academy_search import SearchService  # noqa: E402
from agentsec.attack_app import AcmeBankClient, create_app as create_attack  # noqa: E402
from agentsec.bank_app import build_runtime, create_app as create_bank  # noqa: E402
from agentsec.loan_desk import search as srch  # noqa: E402
from tests.test_workshop_unified_acceptance import GUIDES, LIVE, MODE  # noqa: E402
from tests.ui.test_assurance_academy_browser import axe  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser, page  # noqa: E402,F401
from tests.ui.test_scenario_workbench_browser import lock as lock_scenario  # noqa: E402

STAGES = ["Learn", "Predict", "Baseline", "Attack", "Investigate", "Defend", "Retest", "Explain evidence"]
ROWS = [["1", "agentsec.run.started", "", "", ""], ["2", "agentsec.control.decision", "0", "DENY", "false"], ["3", "agentsec.hop.completed", "0", "", ""]]
LAUNCH_BUTTON = re.compile(r"^(Launch|Run) (BASELINE|ATTACK|RETEST)")


class Backend:
    name = "fake"

    def __init__(self):
        self.calls = []

    def run(self, spl, *, timeout_s, max_rows):
        self.calls.append(spl)
        return srch.Outcome(True, ["seq", "event", "hop", "decision", "executed"], ROWS, False, None, 17)


class ArtifactsSplunk:
    """A stub Splunk that holds exactly what the runs wrote to their own event record (what the collector would have indexed)."""
    def __init__(self, root: Path):
        self.root = root

    def export_csv(self, spl, *, timeout_s=None, max_bytes=None):
        buf = io.StringIO(); w = csv.writer(buf); w.writerow(["_raw"])
        for p in sorted(self.root.glob("*/events.jsonl")):
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    w.writerow([line])
        return buf.getvalue()


@pytest.fixture
def stack(settings, monkeypatch):
    servers, backend = [], Backend()
    monkeypatch.setattr(SearchService, "_default_backend", staticmethod(lambda env: backend))
    bank = make_server("127.0.0.1", 0, create_bank(build_runtime(settings, otel_enabled=False)), threaded=True)
    assurance = AssuranceService(client_factory=lambda env: ArtifactsSplunk(settings.artifacts_dir), ttl_s=0)
    attack = make_server("127.0.0.1", 0, create_attack(AcmeBankClient(f"http://127.0.0.1:{bank.server_port}"), assurance_service=assurance), threaded=True)
    for s in (bank, attack):
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
    yield f"http://127.0.0.1:{attack.server_port}", backend
    for s in servers:
        s.shutdown()


def path_of(lab: str) -> str:
    return {"LAB-LOANDESK-001": "/learn/loan-desk/learn", "LAB-MCP-001": "/learn/mcp"}.get(lab, f"/learn/lab/{lab}")


def rail(pg):
    return pg.locator(".uw-rail li")


def open_practice(pg):
    t = pg.get_by_role("tab", name=re.compile("Practice"))
    if t.count():
        t.click()


# ------------------------------------------------------------------ 1. all 33 workshops, mode by mode
def test_the_orientation_is_reading_only(page, stack):
    base, _ = stack
    page.goto(base + "/learn/foundations")
    page.wait_for_selector("h1")
    assert page.get_by_role("button", name=LAUNCH_BUTTON).count() == 0 and page.locator("a[href*=':5001'], a[href*='/attack-service']").count() == 0
    axe(page, "orientation")


@pytest.mark.parametrize("lab", sorted(MODE))
def test_each_workshop_shows_its_mode_and_only_what_the_mode_supports(page, stack, lab):
    base, _ = stack
    mode = MODE[lab]
    page.goto(base + path_of(lab))
    page.wait_for_selector("h1")
    if lab not in ("LAB-LOANDESK-001", "LAB-MCP-001"):
        assert page.locator(".page-header .badge", has_text=re.compile(f"^{mode}$")).count() == 1, "the page names the catalog mode"
    if mode == "LIVE":
        assert rail(page).locator(".uw-l").all_inner_texts() == STAGES
        assert rail(page).count() == 8
        if lab == "LAB-LOANDESK-001":
            rail(page).nth(4).locator("button").dispatch_event("click")                           # Investigate is locked until the attack ran: said, not silently ignored
            assert "locked" in page.locator("[role=alert]").first.inner_text().lower()
        else:
            rail(page).nth(4).locator("button").click()
            sec = page.locator('[data-stage="investigate"]')
            sec.wait_for(timeout=5000)
            txt = sec.inner_text()
            assert "Run the attack first" in txt and not re.search(r"Run each search in Splunk|in your own Splunk", txt)
            if lab != "LAB-MCP-001":
                assert "Investigate" in sec.locator("h3").inner_text() and "stage 5 of 8" in sec.locator("h3").inner_text()
    else:
        assert rail(page).count() == 0, "no launch stages on a workshop that cannot launch"
        open_practice(page)
        assert page.get_by_role("button", name=LAUNCH_BUTTON).count() == 0
    assert page.locator("a[href*=':5001'], a[href*='/attack-service']").count() == 0
    axe(page, f"workshop-{lab}")


@pytest.mark.parametrize("lab", sorted(GUIDES))
def test_the_finish_section_never_sends_the_learner_out_of_the_academy(page, stack, lab):
    base, _ = stack
    page.goto(base + path_of(lab) if lab not in ("LAB-LOANDESK-001", "LAB-MCP-001") else base + f"/learn/lab/{lab}")
    page.wait_for_selector("h1")
    fin = page.locator("section[aria-label='Finish this workshop']")
    if fin.count():
        assert not re.search(r"Studio|ws_lab|Splunk Search|search Splunk|Attack Service UI|:5001", fin.inner_text(), re.I)


# ------------------------------------------------------------------ 2. the LIVE flow, end to end, with real launches
def investigate(pg, lab):
    sec = pg.locator('[data-stage="investigate"]')
    sec.scroll_into_view_if_needed()
    cell = sec.locator(".notebook-cell").first
    cell.wait_for(timeout=15000)
    assert cell.locator(".m-nb-state").inner_text().strip() == "READY"
    spl = cell.locator(".query-block pre").first.inner_text()
    assert spl.startswith("index=agentsec_telemetry") and re.search(r'"agentsec.run.id"="[0-9a-f-]{36}"', spl)
    cell.get_by_role("button", name="Run search").click()
    cell.locator("table").wait_for(timeout=15000)
    assert cell.locator(".m-nb-state").inner_text().strip() == "COMPLETED" and cell.locator("tbody tr").count() == len(ROWS)
    assert cell.locator(".m-bars li").count() >= 1 and "what these rows say" in cell.inner_text().lower()
    return spl


def test_live_goal_integrity_flow_from_predict_to_explain_with_real_launches(page, stack):
    base, backend = stack
    lab = "LAB-AGENT-GOAL-INTEGRITY-001"
    page.goto(base + f"/learn/lab/{lab}")
    page.wait_for_selector("h1")
    page.get_by_role("tab", name=re.compile("Practice")).click()
    assert rail(page).nth(0).locator(".uw-s").inner_text().startswith("next") or rail(page).nth(0).locator(".uw-s").inner_text().startswith("to do")
    page.get_by_role("button", name=re.compile("Run BASELINE")).click()
    page.wait_for_selector("text=NORMAL TASK, IN-TASK TOOL USE")
    lock_scenario(page, lab)
    page.get_by_role("button", name=re.compile("Launch ATTACK")).click()
    page.wait_for_selector("text=AUTHORIZED TOOL RAN FOR AN UNAUTHORIZED GOAL")
    spl = investigate(page, lab)
    assert backend.calls and backend.calls[-1] == spl                                          # the text that was shown is the text that was sent
    page.get_by_role("button", name=re.compile("Run RETEST")).click()
    page.wait_for_selector("text=GOAL EXPANSION DENIED, AUTHORIZED TASK KEPT")
    assert page.locator('[data-stage="retest"]').get_by_role("link", name="Compare the attack with its retest").count() == 1
    page.locator(f"#{lab}-explain").fill("The control denied the expansion on retest; the notebook rows show the decision, not who was right.")
    done = [t.strip() for t in rail(page).locator(".uw-s").all_inner_texts()]
    assert len(done) == 8 and all(x.startswith("done") for x in done), done
    state = json.loads(page.evaluate("window.localStorage.getItem('agentsec.learn.v1')"))["workbench"][lab]
    assert state["investigated"] is True and state["explain"].startswith("The control denied")


def test_live_mcp_tool_authorization_flow_from_predict_to_explain_with_real_launches(page, stack):
    base, backend = stack
    page.goto(base + "/learn/mcp")
    page.wait_for_selector("h1")
    page.get_by_label("DENY", exact=True).check()
    page.get_by_role("button", name="Lock prediction").click()
    page.get_by_role("button", name=re.compile("Launch BASELINE")).click()
    page.wait_for_selector('[data-stage="baseline"] .m-run')
    page.get_by_role("button", name=re.compile("Launch ATTACK")).click()
    page.wait_for_selector('[data-stage="attack"] .m-run')
    investigate(page, "LAB-MCP-001")
    page.get_by_role("button", name=re.compile("Launch RETEST")).click()
    page.wait_for_selector('[data-stage="retest"] .m-run')
    page.locator("#LAB-MCP-001-explain").fill("The defended profile denied the request before the handler started.")
    assert all("done" in t for t in rail(page).locator(".uw-s").all_inner_texts()), rail(page).locator(".uw-s").all_inner_texts()
    page.wait_for_timeout(900)                                                                  # the outcome cards fade in; axe must measure the settled colours
    axe(page, "mcp-flow")


def test_the_flow_bar_points_at_the_workshop_the_learner_is_in(page, stack):
    base, _ = stack
    page.goto(base + "/learn/lab/LAB-MCP-003")
    page.wait_for_selector("h1")
    page.locator(".wf").get_by_role("link", name="Attack").click()
    assert "/learn/lab/LAB-MCP-003" in page.url and "loan-desk" not in page.url
    page.wait_for_selector('[data-stage="attack"]')
    page.goto(base + "/learn/lab/LAB-HITL-APPROVAL")
    page.wait_for_selector("h1")
    assert page.locator(".wf").get_by_role("link", name="Attack").count() == 0                  # nothing to attack in a simulated workshop
    page.goto(base + "/learn/loan-desk/learn")
    page.wait_for_selector("h1")
    assert page.locator(".wf").get_by_role("link", name="Attack").get_attribute("href").endswith("/loan-desk/attack")
