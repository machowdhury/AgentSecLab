"""Phase 1 learner-UX P0 contracts (LAB-MCP-001).

These tests pin deterministic repository behavior. They do not execute SPL, do
not load a browser, and do not prove how a learner experiences the page. Browser
behavior is measured separately and reported as MEASURED / OBSERVED evidence.

Threat          a learner is taught a false claim by the surface itself
Asset           the learner's mental model of ALLOW vs execution, LIVE vs REPLAY
Trust boundary  Workbench (Flask :5001) -> Splunk Dashboard Studio (:8000)
Invariants      ALLOW != execution; DENY != secure; RETEST != universal security;
                REPLAY is not a newly measured live experiment
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from agentsec.attack_app import MCP_BASELINE_REPLAY_RUN_ID, create_app
from agentsec.search_handoff import STUDIO_URL_PREFILL_STATUS, handoff_doc, investigate_url

ROOT = Path(__file__).resolve().parents[2]
DEFINITION = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json"
BUILDER = ROOT / "scripts" / "build_lab_mcp_001_dashboard.py"
FLOW_SVG = ROOT / "splunk_app" / "agentsec" / "appserver" / "static" / "flows" / "flow-lab-mcp-001.svg"
LEARNER_PATH_JS = ROOT / "splunk_app" / "agentsec" / "appserver" / "static" / "agentsec_learner_path.js"
WORKBENCH_CSS = ROOT / "src" / "agentsec" / "static" / "agentsec-workbench.css"

WORKSHOP = json.loads(DEFINITION.read_text(encoding="utf-8"))
VIZ = WORKSHOP["visualizations"]

RUN_ID = "11111111-2222-3333-4444-555555555555"


def _builder():
    spec = importlib.util.spec_from_file_location("build_lab_mcp_001_dashboard", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _md(viz_id: str) -> str:
    return VIZ[viz_id]["options"]["markdown"]


def _all_markdown() -> str:
    return "\n".join(v["options"]["markdown"] for v in VIZ.values() if v.get("type") == "splunk.markdown")


@pytest.fixture(scope="module")
def workbench() -> str:
    response = create_app().test_client().get("/labs/LAB-MCP-001")
    assert response.status_code == 200
    return response.get_data(as_text=True)


# --- P0-A: mode-neutral notebook prose -------------------------------------


def test_notebook_prose_does_not_assume_the_attack_specimen():
    """BASELINE is a normal run; prose must not say it requested the ungranted tool."""
    header = _md("viz_nb_header")
    # The ungranted tool may be named as an example, but never as this run's fact.
    assert "Whether the run you are reading requested a granted tool" in header
    assert "Do not decide from the name of the specimen" in header
    for claim in ("this run requested lookup_customer_tier", "the agent requested lookup_customer_tier", "the attack run"):
        assert claim not in header.lower()
    for n in range(1, 6):
        question = _md(f"viz_nb{n}_q")
        assert "the agent requested lookup_customer_tier" not in question


# --- P0-B: LIVE deep link ---------------------------------------------------


def test_investigate_url_is_form_prefixed_tab_pinned_and_encoded():
    url = investigate_url("LAB-MCP-001", RUN_ID)
    assert url is not None
    parts = urlsplit(url)
    assert parts.path == "/en-US/app/agentsec/ws_lab_mcp_001"
    query = parse_qs(parts.query, keep_blank_values=True)
    assert query == {"tab": ["layout_investigate"], "form.live_run_id": [RUN_ID]}


def test_unprefixed_token_is_never_generated():
    """Unprefixed live_run_id= was measured to be ignored; do not rely on it."""
    for url in (investigate_url("LAB-MCP-001", RUN_ID), handoff_doc(RUN_ID, lab_id="LAB-MCP-001")["investigate_url"]):
        assert re.search(r"(?<![.\w])live_run_id=", url) is None


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "none",
        "not-a-uuid",
        "ABCDEF12-2222-3333-4444-555555555555",
        RUN_ID + " | delete",
        RUN_ID + '" | rest /services',
        "1111111-2222-3333-4444-555555555555",
        RUN_ID + "&form.run_id=x",
        "../../etc/passwd",
        "*",
        None,
        12345,
    ],
)
def test_investigate_url_rejects_anything_that_is_not_a_canonical_uuid(bad):
    """The value lands in a Studio token that is substituted into SPL."""
    assert investigate_url("LAB-MCP-001", bad) is None


def test_investigate_url_is_only_offered_for_labs_with_a_live_input():
    assert investigate_url("LAB-UNKNOWN", RUN_ID) is None
    assert investigate_url(None, RUN_ID) is None
    doc = handoff_doc(RUN_ID, lab_id="LAB-UNKNOWN")
    assert doc["investigate_url"] is None
    assert "NOT AVAILABLE" in doc["investigate_url_status"]


def test_deep_link_is_classified_honestly_and_binding_stays_unsupported():
    doc = handoff_doc(RUN_ID, lab_id="LAB-MCP-001")
    assert doc["investigate_url_status"] == STUDIO_URL_PREFILL_STATUS
    assert "SUPPORTED WITH CONSTRAINTS" in STUDIO_URL_PREFILL_STATUS
    assert "not located in Splunk documentation" in STUDIO_URL_PREFILL_STATUS
    assert doc["studio_token_binding"] == "NOT SUPPORTED / DO NOT BUILD"
    assert "live_run_id" not in doc["workshop_url"], "the fallback URL stays token-free"


def test_manual_paste_fallback_is_still_offered(workbench):
    assert "Fallback." in workbench
    assert "paste the copied run.id" in workbench
    assert "not a documented guarantee" in workbench


def test_workbench_does_not_forward_arbitrary_query_parameters():
    """The deep link is built from a fixed token and tab. Caller input is only the run.id."""
    forged = create_app().test_client().get("/labs/LAB-MCP-001?form.live_run_id=x&tab=evil&next=//evil.test")
    assert forged.status_code == 200
    body = forged.get_data(as_text=True)
    assert "evil.test" not in body
    assert "form.live_run_id=x" not in body


# --- P0-C: evidence-source clarity -----------------------------------------


def test_selector_says_it_selects_recorded_evidence_and_does_not_run_anything():
    selector = WORKSHOP["inputs"]["input_run_id"]
    # CONTRACT CHANGE (P0.1-F2): "recorded, not your run" moved out of the
    # truncated control title into the CURRENT EVIDENCE table.
    assert "REPLAY" in selector["title"]
    assert all("example" in item["label"] for item in selector["options"]["items"])
    live = WORKSHOP["inputs"]["input_live_run"]
    assert "LIVE" in live["title"]
    assert live["options"]["defaultValue"] == "none"
    assert "does not run an experiment" in _md("viz_attack_prose") if "viz_attack_prose" in VIZ else True


def test_live_and_replay_are_never_labeled_the_same_way():
    titles = {WORKSHOP["inputs"][k]["title"] for k in ("input_run_id", "input_live_run")}
    assert len(titles) == 2
    assert any("REPLAY" in t for t in titles) and any("LIVE" in t for t in titles)


def test_baseline_replay_constant_matches_the_dashboard_baseline():
    """The Workbench BASELINE link and the Studio selector cannot drift apart."""
    builder = _builder()
    assert MCP_BASELINE_REPLAY_RUN_ID == builder.BASELINE_ID
    items = {i["value"] for i in WORKSHOP["inputs"]["input_run_id"]["options"]["items"]}
    assert MCP_BASELINE_REPLAY_RUN_ID in items


# --- P0-D: journey / progress ----------------------------------------------


def test_workbench_journey_names_all_ten_steps_and_says_it_is_not_progress(workbench):
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: the Workbench showed a ten-step journey strip (Learn ... Explain) and said
    #   "It is not saved progress".
    # NEW CONTRACT: five phases (UNDERSTAND, TEST, INVESTIGATE, IMPROVE, PROVE) over eight
    #   instructional steps. OBSERVE is NOT a destination (attack-complete is a state
    #   transition). The page says where the place is kept (this browser tab) and never claims
    #   saved learning progress.
    # WHY: locked P1 information architecture; ten equal destinations were the learner problem.
    rail = workbench.split('id="phase-rail"')[1].split("</ol>")[0]
    for phase in ("Understand", "Test", "Investigate", "Improve", "Prove"):
        assert phase.lower() in rail.lower()
    assert "Predict" in rail and "Attack" in rail and "Defend" in rail and "Retest" in rail
    assert "Compare" in rail and "Explain" in rail and "Baseline" in rail
    assert "Observe" not in rail and "OBSERVE" not in rail
    assert "STEP 3 OF 8" in workbench and "of 10" not in workbench
    assert "remembered in this browser tab" in workbench
    assert "saved progress" not in workbench.lower() or "not saved progress" in workbench.lower()
    assert "Your path" in workbench


def test_journey_does_not_mark_investigate_done_automatically(workbench):
    """Opening the notebook is not investigating. No stage may be auto-completed."""
    assert "journey__done" not in workbench
    assert "aria-current" in workbench


def test_studio_journey_strip_is_surface_local_and_names_replay_baseline():
    for viz_id in ("viz_journey_mission", "viz_journey_investigate"):
        text = _md(viz_id)
        # # CONTRACT CHANGE: P1 learner-experience redesign
        # OLD CONTRACT: a ten-word strip LEARN..EXPLAIN naming REPLAY and "you do not apply it".
        # NEW CONTRACT: the locked five-phase map (UNDERSTAND, TEST, INVESTIGATE, IMPROVE,
        #   PROVE); OBSERVE is a state transition, not a destination; the map is not progress.
        # WHY: D-3 / locked IA. REPLAY and the baseline are asserted on the START panel below.
        for step in ("UNDERSTAND", "TEST", "INVESTIGATE", "IMPROVE", "PROVE"):
            assert step in text
        assert "OBSERVE" not in text
        assert "not saved progress" in text
    assert "REPLAY" in _md("viz_workbench_mission")
    assert "do not run it" in _md("viz_workbench_mission")


def test_baseline_is_replay_only_and_never_launchable(workbench):
    assert 'id="open-baseline"' in workbench
    assert f"form.run_id={MCP_BASELINE_REPLAY_RUN_ID}" in workbench
    assert 'data-mode="BASELINE"' not in workbench
    assert re.findall(r'data-mode="([A-Z]+)"', workbench) == ["ATTACK", "RETEST"]


def test_defend_is_an_explanation_with_no_fake_control(workbench):
    block = workbench.split('id="defend-step"')[1].split("</div>")[0]
    assert "explanation, not a control" in block
    assert "<button" not in block and "<a " not in block
    assert "<form" not in block and "<input" not in block
    assert not re.search(r"apply defen[cs]e</button>", workbench, re.I)


def test_retest_copy_never_calls_the_system_safe(workbench):
    visible = re.sub(r"<script.*?</script>", "", workbench, flags=re.S)
    for banned in ("system is secure now", "now secure", "problem fixed", "FIXED", "is now safe", "SAFE ✓"):
        assert banned not in visible
    assert "does not show the system is secure" in visible


# --- P0-E: prediction loop --------------------------------------------------


def test_prediction_is_two_separate_questions_with_unsure(workbench):
    control = re.findall(r'name="predict-control" value="([A-Z]+)"', workbench)
    execution = re.findall(r'name="predict-execution" value="([A-Z]+)"', workbench)
    assert control == ["ALLOW", "DENY", "ERROR", "UNKNOWN"]
    assert execution == ["YES", "NO", "UNKNOWN"]
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: two "> UNSURE</label>" radios in the legacy choice-card markup.
    # NEW CONTRACT: two UNSURE options in the academy "opt" cards (one per question).
    # WHY: new prediction markup; the substantive rule (UNSURE exists for BOTH questions) is kept.
    assert workbench.count("UNSURE</span>") == 2
    assert "Two separate questions" in workbench


def test_prediction_stays_browser_local(workbench):
    assert "Not sent to the runtime" in workbench or "Never sent to the runtime" in workbench
    assert "not sent to Splunk" in workbench


# --- O1: no outcome spoiler on the normal path -----------------------------


def test_launcher_result_details_are_collapsed_and_warned(workbench):
    match = re.search(r'<details class="launcher-details" id="launcher-details"[^>]*>', workbench)
    assert match is not None
    assert " open" not in match.group(0), "the spoiler must start collapsed"
    assert "This reveals the control decision and the execution outcome" in workbench
    for element_id in ("fact-decision", "fact-execution", "fact-terminal", "fact-evidence"):
        assert f'id="{element_id}"' in workbench, "troubleshooting detail is subordinate, not removed"


def test_completion_card_leads_with_investigation_not_the_outcome(workbench):
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: the card was id="experiment-complete" and said "Now determine what actually
    #   happened from the evidence".
    # NEW CONTRACT: the card is id="attack-complete" (a STATE of the ATTACK step, not a ninth
    #   destination), is hidden until a run exists, shows the two questions and the dominant CTA
    #   "Investigate evidence", and still contains none of the outcome words in its static markup.
    # WHY: the outcome must stay unrevealed on the normal path; only the wording moved.
    card = workbench.split('id="attack-complete"')[1].split("</section>")[0]
    assert "Now work out what actually happened" in card
    assert "Investigate evidence" in card
    assert "What did the control decide?" in card and "Did downstream execution occur?" in card
    for outcome in ("DENY", "ALLOW", "denied", "allowed", "blocked", "executed", "succeeded",
                    "mcp.started", "mcp.completed"):
        assert outcome not in card, f"completion card leaks outcome word {outcome!r}"
    assert " hidden" in workbench.split('id="attack-complete"')[1].split(">")[0]
    assert 'id="experiment-complete"' not in workbench


# --- P0-F: diagram ----------------------------------------------------------


def test_mcp_flow_is_horizontal_and_keeps_the_shared_geometry():
    svg = FLOW_SVG.read_text(encoding="utf-8")
    assert 'viewBox="0 0 1440 200"' in svg, "the shared block height is pinned for all labs"
    xs = [int(m) for m in re.findall(r'<rect x="(\d+)"', svg)]
    assert xs == sorted(xs), "nodes run left to right"
    labels = re.findall(r'<text x="(\d+)" y="64"[^>]*>([^<]+)</text>', svg)
    assert [name for _, name in labels] == ["USER / AGENT", "TOOL REQUEST", "CTRL-MCP-001", "HANDLER START", "TELEMETRY"]
    positions = [int(x) for x, _ in labels]
    assert positions == sorted(positions)


def test_mcp_flow_terminates_on_deny_and_marks_splunk_as_observing_only():
    svg = FLOW_SVG.read_text(encoding="utf-8")
    assert "DENY / ERROR: the path ends here, no handler starts" in svg
    assert "ALLOW / DENY / ERROR" in svg
    assert "Splunk observes" in svg
    telemetry_rect = re.search(r'<rect[^>]*stroke-dasharray[^>]*/>\s*<text[^>]*>TELEMETRY', svg)
    assert telemetry_rect is not None, "Splunk is a dashed, non-enforcing node"
    assert "Splunk decides" not in svg and "Splunk enforces" not in svg


def test_mcp_flow_has_no_red_green_outcome_colour_and_readable_type():
    svg = FLOW_SVG.read_text(encoding="utf-8")
    for colour in ("#FF0000", "#00FF00", "#D93025", "#1E8E3E", "#0F9D58", "#C62828", "#2E7D32", "red", "green"):
        assert colour.lower() not in svg.lower()
    sizes = [int(s) for s in re.findall(r'font-size="(\d+)"', svg)]
    assert sizes and min(sizes) >= 16


# --- Evidence integrity -----------------------------------------------------


def test_surfaces_do_not_claim_llm_activity_for_lab_mcp_001():
    """The measured lab has zero LLM events. Neither surface may invent any."""
    text = _all_markdown() + "\n" + (ROOT / "src/agentsec/templates/attack_mcp.html").read_text(encoding="utf-8")
    assert not re.search(r"LLM calls?\s*[:=]\s*[1-9]", text, re.I)
    assert "get_customer_transactions" not in text
    assert "Denial-of-Wallet" not in text


def test_schema_and_external_evidence_versions_are_unchanged():
    assert "**1.9.0**" in _md("viz_workbench_mission") or "1.9.0" in _all_markdown()
    from agentsec.experiment import SCHEMA_VERSION  # noqa: PLC0415

    assert SCHEMA_VERSION == "1.9.0"


def test_your_path_asset_is_unchanged_by_this_work():
    """The P0 journey is surface-local. Your Path is the only progress memory."""
    import subprocess

    changed = subprocess.run(
        ["git", "diff", "--name-only", "HEAD", "--", str(LEARNER_PATH_JS.relative_to(ROOT))],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    assert changed == ""


def test_no_hardcoded_hosts_in_shipped_workbench_surface(workbench):
    for host in ("localhost", "127.0.0.1", "3.17.29.24"):
        assert host not in workbench
        assert host not in WORKBENCH_CSS.read_text(encoding="utf-8")
