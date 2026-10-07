"""Phase 1 learner-UX P0.1 contracts (LAB-MCP-001).

Deterministic repository checks only. They do not execute SPL and do not load a
browser; how a learner experiences the page is measured separately.

Threat          the page teaches a false claim about how evidence reaches Studio,
                or lets a learner mistake REPLAY evidence for their own LIVE run
Asset           the learner's belief about WHICH evidence is being read
Trust boundary  Workbench (Flask :5001) -> Splunk Dashboard Studio (:8000)
Invariants      REQUEST != AUTHORIZATION; ALLOW != execution; REPLAY is not a
                newly measured live experiment; Splunk is not the PDP
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

from agentsec.attack_app import create_app
from agentsec.search_handoff import LAB_TO_LIVE_RUN_TOKEN, STUDIO_URL_PREFILL_STATUS

ROOT = Path(__file__).resolve().parents[2]
DEFINITION = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json"
BUILDER = ROOT / "scripts" / "build_lab_mcp_001_dashboard.py"
GUIDED = ROOT / "scripts" / "apply_guided_learning.py"
TEMPLATE = ROOT / "src" / "agentsec" / "templates" / "attack_mcp.html"

WORKSHOP = json.loads(DEFINITION.read_text(encoding="utf-8"))
VIZ = WORKSHOP["visualizations"]
DS = WORKSHOP["dataSources"]

STALE = "Studio cannot receive"
JOURNEY = ["LEARN", "BASELINE", "PREDICT", "ATTACK", "OBSERVE", "INVESTIGATE", "DEFEND", "RETEST", "COMPARE", "EXPLAIN"]


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _md(viz_id: str) -> str:
    return VIZ[viz_id]["options"]["markdown"]


def _studio_text() -> str:
    """Every learner-visible string in the MCP workshop dashboard."""
    return json.dumps(WORKSHOP)


@pytest.fixture(scope="module")
def workbench() -> str:
    response = create_app().test_client().get("/labs/LAB-MCP-001")
    assert response.status_code == 200
    return response.get_data(as_text=True)


# --- F1: stale handoff copy -------------------------------------------------


def test_stale_cannot_receive_statement_is_absent_from_lab_mcp_001():
    assert STALE not in _studio_text()
    assert "Studio cannot receive a fresh LIVE run.id" not in _studio_text()


def test_stale_statement_is_absent_from_the_owning_sources_for_this_lab():
    builder = BUILDER.read_text(encoding="utf-8")
    assert STALE not in builder
    assert "That handoff is Search, not a token write" not in builder


def test_deep_link_workflow_is_described_truthfully():
    text = _studio_text()
    assert "Investigate evidence" in text or "Open the guided lab" in text
    # normal path is the lab link; manual entry is named as recovery only
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: manual entry was called a "fallback". NEW CONTRACT: it is called
    #   "Recovery only ... not the normal path". WHY: same meaning, clearer learner wording.
    assert "recovery only" in text.lower()
    assert "not the normal path" in text.lower()


def test_guide_steps_name_the_workbench_link_as_the_normal_path():
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: a generic guide shell (viz_guide_shell) carried this statement.
    # NEW CONTRACT: LAB-MCP-001 no longer renders a generic guide (AUTHORED_START_LABS); the
    #   authored notebook header carries the same statement. WHY: D-3, one journey only.
    text = _md("viz_nb_header") + _md("viz_workbench_mission")
    assert "recovery" in text.lower() and "not the normal path" in text
    assert "Open the guided lab" in text
    assert STALE not in text
    assert "viz_guide_shell" not in VIZ


def test_no_invented_formal_support_claim_for_form_prefill():
    assert "SUPPORTED WITH CONSTRAINTS" in STUDIO_URL_PREFILL_STATUS
    text = _studio_text() + TEMPLATE.read_text(encoding="utf-8")
    for banned in ("documented Splunk API", "officially supported", "guaranteed by Splunk", "Splunk guarantees"):
        assert banned not in text
    assert "not a documented" in text


def test_deep_link_labs_pin_matches_the_handoff_table():
    guided = _load(GUIDED)
    assert set(guided.DEEP_LINK_LABS) == set(LAB_TO_LIVE_RUN_TOKEN)


def test_other_labs_keep_their_manual_paste_instruction():
    """Only labs with a real handoff may drop the manual-paste sentence."""
    xml = (ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_rag_context.xml").read_text(
        encoding="utf-8"
    )
    assert STALE in xml


# --- F2: LIVE vs REPLAY selector --------------------------------------------


def test_selector_titles_and_labels_survive_studio_truncation():
    builder = _load(BUILDER)
    limit = builder.CONTROL_TEXT_MAX
    for inp in WORKSHOP["inputs"].values():
        assert len(inp["title"]) <= limit, inp["title"]
        for item in inp["options"].get("items", []):
            assert len(item["label"]) <= limit, item["label"]


def test_live_and_replay_controls_are_named_by_source():
    titles = {v["options"]["token"]: v["title"] for v in WORKSHOP["inputs"].values()}
    assert titles["live_run_id"].startswith("LIVE")
    assert titles["run_id"].startswith("REPLAY")


def test_replay_options_do_not_look_like_the_current_evidence():
    items = WORKSHOP["inputs"]["input_run_id"]["options"]["items"]
    assert [i["label"] for i in items] == ["Baseline example", "Attack example", "Retest example"]
    # the selector never contains a LIVE option
    assert not any("LIVE" in i["label"] for i in items)


def test_current_evidence_panel_is_first_on_investigate():
    items = [s["item"] for s in WORKSHOP["layout"]["layoutDefinitions"]["layout_investigate"]["structure"]]
    assert items[0] == "viz_nb_state"
    assert VIZ["viz_nb_state"]["title"].startswith("CURRENT EVIDENCE")


def test_current_evidence_states_live_or_replay_from_the_token_not_the_dropdown():
    query = DS["ds_nb_state"]["options"]["query"]
    assert "current_evidence" in query
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: "LIVE: your own " / "REPLAY: a recorded ". NEW CONTRACT: the em-dash wording
    #   the brief requires: "LIVE — your ATTACK experiment" / "REPLAY — recorded BASELINE example".
    assert '"LIVE — your "' in query
    assert '"REPLAY — recorded "' in query
    assert '+mode+" experiment"' in query and '+mode+" example (not your run)"' in query
    assert 'if("$live_run_id$"=="none"' in query
    assert "not your run" in query


def test_current_evidence_does_not_read_the_control_decision_event():
    """Cell 2 and the state panel must stay independent of agentsec.control.decision."""
    assert "agentsec.control.decision" not in DS["ds_nb_state"]["options"]["query"]
    # Cell 2 is the execution timeline; it reads mcp.* events, not the decision.
    assert "agentsec.control.decision" not in DS["ds_nb_execution"]["options"]["query"]


def test_visible_spl_equals_executed_spl_for_the_state_panel():
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: the SPL was printed in the notebook header. NEW CONTRACT: it is printed in the
    #   REFERENCE panel, and the INVESTIGATE tab shows only the table. Visible == executed still holds.
    query = DS["ds_nb_state"]["options"]["query"]
    assert query in _md("viz_ref_state")
    investigate = {row["item"] for row in WORKSHOP["layout"]["layoutDefinitions"]["layout_investigate"]["structure"]}
    assert "viz_ref_state" not in investigate and "viz_nb_state" in investigate


def test_header_explains_that_the_replay_selector_is_ignored_while_live_is_set():
    header = _md("viz_nb_header")
    assert "ignored" in header
    assert "CURRENT EVIDENCE" in header


def test_workbench_fallback_names_the_renamed_live_box(workbench):
    assert "LIVE: your run.id" in workbench
    assert "LIVE evidence</strong> box" not in workbench


# --- Mission leakage and journey order --------------------------------------


def test_mission_does_not_reveal_attack_decision_execution_or_retest_answer():
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: also required the sentence "deliberately not stated here".
    # NEW CONTRACT: START no longer discusses outcomes at all, so there is nothing to disclaim.
    #   Every spoiler phrase must still be absent. WHY: one screen, one objective, one action.
    mission = _md("viz_workbench_mission") + _md("viz_journey_mission")
    for spoiler in (
        "will be denied",
        "is denied",
        "is allowed",
        "will execute",
        "handler executes",
        "RETEST will",
        "ATTACK will",
        "fail-open",
        "reason=",
    ):
        assert spoiler.lower() not in mission.lower(), spoiler


def test_mission_states_the_determination_as_questions():
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: START listed three "Whether ..." determinations under "What you are determining".
    # NEW CONTRACT: START frames ONE question as its title and gives ONE next action; the two
    #   independent prediction questions live in the guided lab's PREDICT step (asserted in
    #   tests/unit/test_p1_web_experience.py). WHY: one screen, one objective, one dominant action.
    mission = _md("viz_workbench_mission")
    assert mission.splitlines()[0].endswith("?")
    assert mission.count("Open the guided lab") == 1
    assert "You **predict first**" in mission


def test_journey_order_is_pinned_in_every_journey_strip():
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: the ten-word LEARN..EXPLAIN order. NEW CONTRACT: the locked five-phase order.
    phases = ["UNDERSTAND", "TEST", "INVESTIGATE", "IMPROVE", "PROVE"]
    for viz_id in ("viz_journey_mission", "viz_journey_investigate"):
        strip = _md(viz_id).split("\n\n")[0]
        words = re.findall(r"\b(START|" + "|".join(phases) + r")\b", strip)
        assert [w for w in words if w != "START"] == phases, viz_id


def test_investigate_journey_does_not_claim_the_experiment_just_finished_unconditionally():
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: the strip said "if you came from the Workbench" and "REPLAY example".
    # NEW CONTRACT: the strip never claims the experiment just finished; the CURRENT EVIDENCE
    #   panel states LIVE or REPLAY from the token, and the header says both are possible.
    text = _md("viz_journey_investigate")
    assert "just finished" not in text and "your experiment" not in text.lower()
    header = _md("viz_nb_header")
    assert "REPLAY — a recorded example" in header and "LIVE — your own experiment" in header


def test_defend_is_hidden_until_the_experiment_is_complete(workbench):
    tag = re.search(r'<div[^>]*id="defend-step"[^>]*>', workbench).group(0)
    assert "hidden" in tag


def test_defend_follows_the_prediction_in_page_order(workbench):
    assert 'id="defend-step"' in workbench
    assert workbench.index("</form>") < workbench.index('id="defend-step"')
    assert "after you have investigated ATTACK" in workbench


def test_defend_is_revealed_only_from_the_completion_path():
    # CONTRACT CHANGE: P1 learner-experience redesign
    # OLD CONTRACT: a revealDefend() function was called from the completion and reload paths.
    # NEW CONTRACT: DEFEND is a wizard step. canEnter("defend") requires a recorded ATTACK run
    #   (live or restored); direct navigation falls back to the nearest allowed step.
    # WHY: the single-page reveal was replaced by step gating; the property (no DEFEND before an
    #   ATTACK run exists) is preserved and still tested.
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "revealDefend" not in source
    assert "function canEnter" in source and "function fallbackStep" in source
    gate = source.split("function canEnter", 1)[1].split("}", 1)[0]
    assert "defend" in gate and "ATTACK" in gate


# --- Evidence integrity -----------------------------------------------------


def test_no_phase_2_or_llm_content_was_added_to_the_workshop():
    text = _studio_text()
    assert not re.search(r"LLM calls?\s*[:=]\s*[1-9]", text, re.I)
    for banned in ("Phase 2", "PyRIT", "garak", "MITRE"):
        assert banned not in text, banned


def test_double_negative_copy_is_gone():
    text = _studio_text()
    assert "does not prove nothing" not in text


def test_versions_are_unchanged():
    from agentsec import __version__  # noqa: PLC0415
    from agentsec.experiment import SCHEMA_VERSION  # noqa: PLC0415

    assert __version__ == "1.1.0"
    assert SCHEMA_VERSION == "1.9.0"
    app_conf = (ROOT / "splunk_app" / "agentsec" / "default" / "app.conf").read_text(encoding="utf-8")
    assert re.search(r"^version = 1\.1\.0$", app_conf, re.M)
    garak = (ROOT / "src" / "agentsec" / "external_evidence" / "garak.py").read_text(encoding="utf-8")
    assert "ExternalEvidence 1.0.0" in garak
