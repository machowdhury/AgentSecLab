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
    assert "Investigate evidence" in text
    # normal path is the Workbench link; manual entry is named as fallback
    assert "fallback" in text.lower()


def test_guide_steps_name_the_workbench_link_as_the_normal_path():
    text = _md("viz_guide_shell")
    assert "Investigate evidence" in text
    assert "recovery" in text and "not the normal path" in text
    assert STALE not in text


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
    assert '"LIVE: your own "' in query
    assert '"REPLAY: a recorded "' in query
    assert 'if("$live_run_id$"=="none"' in query
    assert "not your run" in query


def test_current_evidence_does_not_read_the_control_decision_event():
    """Cell 2 and the state panel must stay independent of agentsec.control.decision."""
    assert "agentsec.control.decision" not in DS["ds_nb_state"]["options"]["query"]
    # Cell 2 is the execution timeline; it reads mcp.* events, not the decision.
    assert "agentsec.control.decision" not in DS["ds_nb_execution"]["options"]["query"]


def test_visible_spl_equals_executed_spl_for_the_state_panel():
    query = DS["ds_nb_state"]["options"]["query"]
    assert query in _md("viz_nb_header")


def test_header_explains_that_the_replay_selector_is_ignored_while_live_is_set():
    header = _md("viz_nb_header")
    assert "ignored" in header
    assert "CURRENT EVIDENCE" in header


def test_workbench_fallback_names_the_renamed_live_box(workbench):
    assert "LIVE: your run.id" in workbench
    assert "LIVE evidence</strong> box" not in workbench


# --- Mission leakage and journey order --------------------------------------


def test_mission_does_not_reveal_attack_decision_execution_or_retest_answer():
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
    assert "deliberately not stated here" in mission


def test_mission_states_the_determination_as_questions():
    mission = _md("viz_workbench_mission")
    section = mission.split("## What you are determining")[1].split("Predict each answer")[0]
    assert section.count("Whether") >= 3


def test_journey_order_is_pinned_in_every_journey_strip():
    for viz_id in ("viz_journey_mission", "viz_journey_investigate"):
        words = re.findall(r"\b(" + "|".join(JOURNEY) + r")\b", _md(viz_id).split("**You are here:**")[0])
        assert words == JOURNEY, viz_id


def test_investigate_journey_does_not_claim_the_experiment_just_finished_unconditionally():
    text = _md("viz_journey_investigate")
    assert "if you came from the Workbench" in text
    assert "REPLAY example" in text


def test_defend_is_hidden_until_the_experiment_is_complete(workbench):
    tag = re.search(r'<div[^>]*id="defend-step"[^>]*>', workbench).group(0)
    assert "hidden" in tag


def test_defend_follows_the_prediction_in_page_order(workbench):
    assert 'id="defend-step"' in workbench
    assert workbench.index("</form>") < workbench.index('id="defend-step"')
    assert "after you have investigated ATTACK" in workbench


def test_defend_is_revealed_only_from_the_completion_path():
    source = TEMPLATE.read_text(encoding="utf-8")
    calls = [m.start() for m in re.finditer(r"revealDefend\(\)", source)]
    # one definition plus the completion and reload call sites
    assert len(calls) == 3
    assert "function revealDefend" in source


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
