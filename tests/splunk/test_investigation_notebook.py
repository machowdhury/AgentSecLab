"""The AgentSec Investigation Notebook on LAB-MCP-001 INVESTIGATE.

The notebook is a learning interaction model, not a Jupyter kernel. It is five
Dashboard Studio markdown cells, each paired with one real SPL data source, in
the order QUESTION -> WHY -> VISIBLE SPL -> REAL RESULT -> OBSERVATION ->
EVIDENCE BOUNDARY.

Three failure modes are worth pinning:

  * A cell that renders a result without stating what the result cannot show
    teaches a learner to overclaim from one run.
  * A surface that narrates an expected ALLOW or DENY before the learner
    predicts removes the only part of the lab that teaches.
  * A query that reads a decision field to answer an execution question
    silently collapses the two facts this lab exists to separate.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEFINITION = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json"
VIEW = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_mcp_001.xml"
WORKBENCH = (ROOT / "src" / "agentsec" / "templates" / "attack_mcp.html").read_text(encoding="utf-8")

WORKSHOP = json.loads(DEFINITION.read_text(encoding="utf-8"))
INVESTIGATE = WORKSHOP["layout"]["layoutDefinitions"]["layout_investigate"]
VIZ = WORKSHOP["visualizations"]
DS = WORKSHOP["dataSources"]

CELL_IDS = [f"viz_nb{n}_q" for n in range(1, 6)]
RESULT_SOURCES = {
    "viz_nb1_r": "ds_nb_decision",
    "viz_nb2_r": "ds_nb_execution",
    "viz_nb3_r": "ds_nb_scope",
    "viz_nb4_r": "ds_nb_timeline",
}
NOTEBOOK_SOURCES = ["ds_nb_state", *RESULT_SOURCES.values()]


def _items() -> list[str]:
    return [row["item"] for row in INVESTIGATE["structure"]]


def _markdown(viz_id: str) -> str:
    return VIZ[viz_id]["options"]["markdown"]


def _all_markdown() -> str:
    return "\n".join(
        viz["options"]["markdown"]
        for viz in VIZ.values()
        if viz.get("type") == "splunk.markdown"
    )


# --- structure -------------------------------------------------------------


def test_investigate_opens_with_the_notebook_header():
    items = _items()
    assert items[0] == "viz_nb_header"
    header = _markdown("viz_nb_header")
    assert "AgentSec Investigation Notebook" in header
    assert "LAB-MCP-001" in header
    assert "MCP Tool Authorization" in header


def test_header_states_mode_run_id_and_evidence_state_from_real_data():
    """The header explains the fields; the state panel reports them from the index."""
    state = VIZ["viz_nb_state"]
    assert state["dataSources"]["primary"] == "ds_nb_state"
    query = DS["ds_nb_state"]["options"]["query"]
    for field in ("agentsec.testbed.mode", "agentsec.security.profile", "agentsec.run.id"):
        assert field in query
    assert "evidence_state" in query


def test_header_teaches_the_business_context_and_the_core_distinction():
    header = _markdown("viz_nb_header")
    assert "lookup_policy" in header
    assert "lookup_customer_tier" in header
    assert "KNOWN TOOL != GRANTED TOOL" in header


def test_five_investigation_questions_exist_in_order():
    items = _items()
    positions = [items.index(cell) for cell in CELL_IDS]
    assert positions == sorted(positions), "notebook cells are out of order"
    assert len(CELL_IDS) == 5


@pytest.mark.parametrize("cell_id", CELL_IDS)
def test_every_cell_has_the_full_notebook_shape(cell_id):
    cell = _markdown(cell_id)
    assert "**QUESTION.**" in cell
    assert "**WHY THIS MATTERS.**" in cell
    assert "**YOUR OBSERVATION.**" in cell
    assert "**WHAT THIS DOES NOT PROVE.**" in cell, "a cell has no evidence boundary"


@pytest.mark.parametrize("viz_id,ds_id", sorted(RESULT_SOURCES.items()))
def test_each_question_is_answered_by_its_own_real_search(viz_id, ds_id):
    assert VIZ[viz_id]["dataSources"]["primary"] == ds_id
    assert DS[ds_id]["type"] == "ds.search"
    assert "index=agentsec_telemetry" in DS[ds_id]["options"]["query"]


def test_result_table_follows_its_question_cell():
    """One result at a time, not five tables stacked at the bottom."""
    items = _items()
    for number, (viz_id, _) in enumerate(sorted(RESULT_SOURCES.items()), start=1):
        assert items.index(viz_id) == items.index(f"viz_nb{number}_q") + 1


# --- the SPL is visible and real -------------------------------------------


@pytest.mark.parametrize("cell_id", CELL_IDS[:4])
def test_spl_is_visible_in_the_question_cell(cell_id):
    """A learner can read the query that produced the answer."""
    cell = _markdown(cell_id)
    assert "```text" in cell, "no visible query block"
    assert "| eval" in cell or "event.name" in cell


@pytest.mark.parametrize("ds_id", NOTEBOOK_SOURCES)
def test_notebook_searches_use_real_agentsec_fields(ds_id):
    query = DS[ds_id]["options"]["query"]
    assert "index=agentsec_telemetry" in query
    assert "sourcetype=otel:agentic:json" in query
    assert "agentsec.run.id" in query


@pytest.mark.parametrize("ds_id", NOTEBOOK_SOURCES)
def test_notebook_searches_invent_no_telemetry(ds_id):
    """llm_call_count and tool_call_count are Figma demonstration values."""
    query = DS[ds_id]["options"]["query"]
    for invented in ("llm_call_count", "tool_call_count", "agentsec.llm."):
        assert invented not in query, f"{ds_id} references {invented}"


def test_no_surface_claims_an_llm_call_count():
    blob = json.dumps(WORKSHOP)
    assert "llm_call_count" not in blob
    assert "tool_call_count" not in blob


def test_notebook_queries_the_run_the_learner_selected():
    """Both existing tokens, newest wins. No third input was added."""
    for ds_id in NOTEBOOK_SOURCES:
        query = DS[ds_id]["options"]["query"]
        assert "$live_run_id$" in query
        assert "$run_id$" in query
        assert "selected_run" in query
    inputs = WORKSHOP["inputs"]
    text_inputs = [v for v in inputs.values() if v["type"] == "input.text"]
    assert len(text_inputs) == 1, "the single LIVE run.id box is the invariant"
    assert text_inputs[0]["title"] == "LIVE run.id"


# --- decision and execution stay separate ----------------------------------


def test_execution_question_never_reads_the_control_decision():
    """CONTROL DECISION != EXECUTION has to hold in the query, not just the prose."""
    query = DS["ds_nb_execution"]["options"]["query"]
    assert "agentsec.control.decision" not in query
    for event in ("agentsec.mcp.started", "agentsec.mcp.completed", "agentsec.mcp.failed"):
        assert event in query
    assert "agentsec.pipeline.stopped" in query


def test_decision_question_does_not_answer_execution():
    query = DS["ds_nb_decision"]["options"]["query"]
    assert "agentsec.control.decision" in query
    assert "agentsec.mcp.started" not in query


def test_cells_teach_the_two_inequalities():
    cell1 = _markdown("viz_nb1_q")
    cell2 = _markdown("viz_nb2_q")
    assert "ALLOW != EXECUTION" in cell1
    assert "CONTROL DECISION != EXECUTION" in cell2


def test_requested_versus_granted_is_taught_with_honest_evidence_origin():
    """The scopes are OBSERVED; the grant list is DOCUMENTED configuration."""
    cell = _markdown("viz_nb3_q")
    assert "KNOWN TOOL != GRANTED TOOL" in cell
    assert "DOCUMENTED configuration" in cell
    assert "OBSERVED" in cell
    query = DS["ds_nb_scope"]["options"]["query"]
    assert "agentsec.mcp.requested_scope" in query
    assert "agentsec.mcp.allowed_scope" in query


def test_timeline_is_data_driven_not_a_hardcoded_expected_sequence():
    query = DS["ds_nb_timeline"]["options"]["query"]
    assert "sort sequence" in query
    # The validated ATTACK/RETEST sequences are regression context, not answers.
    for narrated in ("run.started", "hop.started", "hop.completed", "run.completed"):
        assert f'"{narrated}"' not in query
    cell = _markdown("viz_nb4_q")
    assert "agentsec.run.started" not in cell, "the expected sequence is narrated to the learner"


# --- the conclusion cell does not overclaim --------------------------------


def test_conclusion_uses_the_claim_vocabulary():
    cell = _markdown("viz_nb5_q")
    for word in ("PROVEN", "SUPPORTED", "OBSERVED", "NOT PROVEN"):
        assert word in cell


def test_conclusion_refuses_the_whole_system_verdicts():
    cell = _markdown("viz_nb5_q")
    assert "should not write" in cell.lower()
    for forbidden in ("compromised", "secure"):
        assert forbidden in cell.lower(), "the overclaim is not named, so it is not warned against"
    assert "ATTACK != UNIVERSAL COMPROMISE" in cell
    assert "RETEST != UNIVERSAL SECURITY" in cell


def test_no_cell_asserts_an_outcome_for_the_learners_run():
    """A notebook that states the answer is a worksheet with the back page open."""
    for cell_id in CELL_IDS:
        cell = _markdown(cell_id)
        for leak in (
            "will be ALLOW",
            "will be DENY",
            "returns ALLOW",
            "returns DENY",
            "the decision is ALLOW",
            "the decision is DENY",
        ):
            assert leak not in cell, f"{cell_id} states the outcome: {leak}"


# --- MISSION does not leak the answer (section 19) -------------------------


def test_mission_states_the_question_not_the_answer():
    mission = _markdown("viz_workbench_mission")
    assert "ATTACK expectation" not in mission
    assert "RETEST expectation" not in mission
    assert "fail-open ALLOW" not in mission
    assert "tool_not_granted" not in mission
    assert "handler count 1" not in mission
    assert "handler count 0" not in mission


def test_mission_asks_the_learner_to_determine_the_outcome():
    mission = _markdown("viz_workbench_mission")
    assert "Determine" in mission
    assert "Predict" in mission or "predict" in mission


# --- PATH B does not undermine prediction (section 18) ---------------------


def test_path_b_opens_with_the_answer_key_warning():
    path_b = WORKSHOP["layout"]["layoutDefinitions"]["layout_path_b"]
    assert path_b["structure"][0]["item"] == "viz_path_b_gate"
    gate = _markdown("viz_path_b_gate")
    assert "answer key" in gate.lower()
    assert "predict" in gate.lower()
    # The platform cannot enforce the gate, so the surface must say so.
    assert "cannot lock itself" in gate.lower()


def test_path_b_tab_is_labelled_as_answers():
    labels = [tab["label"] for tab in WORKSHOP["layout"]["tabs"]["items"]]
    assert "PATH B · ANSWERS" in labels


def test_notebook_does_not_link_the_learner_to_the_answers():
    for cell_id in [*CELL_IDS, "viz_nb_header"]:
        assert "PATH B" not in _markdown(cell_id)


# --- navigation: notebook first, native Search still available -------------


def test_workbench_primary_action_is_the_notebook_not_native_search():
    assert 'id="open-notebook-primary"' in WORKBENCH
    assert 'id="open-search-primary"' not in WORKBENCH, "native Search is no longer the primary CTA"
    primary = WORKBENCH.split('id="open-notebook-primary"', 1)[1].split(">", 1)[0]
    assert "ws_lab_mcp_001" in primary


def test_native_search_remains_available_as_advanced_investigation():
    assert 'id="open-search"' in WORKBENCH
    assert "advanced-search" in WORKBENCH
    assert "Open Splunk Search" in WORKBENCH


def test_notebook_offers_native_search_as_an_addition():
    advanced = _markdown("viz_nb_advanced")
    assert "Open Splunk Search" in advanced
    assert "not a replacement" in advanced
    assert "SPLUNK != ENFORCEMENT" in advanced


def test_run_id_handoff_does_not_fake_an_unsupported_token_binding():
    """Studio cannot take a token from a URL, so the UI must not imply it does."""
    from agentsec.search_handoff import handoff_doc, workshop_url

    doc = handoff_doc("11111111-2222-3333-4444-555555555555", lab_id="LAB-MCP-001")
    assert doc["studio_token_binding"] == "NOT SUPPORTED / DO NOT BUILD"
    assert doc["workshop_url"].endswith("/en-US/app/agentsec/ws_lab_mcp_001")
    assert "live_run_id" not in doc["workshop_url"], "a token in the URL would be ignored"
    assert workshop_url("LAB-UNKNOWN") is None
    assert "has no supported way for this page to fill that field" in WORKBENCH


def test_handoff_resolves_views_from_the_module_that_writes_them():
    """A hand-copied lab->view table drifted once; it must not exist again."""
    import agentsec.search_handoff as handoff
    from agentsec.workshop_flows import LAB_TO_VIEW

    assert not hasattr(handoff, "WORKSHOP_VIEW_BY_LAB")
    for lab_id, view in LAB_TO_VIEW.items():
        assert handoff.workshop_url(lab_id).endswith(f"/en-US/app/agentsec/{view}")


def test_every_workshop_url_points_at_a_view_that_ships():
    from agentsec.workshop_flows import LAB_TO_VIEW

    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    for lab_id, view in LAB_TO_VIEW.items():
        assert (views / f"{view}.xml").is_file(), f"{lab_id} links to a missing view"


# --- EVIDENCE is a different surface, not a duplicate ----------------------


def test_evidence_tab_is_the_raw_explorer_and_says_so():
    evidence = _markdown("viz_workbench_evidence")
    assert "not the guided investigation" in evidence.lower()
    assert "INVESTIGATE" in evidence


def test_evidence_and_investigate_share_no_data_source():
    """Same table on two tabs would be duplication without pedagogical purpose."""
    investigate = {
        VIZ[item].get("dataSources", {}).get("primary")
        for item in _items()
    } - {None}
    evidence_items = WORKSHOP["layout"]["layoutDefinitions"]["layout_evidence"]["structure"]
    evidence = {
        VIZ[row["item"]].get("dataSources", {}).get("primary") for row in evidence_items
    } - {None}
    assert not (investigate & evidence), f"shared sources: {sorted(investigate & evidence)}"


# --- architectural invariants (section 3) ----------------------------------


def test_runtime_contract_versions_are_unchanged():
    from agentsec.experiment import SCHEMA_VERSION
    from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION

    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"


def test_control_identity_is_unchanged():
    from agentsec.mcp.policy import ALLOWED_TOOLS

    assert ALLOWED_TOOLS == frozenset({"lookup_policy"})
    assert "CTRL-MCP-001" in json.dumps(WORKSHOP)


def test_det_mcp_001_stays_disabled():
    saved = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
    text = saved.read_text(encoding="utf-8")
    # DET-MCP-001 ships under its display name; the id lives in the description.
    block = text.split("[AgentSec - MCP Execution After Authorization Deny]", 1)[1]
    block = block.split("\n[", 1)[0]
    assert "DET-MCP-001" in block
    assert re.search(r"^disabled\s*=\s*1", block, re.M), "DET-MCP-001 must stay disabled"


def test_no_phase_2_lab_or_control_was_introduced():
    blob = json.dumps(WORKSHOP) + WORKBENCH
    for forbidden in (
        "LAB-GOV-004",
        "LAB-DATA-003",
        "LAB-A2A-005",
        "CTRL-RUNTIME-004",
        "CTRL-DATA-003",
        "CTRL-A2A-005",
    ):
        assert forbidden not in blob


def test_view_xml_matches_the_definition():
    xml = VIEW.read_text(encoding="utf-8")
    shipped = json.loads(
        re.search(r"<definition><!\[CDATA\[(.*?)\]\]></definition>", xml, re.S).group(1)
    )
    assert shipped == WORKSHOP


def test_no_jupyter_or_second_query_engine_was_introduced():
    blob = _all_markdown().lower()
    for banned in ("jupyter", "notebook server", "kernel"):
        assert banned not in blob
    for viz in VIZ.values():
        assert viz["type"] in {"splunk.markdown", "splunk.table", "splunk.image"}
    for ds in DS.values():
        assert ds["type"] == "ds.search"
