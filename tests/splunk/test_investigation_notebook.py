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
#: CONTRACT CHANGE: P1 learner-experience redesign
#: OLD CONTRACT: a notebook cell was ONE markdown panel (question + WHY + printed SPL +
#:   observation + evidence boundary) followed by one result table.
#: NEW CONTRACT: a cell is several panels in the order QUESTION -> WHY IT MATTERS ->
#:   EVIDENCE RESULT -> YOUR INTERPRETATION -> WHAT THE EVIDENCE SUPPORTS -> WHAT THIS DOES
#:   NOT PROVE -> NEXT. The question panel carries QUESTION/WHY; the "limits" panel carries
#:   OBSERVATION/SUPPORTS/DOES NOT PROVE/NEXT. The SPL moved to the REFERENCE tab.
#: WHY: ONE SCREEN -> ONE LEARNING OBJECTIVE. Visible SPL == executed SPL is NOT loosened;
#:   it is asserted against the REFERENCE panels below.
LIMIT_IDS = {n: f"viz_nb{n}_limits" for n in range(1, 6)}
RESULT_SOURCES = {
    "viz_nb1_r": "ds_nb_decision",
    "viz_nb2_r": "ds_nb_execution",
    "viz_nb3_r": "ds_nb_scope",
    "viz_nb4_r": "ds_nb_timeline",
}
#: The interpretation CHECK tables (P1). Each reads the SAME events as its result table.
CHECK_SOURCES = {
    "viz_nb1_fb": "ds_nb_decision_fb",
    "viz_nb2_fb": "ds_nb_execution_fb",
    "viz_nb3_fb": "ds_nb_scope_fb",
}
NOTEBOOK_SOURCES = ["ds_nb_state", *RESULT_SOURCES.values(), *CHECK_SOURCES.values()]

#: REFERENCE panels that print queries, and the data sources each one prints, in order.
#: The live pair selects by mode and recency, so it deliberately carries no run.id token.
QUERY_CELLS = {
    "viz_ref_state": ["ds_nb_state"],
    "viz_ref_nb1": ["ds_nb_decision", "ds_nb_decision_fb"],
    "viz_ref_nb2": ["ds_nb_execution", "ds_nb_execution_fb"],
    "viz_ref_nb3": ["ds_nb_scope", "ds_nb_scope_fb"],
    "viz_ref_nb4": ["ds_nb_timeline"],
    "viz_live_pair_intro": ["ds_live_pair"],
}
RUN_BOUND_CELLS = {k: v for k, v in QUERY_CELLS.items() if v != ["ds_live_pair"]}


def _items() -> list[str]:
    """Panels (not in-canvas inputs). Inputs are checked separately."""
    return [row["item"] for row in INVESTIGATE["structure"] if row.get("type") == "block"]


def _reference_items() -> list[str]:
    layout = WORKSHOP["layout"]["layoutDefinitions"]["layout_evidence"]
    return [row["item"] for row in layout["structure"]]


def _markdown(viz_id: str) -> str:
    return VIZ[viz_id]["options"]["markdown"]


def _query_blocks(viz_id: str) -> list[str]:
    """Fenced ```text blocks printed in a cell."""
    return re.findall(r"```text\n(.*?)\n```", _markdown(viz_id), re.S)


def _evidence_items() -> list[str]:
    layout = WORKSHOP["layout"]["layoutDefinitions"]["layout_evidence"]
    return [row["item"] for row in layout["structure"]]


def _panel_text(viz_id: str) -> str:
    viz = VIZ[viz_id]
    markdown = re.sub(r"```text\n.*?\n```", "", viz.get("options", {}).get("markdown", ""), flags=re.S)
    # CONTRACT CHANGE (P1): REFERENCE now hosts printed SPL. A query is a definition, not an
    # expectation, so the answer-leak guard reads the prose around it, not the code block.
    return "\n".join([viz.get("title", ""), viz.get("description", ""), markdown])


def _all_markdown() -> str:
    return "\n".join(
        viz["options"]["markdown"]
        for viz in VIZ.values()
        if viz.get("type") == "splunk.markdown"
    )


# --- structure -------------------------------------------------------------


def test_investigate_opens_with_the_journey_map_then_the_notebook_header():
    """CONTRACT CHANGE (P0-D): a journey map now sits above the header so the
    learner sees where INVESTIGATE falls before reading the notebook. The
    header must still be the very next panel, ahead of every question cell."""
    items = _items()
    # CONTRACT CHANGE (P0.1-F2): CURRENT EVIDENCE is now the first panel.
    assert items[0] == "viz_nb_state"
    assert items[1] == "viz_journey_investigate"
    assert items[2] == "viz_nb_header"
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


@pytest.mark.parametrize("number", range(1, 6))
def test_every_cell_has_the_full_notebook_shape(number):
    question = _markdown(f"viz_nb{number}_q")
    limits = _markdown(LIMIT_IDS[number])
    assert "**QUESTION.**" in question
    assert "**WHY THIS MATTERS.**" in question
    assert "**EVIDENCE RESULT.**" in question
    assert "**YOUR OBSERVATION.**" in limits
    assert "**WHAT THE EVIDENCE SUPPORTS.**" in limits
    assert "**WHAT THIS DOES NOT PROVE.**" in limits, "a cell has no evidence boundary"
    assert "**NEXT.**" in limits


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


@pytest.mark.parametrize("cell_id", CELL_IDS)
def test_spl_is_not_in_the_question_cell_but_on_reference(cell_id):
    """CONTRACT CHANGE: P1 learner-experience redesign
    OLD CONTRACT: the question cell printed its SPL (test_spl_is_visible_in_the_question_cell).
    NEW CONTRACT: no INVESTIGATE panel prints SPL; every query is printed on REFERENCE.
    WHY: SPL before the interpretation buried the question. Reproducibility is unchanged and is
      asserted by test_displayed_spl_is_the_executed_spl on the REFERENCE panels.
    """
    assert "```text" not in _markdown(cell_id)
    assert "```text" not in _markdown(LIMIT_IDS[int(cell_id[6])])
    printed = [b for ref in QUERY_CELLS for b in _query_blocks(ref)]
    assert printed, "REFERENCE prints no queries"
    assert any("| eval" in b or "event.name" in b for b in printed)


@pytest.mark.parametrize("viz_id,ds_ids", sorted(QUERY_CELLS.items()))
def test_displayed_spl_is_the_executed_spl(viz_id, ds_ids):
    """The printed query must be the query, not a summary of it.

    The first notebook printed an abbreviated query beside the real one. Cell 4
    was the worst case: pasted into Search verbatim it returned the right rows
    with event_name, control_id, decision and executed all blank, because the
    eval clauses that build those columns were not shown. A learning product
    whose whole method is "check the claim against the evidence" cannot show a
    query that does not reproduce its own table.

    CONTRACT CHANGE (P1): the printed blocks now live on REFERENCE and a panel may print
    more than one query (result + CHECK), in order. The string equality is unchanged.
    """
    blocks = _query_blocks(viz_id)
    assert len(blocks) == len(ds_ids), f"{viz_id} prints {len(blocks)} queries, expected {len(ds_ids)}"
    for block, ds_id in zip(blocks, ds_ids):
        assert block == DS[ds_id]["options"]["query"], (
            f"{viz_id} displays SPL that differs from {ds_id}. These must be one string, "
            "not two that are kept in step by hand."
        )


def test_every_notebook_search_is_printed_somewhere_in_the_notebook():
    """No cell may run a query the learner cannot read."""
    printed = {block for viz_id in QUERY_CELLS for block in _query_blocks(viz_id)}
    for ds_id in NOTEBOOK_SOURCES:
        assert DS[ds_id]["options"]["query"] in printed, f"{ds_id} runs unseen"


def test_displayed_spl_carries_the_run_selection_the_table_used():
    """A query a learner cannot bind to a run would not reproduce the table.

    Studio substitutes these tokens in markdown exactly as it does in a search,
    so what the learner copies already names the run they are looking at.
    """
    for viz_id in RUN_BOUND_CELLS:
        for block in _query_blocks(viz_id):
            assert "$live_run_id$" in block and "$run_id$" in block


def test_every_search_on_investigate_is_printed_verbatim():
    """Drift protection derived from the layout, not from a hand-kept list.

    Walk every panel on the INVESTIGATE canvas. Any panel backed by a search must have that
    search's exact text printed in some markdown panel on the REFERENCE canvas (CONTRACT
    CHANGE, P1: it used to be printed on INVESTIGATE itself). A search added later without a
    printed twin fails here even if nobody remembers to extend QUERY_CELLS.
    """
    printed = []
    for item in _reference_items():
        viz = VIZ[item]
        if viz.get("type") == "splunk.markdown":
            printed.extend(_query_blocks(item))

    executed = {}
    for item in _items():
        primary = VIZ[item].get("dataSources", {}).get("primary")
        if primary and DS[primary]["type"] == "ds.search":
            executed[primary] = DS[primary]["options"]["query"]

    assert executed, "no searches found on INVESTIGATE; the walk is broken"
    for ds_id, query in sorted(executed.items()):
        assert query in printed, f"{ds_id} runs on INVESTIGATE but its query is not printed on REFERENCE"

    # Nothing on INVESTIGATE prints a query at all, and nothing REFERENCE presents as "the
    # query behind this table" is printed without running: a decorative query is a claim. The
    # Advanced panel is the one named exception. It is a starter for native Search with a
    # YOUR-RUN-ID placeholder, it feeds no table, and it says so.
    for item in _items():
        if VIZ[item].get("type") == "splunk.markdown":
            assert not _query_blocks(item), f"{item} prints SPL on INVESTIGATE"
    for item in _reference_items():
        if item == "viz_nb_advanced":
            continue
        for block in _query_blocks(item) if VIZ[item].get("type") == "splunk.markdown" else []:
            assert block in {q["options"]["query"] for q in DS.values()}, f"{item} prints a query that no search runs"

    advanced = _markdown("viz_nb_advanced")
    assert "YOUR-RUN-ID" in advanced, "the advanced starter must stay visibly a template"
    assert "Start from the base search and add your own clauses" in advanced
    assert "this query" not in advanced.lower() and "table below" not in advanced.lower()


def test_comparison_query_is_printed_beside_the_table_it_produces():
    """Cell 5's table must not run a query the learner cannot read (CONTRACT CHANGE, P1:
    the query is printed on REFERENCE; the table stays on INVESTIGATE)."""
    assert VIZ["viz_live_pair"]["dataSources"]["primary"] == "ds_live_pair"
    blocks = _query_blocks("viz_live_pair_intro")
    assert blocks == [DS["ds_live_pair"]["options"]["query"]]
    assert "viz_live_pair" in _items()
    assert "viz_live_pair_intro" in _reference_items()


def test_comparison_query_is_not_bound_to_a_run_id_token():
    """It selects by mode and recency; a token here would be a different query."""
    block = _query_blocks("viz_live_pair_intro")[0]
    assert "$live_run_id$" not in block and "$run_id$" not in block
    assert "testbed.mode" in block


def test_cell_four_prints_every_column_it_renders():
    """The regression that started this: a table clause with unshown evals."""
    block = _query_blocks("viz_ref_nb4")[0]
    table_clause = [line for line in block.splitlines() if line.startswith("| table")]
    assert table_clause, "cell 4 has no table clause"
    columns = [c.strip() for c in table_clause[0][len("| table") :].split(",")]
    for column in columns:
        if column == "_time":
            continue  # supplied by the index, not by an eval
        assert f"| eval {column}=" in block, f"column {column} is rendered but never built"


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
    # CONTRACT CHANGE (P0-C): the box is still the single LIVE run.id input, but
    # its title now says it is the learner's own evidence. See test_evidence_source_*.
    assert text_inputs[0]["title"].startswith("LIVE")
    assert "run.id" in text_inputs[0]["title"]


# --- decision and execution stay separate ----------------------------------


def test_execution_question_never_reads_the_control_decision():
    """CONTROL DECISION != EXECUTION has to hold in the query, not just the prose."""
    query = DS["ds_nb_execution"]["options"]["query"]
    assert "agentsec.control.decision" not in query
    for event in ("agentsec.mcp.started", "agentsec.mcp.completed", "agentsec.mcp.failed"):
        assert event in query
    assert "agentsec.pipeline.stopped" in query


def test_execution_question_decision_independence_holds_for_the_printed_query():
    """Prove it on what the learner reads, and on every spelling of the field.

    CONTRACT CHANGE (P1): the printed queries are the REFERENCE ones and now include the
    interpretation CHECK query. BOTH must be free of any decision field; the CHECK table is
    part of "Cell 2" and must not collapse the two facts either.
    """
    printed = _query_blocks("viz_ref_nb2")
    assert len(printed) == 2
    for text in (*printed, DS["ds_nb_execution"]["options"]["query"], DS["ds_nb_execution_fb"]["options"]["query"]):
        lowered = text.lower()
        assert "control.decision" not in lowered
        assert "control.id" not in lowered
        assert "decision" not in lowered, "the execution question must not touch any decision field"


def test_decision_question_does_not_answer_execution():
    query = DS["ds_nb_decision"]["options"]["query"]
    assert "agentsec.control.decision" in query
    assert "agentsec.mcp.started" not in query


def test_cells_teach_the_two_inequalities():
    assert "ALLOW != EXECUTION" in _markdown(LIMIT_IDS[1])
    assert "CONTROL DECISION != EXECUTION" in _markdown(LIMIT_IDS[2])


def test_requested_versus_granted_is_taught_with_honest_evidence_origin():
    """The scopes are OBSERVED; the grant list is DOCUMENTED configuration."""
    cell = _markdown(LIMIT_IDS[3])
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
    cell = _markdown(LIMIT_IDS[5])
    for word in ("PROVEN", "SUPPORTED", "OBSERVED", "NOT PROVEN"):
        assert word in cell


def test_conclusion_refuses_the_whole_system_verdicts():
    cell = _markdown(LIMIT_IDS[5])
    assert "do not write" in cell.lower()
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
    """CONTRACT CHANGE: P1 learner-experience redesign
    OLD CONTRACT: the mission said "Determine" and "Predict".
    NEW CONTRACT: the short START panel says the learner predicts first and then works out what
      happened from evidence. It still states no outcome (see the leak tests above).
    WHY: ONE SCREEN -> ONE LEARNING OBJECTIVE -> ONE DOMINANT NEXT ACTION.
    """
    mission = _markdown("viz_workbench_mission")
    assert "predict first" in mission
    assert "work out what happened from **evidence**" in mission
    assert "Open the guided lab" in mission


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
    """CONTRACT CHANGE: P1 (D-3). The learner tabs are START and INVESTIGATE; the answer key is
    a REFERENCE tab and is still labelled as answers."""
    labels = [tab["label"] for tab in WORKSHOP["layout"]["tabs"]["items"]]
    assert labels == ["START", "INVESTIGATE", "REFERENCE", "REFERENCE · ANSWERS"]
    assert "PATH B · ANSWERS" not in labels


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
    assert doc["workshop_url"].startswith("http")
    assert "/en-US/app/agentsec/ws_lab_mcp_001" in doc["workshop_url"]
    assert "live_run_id" not in doc["workshop_url"], "a token in the URL would be ignored"
    assert workshop_url("LAB-UNKNOWN") is None
    # CONTRACT CHANGE (P0-B): the plain workshop URL still carries no token, but
    # the Workbench now offers a separate, validated deep link (investigate_url)
    # whose prefill is SUPPORTED WITH CONSTRAINTS, and it must say so honestly
    # and keep the manual fallback.
    assert "not a documented guarantee" in WORKBENCH
    assert "paste the copied run.id" in WORKBENCH


def test_handoff_lands_on_the_tab_the_workbench_promises():
    """The workbench said INVESTIGATE; Studio opened the first tab, MISSION.

    Studio opens a workshop on its first tab unless the URL names another. The
    promise was on the page and the behaviour was not, so the learner arrived
    holding a fresh run.id on a page with nowhere to paste it.
    """
    from agentsec.search_handoff import workshop_url
    from agentsec.workshop_flows import LAB_TO_LANDING_TAB

    promise = WORKBENCH.split('id="open-notebook-primary"', 1)[1]
    assert "tab=layout_investigate" in WORKBENCH.split('id="open-notebook"', 1)[1][:400]
    assert "tab=layout_investigate" in promise[:400]
    assert "INVESTIGATE tab" in WORKBENCH, "the claim itself should still be made"
    assert LAB_TO_LANDING_TAB["LAB-MCP-001"] == "layout_investigate"
    assert workshop_url("LAB-MCP-001").endswith(
        "/en-US/app/agentsec/ws_lab_mcp_001?tab=layout_investigate"
    )


def test_a_named_landing_tab_exists_in_the_view_it_names():
    """Studio ignores an unknown tab id, silently restoring MISSION-first."""
    import json as _json

    from agentsec.workshop_flows import LAB_TO_LANDING_TAB, LAB_TO_VIEW

    for lab_id, tab in LAB_TO_LANDING_TAB.items():
        definition = _json.loads(
            (ROOT / "learning" / "level_1" / lab_id / "dashboard.definition.json").read_text(
                encoding="utf-8"
            )
        )
        assert tab in definition["layout"]["layoutDefinitions"], f"{lab_id} has no {tab}"
        assert any(
            item["layoutId"] == tab for item in definition["layout"]["tabs"]["items"]
        ), f"{lab_id} does not expose {tab} as a tab"
        assert lab_id in LAB_TO_VIEW


def test_labs_without_a_promise_still_open_on_their_first_tab():
    """Only redirect a learner where the product actually promised to."""
    from agentsec.search_handoff import workshop_url
    from agentsec.workshop_flows import LAB_TO_LANDING_TAB, LAB_TO_VIEW

    for lab_id, view in LAB_TO_VIEW.items():
        if lab_id in LAB_TO_LANDING_TAB:
            continue
        assert workshop_url(lab_id).endswith(f"/en-US/app/agentsec/{view}")


def test_handoff_resolves_views_from_the_module_that_writes_them():
    """A hand-copied lab->view table drifted once; it must not exist again."""
    import agentsec.search_handoff as handoff
    from agentsec.workshop_flows import LAB_TO_VIEW

    assert not hasattr(handoff, "WORKSHOP_VIEW_BY_LAB")
    for lab_id, view in LAB_TO_VIEW.items():
        assert f"/en-US/app/agentsec/{view}" in handoff.workshop_url(lab_id)


def test_every_workshop_url_points_at_a_view_that_ships():
    from agentsec.workshop_flows import LAB_TO_VIEW

    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    for lab_id, view in LAB_TO_VIEW.items():
        assert (views / f"{view}.xml").is_file(), f"{lab_id} links to a missing view"


# --- EVIDENCE is a different surface, not a duplicate ----------------------


#: Phrasings that hand a learner the outcome before they investigate.
#: PATH B may use them: it is labelled ANSWERS and opens with a gate. EVIDENCE
#: may not: it sits between INVESTIGATE and PATH B with no warning at all.
ANSWER_LEAKS = [
    r"\bExpect\b",
    r"decision (ALLOW|DENY)",
    r"fail-open ALLOW",
    r"reason tool_(not_)?granted",
    r"execution_state\s*=\s*\S",
    r"has_started\s*=\s*\d",
    r"outcome\s*=?\s*prevented",
]


@pytest.mark.parametrize("pattern", ANSWER_LEAKS)
def test_evidence_tab_guides_investigation_without_giving_the_answer(pattern):
    """MISSION was cleaned and PATH B was gated; EVIDENCE was neither.

    Panels here used to read "Expect decision DENY, reason tool_not_granted".
    A learner one click from INVESTIGATE could read the conclusion before
    forming one, which removes the only part of the lab that teaches.
    """
    offenders = [
        viz_id
        for viz_id in _evidence_items()
        if re.search(pattern, _panel_text(viz_id), re.IGNORECASE)
    ]
    assert not offenders, f"EVIDENCE panels state the answer ({pattern}): {offenders}"


def test_evidence_tab_still_tells_the_learner_what_to_read():
    """Removing leakage must not strip the guidance that made it useful."""
    guidance = " ".join(_panel_text(v) for v in _evidence_items()).lower()
    for field in ("decision", "execution_state", "requested_scope", "allowed_scope", "has_started"):
        assert field in guidance, f"EVIDENCE no longer points at {field}"
    assert "compare" in guidance


def test_answer_key_tab_may_still_state_outcomes():
    """The gate exists so PATH B can be explicit. Do not sanitise it too."""
    layout = WORKSHOP["layout"]["layoutDefinitions"]["layout_path_b"]
    text = " ".join(_panel_text(row["item"]) for row in layout["structure"])
    assert "Expect" in text


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


def _block(viz_id: str) -> dict:
    for row in INVESTIGATE["structure"]:
        if row["item"] == viz_id:
            return row
    raise AssertionError(f"{viz_id} is not on INVESTIGATE")


# MEASURED, not guessed (evidence class: MEASURED, deployed Splunk 10.2, live ATTACK run).
# Minimum LAYOUT height each INVESTIGATE panel needs so its content does not overflow the box,
# taken as the larger of two real Chrome conditions: a 1024px window and genuine 200% browser
# zoom (chrome.tabs.setZoom, CSS viewport 960px). Rendered content height * canvas scale / 0.965
# (the measured rendered-px per layout-unit) gives layout units. At 1920px every panel has room
# to spare; the Studio grid has fixed heights and does not reflow (SPLUNK PLATFORM CONSTRAINT).
# CONTRACT CHANGE (P1): the P0 single entry {"viz_nb4_r": 543} is replaced by a P1 measurement of
# every INVESTIGATE panel whose content height depends on width. viz_live_pair_intro (858) moved
# to REFERENCE and now prints only the query.
MEASURED_MIN_HEIGHT_NARROW = {
    "viz_nb_state": 192,
    "viz_nb_header": 415,
    "viz_nb1_q": 139,
    "viz_nb2_q": 139,
    "viz_nb3_q": 155,
    "viz_nb4_q": 155,
    "viz_nb1_r": 295,
    "viz_nb2_r": 163,
    "viz_nb3_r": 150,
    "viz_nb4_r": 618,
    "viz_live_pair": 544,
    "viz_nb1_limits": 145,
    "viz_nb2_limits": 181,
    "viz_nb3_limits": 165,
    "viz_nb4_limits": 152,
    "viz_nb5_q": 176,
    "viz_nb5_limits": 262,
    # CHECK tables, measured with an answer selected (they are closed until then).
    "viz_nb1_fb": 358,
    "viz_nb2_fb": 213,
    "viz_nb3_fb": 275,
}


@pytest.mark.parametrize("panel_id,minimum", sorted(MEASURED_MIN_HEIGHT_NARROW.items()))
def test_p1_measured_panel_heights_hold(panel_id, minimum):
    height = _block(panel_id)["position"]["h"]
    assert height >= minimum, (
        f"{panel_id} is {height} layout units; its content measured {minimum} at a 1024px window "
        "and at 200% zoom, so the learner would have to scroll inside the panel"
    )


def test_comparison_table_is_transposed_so_width_cannot_clip_it():
    """Twelve columns did not fit at 1024px: 127px of horizontal and 35px of
    vertical overflow hid last_seen and the RETEST row. One column per run and
    one row per field removes the dependence on window width without dropping a
    field or truncating a value."""
    query = DS["ds_live_pair"]["options"]["query"]
    lines = query.splitlines()
    assert lines[-1] == "| transpose 0 header_field=mode column_name=field"
    assert query.count("| transpose") == 1
    table_at = max(i for i, line in enumerate(lines) if line.startswith("| table "))
    sort_at = max(i for i, line in enumerate(lines) if line.startswith("| sort mode"))
    assert sort_at < table_at, "ATTACK must sort before RETEST before the table is turned"
    assert table_at == len(lines) - 2, "transpose must directly consume the table"


def test_comparison_panel_keeps_every_evidence_column():
    """Transposing re-orients the table; it must not drop a field."""
    table_clause = DS["ds_live_pair"]["options"]["query"].rsplit("| table", 1)[1].split("\n")[0]
    columns = {c.strip() for c in table_clause.split(",")}
    assert {"mode", "run_id", "decision", "reason", "execution_state"} <= columns
    assert {"requested_scope", "allowed_scope", "scope_gap"} <= columns
    assert {"profile", "tool", "matched_events", "last_seen"} <= columns


def test_comparison_prose_matches_the_transposed_orientation():
    """The cell must not tell the learner to look for rows that are now columns."""
    intro = " ".join(VIZ["viz_nb5_q"]["options"]["markdown"].split())
    assert "one column per run.id" in intro and "A missing column" in intro
    assert "one row instead of two" not in intro
    description = VIZ["viz_live_pair"]["description"]
    assert description.startswith("One column per run.id, one row per field")
    assert "One row per run.id" not in description


def test_investigate_panels_are_stacked_with_a_constant_gap():
    """Offsets follow from heights, so raising one panel cannot overlap another."""
    rows = INVESTIGATE["structure"]
    assert rows[0]["position"]["y"] == 0
    for upper, lower in zip(rows, rows[1:]):
        expected = upper["position"]["y"] + upper["position"]["h"] + 8
        assert lower["position"]["y"] == expected, f"{lower['item']} is not stacked under {upper['item']}"


def test_investigate_canvas_is_tall_enough_for_its_panels():
    """A panel taller than the canvas is unreachable however you scroll."""
    canvas = WORKSHOP["layout"]["layoutDefinitions"]["layout_investigate"]
    declared = canvas["options"]["height"]
    lowest = max(row["position"]["y"] + row["position"]["h"] for row in canvas["structure"])
    assert declared >= lowest, f"canvas {declared}px cannot show content ending at {lowest}px"


def test_panels_on_investigate_do_not_overlap():
    rows = sorted(INVESTIGATE["structure"], key=lambda r: r["position"]["y"])
    for upper, lower in zip(rows, rows[1:]):
        bottom = upper["position"]["y"] + upper["position"]["h"]
        assert bottom <= lower["position"]["y"], (
            f"{upper['item']} ends at {bottom} but {lower['item']} starts at {lower['position']['y']}"
        )


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


# --- the pre-run specimen fallback actually engages ---------------------------
#
# Found only in a real browser. With the LIVE run.id box empty, Dashboard Studio
# treats the token as unset and never runs a search that references it, so the
# documented fallback ("investigate the canonical specimen until you have a run")
# rendered 55 "Set token value to render visualization" panels. Splunk documents
# this under "Defaults for tokens". An empty defaults.tokens value did not help
# (60 panels). These tests pin the contract that does work.

LIVE_INPUT = WORKSHOP["inputs"]["input_live_run"]
NOTEBOOK_SPLS = [DS[ds_id]["options"]["query"] for ds_id in NOTEBOOK_SOURCES]


def test_live_run_box_has_a_non_empty_default():
    """An empty default is the bug. Studio never runs a search on an unset token."""
    default = LIVE_INPUT["options"]["defaultValue"]
    assert default, "an empty LIVE run.id default leaves every notebook panel unrendered"
    assert LIVE_INPUT["options"]["token"] == "live_run_id"
    assert "input_live_run" in WORKSHOP["layout"]["globalInputs"]


def test_the_default_is_the_constant_the_sql_tests_against():
    """One constant feeds both sides, so the input and the SPL cannot drift."""
    default = LIVE_INPUT["options"]["defaultValue"]
    for query in NOTEBOOK_SPLS:
        assert f'if("$live_run_id$"=="{default}","$run_id$","$live_run_id$")' in query


def test_the_default_can_never_be_mistaken_for_a_run_id():
    """It must match no event, or the fallback would silently investigate a run."""
    default = LIVE_INPUT["options"]["defaultValue"]
    assert not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}", default)
    for pack in (ROOT / "learning" / "level_1" / "LAB-MCP-001" / "specimens").glob("*.jsonl"):
        for line in pack.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            assert event.get("agentsec.run.id") != default


def test_no_notebook_search_is_left_depending_on_an_empty_token():
    """The old test, `$live_run_id$ != ""`, can never be true once a default exists."""
    for query in NOTEBOOK_SPLS:
        assert '"$live_run_id$"!=""' not in query


def test_an_empty_token_default_is_not_reintroduced_by_a_defaults_stanza():
    """Measured to do nothing; keeping dead configuration only misleads."""
    assert "tokens" not in WORKSHOP.get("defaults", {})


def test_workbench_tells_the_learner_to_replace_the_default_before_pasting():
    """A prefilled box appends a paste unless the text is selected first."""
    assert "select the <code>none</code>" in WORKBENCH
    assert "select the existing text" in WORKBENCH
    header = _markdown("viz_nb_header")
    assert "reads `none`" in header and "select everything" in header
    assert "Leave it empty" not in _all_markdown()
