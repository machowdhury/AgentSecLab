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

#: Cells that print a query, and the data source that query belongs to.
#: The header prints the state-panel query. Cell 5's question is synthesis, but
#: the comparison table that sits under it runs a real search, so the panel that
#: introduces that table prints it. An earlier version of this comment said cell
#: 5 "runs none"; the comparison table does run one, and it was the one query on
#: the tab the learner could not read.
QUERY_CELLS = {
    "viz_nb_header": "ds_nb_state",
    "viz_nb1_q": "ds_nb_decision",
    "viz_nb2_q": "ds_nb_execution",
    "viz_nb3_q": "ds_nb_scope",
    "viz_nb4_q": "ds_nb_timeline",
    "viz_live_pair_intro": "ds_live_pair",
}

#: The live pair selects by mode and recency, so it deliberately carries no
#: run.id token. Every other printed query is bound to the selected run.
RUN_BOUND_CELLS = {k: v for k, v in QUERY_CELLS.items() if v != "ds_live_pair"}


def _items() -> list[str]:
    return [row["item"] for row in INVESTIGATE["structure"]]


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
    return "\n".join(
        [viz.get("title", ""), viz.get("description", ""), viz.get("options", {}).get("markdown", "")]
    )


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


@pytest.mark.parametrize("viz_id,ds_id", sorted(QUERY_CELLS.items()))
def test_displayed_spl_is_the_executed_spl(viz_id, ds_id):
    """The printed query must be the query, not a summary of it.

    The first notebook printed an abbreviated query beside the real one. Cell 4
    was the worst case: pasted into Search verbatim it returned the right rows
    with event_name, control_id, decision and executed all blank, because the
    eval clauses that build those columns were not shown. A learning product
    whose whole method is "check the claim against the evidence" cannot show a
    query that does not reproduce its own table.
    """
    blocks = _query_blocks(viz_id)
    assert len(blocks) == 1, f"{viz_id} should print exactly one query, found {len(blocks)}"
    assert blocks[0] == DS[ds_id]["options"]["query"], (
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
        block = _query_blocks(viz_id)[0]
        assert "$live_run_id$" in block and "$run_id$" in block


def test_every_search_on_investigate_is_printed_verbatim():
    """Drift protection derived from the layout, not from a hand-kept list.

    Walk every panel on the INVESTIGATE canvas. Any panel backed by a search
    must have that search's exact text printed in some markdown panel on the
    same canvas. A search added later without a printed twin fails here even if
    nobody remembers to extend QUERY_CELLS.
    """
    printed = []
    for item in _items():
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
        assert query in printed, f"{ds_id} runs on INVESTIGATE but its query is not printed"

    # And nothing a cell presents as "the query behind this table" is printed
    # without running: a decorative query is a claim. The Advanced panel is the
    # one named exception. It is a starter for native Search with a
    # YOUR-RUN-ID placeholder, it feeds no table, and it says so.
    for item in _items():
        if item == "viz_nb_advanced":
            continue
        for block in _query_blocks(item) if VIZ[item].get("type") == "splunk.markdown" else []:
            assert block in executed.values(), f"{item} prints a query that no search runs"

    advanced = _markdown("viz_nb_advanced")
    assert "YOUR-RUN-ID" in advanced, "the advanced starter must stay visibly a template"
    assert "Start from the base search and add your own clauses" in advanced
    assert "this query" not in advanced.lower() and "table below" not in advanced.lower()


def test_comparison_query_is_printed_beside_the_table_it_produces():
    """Cell 5's table must not run a query the learner cannot read."""
    assert VIZ["viz_live_pair"]["dataSources"]["primary"] == "ds_live_pair"
    blocks = _query_blocks("viz_live_pair_intro")
    assert blocks == [DS["ds_live_pair"]["options"]["query"]]
    items = _items()
    assert items.index("viz_live_pair") == items.index("viz_live_pair_intro") + 1


def test_comparison_query_is_not_bound_to_a_run_id_token():
    """It selects by mode and recency; a token here would be a different query."""
    block = _query_blocks("viz_live_pair_intro")[0]
    assert "$live_run_id$" not in block and "$run_id$" not in block
    assert "testbed.mode" in block


def test_cell_four_prints_every_column_it_renders():
    """The regression that started this: a table clause with unshown evals."""
    block = _query_blocks("viz_nb4_q")[0]
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
    assert text_inputs[0]["title"] == "LIVE run.id"


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

    The executed query is the printed query (see the drift tests), but this
    asserts the invariant on the printed text directly so a future change that
    breaks the one-string design cannot also hide a decision read.
    """
    printed = _query_blocks("viz_nb2_q")
    assert len(printed) == 1
    for text in (printed[0], DS["ds_nb_execution"]["options"]["query"]):
        lowered = text.lower()
        assert "control.decision" not in lowered
        assert "control.id" not in lowered
        assert "decision" not in lowered, "the execution question must not touch any decision field"


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
    assert doc["workshop_url"].startswith("http")
    assert "/en-US/app/agentsec/ws_lab_mcp_001" in doc["workshop_url"]
    assert "live_run_id" not in doc["workshop_url"], "a token in the URL would be ignored"
    assert workshop_url("LAB-UNKNOWN") is None
    assert "has no supported way for this page to fill that field" in WORKBENCH


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


def test_comparison_panel_has_room_for_both_runs():
    """Cell 5 tells the learner to compare two rows; one was off-panel.

    The table is twelve columns wide and one holds the full fail-open reason,
    a long sentence that wraps. At 320px the wrapped ATTACK row pushed RETEST
    past the panel edge at both 1920 and 1024. The row stayed in the DOM, so
    only looking at the rendered page caught it.
    """
    panel = _block("viz_live_pair")
    columns = DS["ds_live_pair"]["options"]["query"].rsplit("| table", 1)[1].split("\n")[0]
    column_count = len(columns.split(","))
    assert column_count >= 10, "this guard assumes a wide table"
    # Two wrapped rows plus header, title and description. Measured against the
    # rendering that clipped at 320.
    assert panel["position"]["h"] >= 560, (
        f"{column_count} columns including a long reason string will not fit in "
        f"{panel['position']['h']}px without hiding the RETEST row"
    )


def test_comparison_panel_keeps_every_evidence_column():
    """Height was the fix. Dropping columns would have hidden evidence instead."""
    table_clause = DS["ds_live_pair"]["options"]["query"].rsplit("| table", 1)[1].split("\n")[0]
    columns = {c.strip() for c in table_clause.split(",")}
    assert {"mode", "run_id", "decision", "reason", "execution_state"} <= columns
    assert {"requested_scope", "allowed_scope", "scope_gap"} <= columns


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
