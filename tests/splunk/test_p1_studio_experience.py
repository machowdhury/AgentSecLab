"""P1 learner experience: the Splunk Studio half of LAB-MCP-001.

Every assertion here is about the shipped dashboard definition (deterministic). Nothing
here claims Studio renders it a particular way; rendering is qualified in the browser and
reported separately. Evidence class: DOCUMENTED (definition) for these tests.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEFINITION = json.loads(
    (ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json").read_text(encoding="utf-8")
)
VIZ = DEFINITION["visualizations"]
DS = DEFINITION["dataSources"]
INPUTS = DEFINITION["inputs"]
LAYOUTS = DEFINITION["layout"]["layoutDefinitions"]
ANSWER_TOKENS = ("nb_a1", "nb_a2", "nb_a3")
CHECKS = (
    ("ds_nb_decision_fb", "nb_a1", "ds_nb_decision"),
    ("ds_nb_execution_fb", "nb_a2", "ds_nb_execution"),
    ("ds_nb_scope_fb", "nb_a3", "ds_nb_scope"),
)


def _md(viz_id: str) -> str:
    return VIZ[viz_id]["options"]["markdown"]


def _items(layout_id: str) -> list[str]:
    return [row["item"] for row in LAYOUTS[layout_id]["structure"]]


def test_learner_tabs_are_start_and_investigate_with_reference_behind():
    labels = [row["label"] for row in DEFINITION["layout"]["tabs"]["items"]]
    assert labels == ["START", "INVESTIGATE", "REFERENCE", "REFERENCE · ANSWERS"]
    assert not any("OBSERVE" in label for label in labels)


def test_start_has_one_dominant_action_and_no_prose_wall():
    start = _items("layout_mission")
    assert "viz_workbench_mission" in start
    mission = _md("viz_workbench_mission")
    assert mission.count("Open the guided lab") == 1
    # a short page: heading, one sentence, one action. Not a lecture.
    assert len(mission.split()) < 220


def test_start_names_the_replay_baseline_without_offering_a_live_one():
    mission = _md("viz_workbench_mission")
    assert "REPLAY" in mission and "do not run it" in mission
    assert "run a live baseline" not in mission.lower()


def test_answer_controls_are_supported_dropdowns_defaulting_to_none():
    """D-2: input.radio is NOT SUPPORTED on the deployed Splunk 10.2; dropdown is."""
    answer_inputs = [inp for inp in INPUTS.values() if inp["options"]["token"] in ANSWER_TOKENS]
    assert len(answer_inputs) == 3
    for inp in answer_inputs:
        assert inp["type"] == "input.dropdown"
        assert inp["options"]["defaultValue"] == "none"
        values = [item["value"] for item in inp["options"]["items"]]
        assert values[0] == "none" and "UNSURE" in values
    assert not any(inp["type"] == "input.radio" for inp in INPUTS.values())


def test_interpretation_choices_sit_between_result_and_check_in_each_cell():
    order = _items("layout_investigate")
    for n in (1, 2, 3):
        assert order.index(f"viz_nb{n}_r") < order.index(f"input_nb{n}") < order.index(f"viz_nb{n}_fb")
        assert order.index(f"viz_nb{n}_fb") < order.index(f"viz_nb{n}_limits")


@pytest.mark.parametrize(("check_ds", "token", "result_ds"), CHECKS)
def test_check_is_closed_until_the_learner_answers(check_ds, token, result_ds):
    query = DS[check_ds]["options"]["query"]
    assert f'"${token}$"' in query
    assert 'where your_answer!="none"' in query
    # reads the same events as the result it checks, and never a fabricated outcome
    first = query.split("\n")[0]
    assert first == DS[result_ds]["options"]["query"].split("\n")[0]
    assert "makeresults" not in query.lower()
    assert "UNSURE" in query


def test_check_reports_what_the_evidence_supports_not_a_grade():
    for check_ds, _token, _result in CHECKS:
        query = DS[check_ds]["options"]["query"]
        assert "evidence_supports" in query
        for banned in ("CORRECT", "INCORRECT", "PASS", "FAIL", "SAFE", "SECURE", "FIXED"):
            assert not re.search(rf"\b{banned}\b", query), (check_ds, banned)


def test_execution_cell_never_reads_the_control_decision():
    for ds_id in ("ds_nb_execution", "ds_nb_execution_fb"):
        assert "agentsec.control.decision" not in DS[ds_id]["options"]["query"], ds_id


def test_current_evidence_panel_is_first_on_investigate():
    assert _items("layout_investigate")[0] == "viz_nb_state"
    assert VIZ["viz_nb_state"]["title"].startswith("CURRENT EVIDENCE")


def test_every_cell_says_which_evidence_it_reads():
    for n in (1, 2, 3, 4):
        assert "reads the CURRENT EVIDENCE run" in _md(f"viz_nb{n}_q"), n


def test_notebook_order_is_question_result_interpretation_limits():
    q = _md("viz_nb1_q")
    assert q.index("**QUESTION.**") < q.index("**WHY THIS MATTERS.**") < q.index("**EVIDENCE RESULT.**")
    limits = _md("viz_nb1_limits")
    assert limits.index("WHAT THE EVIDENCE SUPPORTS") < limits.index("WHAT THIS DOES NOT PROVE")
    assert "NEXT" in limits


def test_reference_keeps_hunt_detect_raw_spl_and_search():
    reference = set(_items("layout_evidence")) | set(_items("layout_path_b"))
    for kept in ("viz_ref_state", "viz_ref_nb1", "viz_nb_advanced", "viz_detect_live", "viz_detect_sim", "viz_hunt_intro", "viz_i1_q", "viz_detect_md"):
        assert kept in reference, kept
    assert "Search" in _md("viz_nb_advanced")


def test_every_printed_reference_query_equals_the_executed_query():
    for viz_id, ds_id in (
        ("viz_ref_state", "ds_nb_state"),
        ("viz_ref_nb1", "ds_nb_decision"),
        ("viz_ref_nb2", "ds_nb_execution"),
        ("viz_ref_nb3", "ds_nb_scope"),
        ("viz_ref_nb4", "ds_nb_timeline"),
    ):
        blocks = re.findall(r"```text\n(.*?)\n```", _md(viz_id), re.S)
        assert DS[ds_id]["options"]["query"] in blocks, viz_id
    for viz_id, (check_ds, _t, _r) in zip(("viz_ref_nb1", "viz_ref_nb2", "viz_ref_nb3"), CHECKS):
        blocks = re.findall(r"```text\n(.*?)\n```", _md(viz_id), re.S)
        assert DS[check_ds]["options"]["query"] in blocks, viz_id


def test_no_learner_visible_ten_step_journey_or_second_navigation():
    for viz_id in ("viz_journey_mission", "viz_journey_investigate"):
        strip = _md(viz_id)
        assert "LEARN" not in strip and "OBSERVE" not in strip and "MEASURE" not in strip
    assert "viz_guide_shell" not in VIZ and "viz_guide_steps" not in VIZ


def test_start_baseline_link_is_locale_safe_and_replay():
    mission = _md("viz_workbench_mission")
    links = re.findall(r"\]\((/[^)]+)\)", mission)
    assert links and all(link.startswith("/app/agentsec/") for link in links)
    assert any("form.run_id=" in link for link in links)
    assert not any("form.live_run_id" in link for link in links)


def test_panels_do_not_overlap_in_any_layout():
    for layout_id, layout in LAYOUTS.items():
        rows = sorted(
            (row["position"]["y"], row["position"]["y"] + row["position"]["h"], row["position"]["x"], row["position"]["w"], row["item"])
            for row in layout["structure"]
        )
        for i, (y0, y1, x0, w0, item) in enumerate(rows):
            for y2, _y3, x2, w2, other in rows[i + 1 :]:
                if y2 >= y1:
                    break
                assert x2 >= x0 + w0 or x0 >= x2 + w2, (layout_id, item, other)
