"""Offline contracts for the L10 mastery capstone. Learning metadata is not policy."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-ADVANCED-CAPSTONE-MASTERY-001"
VIEW = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_advanced_capstone.xml"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"

EARLY_TABS = (
    "layout_mission", "layout_architecture", "layout_investigate", "layout_evidence",
    "layout_timeline", "layout_data", "layout_controls", "layout_detect",
    "layout_respond", "layout_report",
)


def _packet() -> dict:
    return json.loads((LAB / "incident.json").read_text(encoding="utf-8"))


def _definition() -> dict:
    xml = VIEW.read_text(encoding="utf-8")
    start = xml.index("<![CDATA[") + len("<![CDATA[")
    end = xml.index("]]>")
    return json.loads(xml[start:end].strip())


def _markdown(layout_ids: tuple[str, ...] | None = None) -> str:
    definition = _definition()
    if layout_ids is None:
        ids = [
            row["item"]
            for layout in definition["layout"]["layoutDefinitions"].values()
            for row in layout["structure"]
            if definition["visualizations"][row["item"]]["type"] == "splunk.markdown"
        ]
    else:
        ids = [
            row["item"]
            for layout_id in layout_ids
            for row in definition["layout"]["layoutDefinitions"][layout_id]["structure"]
            if definition["visualizations"][row["item"]]["type"] == "splunk.markdown"
        ]
    return "\n".join(definition["visualizations"][viz_id]["options"]["markdown"] for viz_id in ids)


def test_l10_registration_preserves_live_capstone_boundary():
    curriculum = json.loads((ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8"))
    level = next(row for row in curriculum["levels"] if row["id"] == "L10")
    assert level["next"] is None
    assert level["labs"][0]["lab_id"] == "LAB-ADVANCED-CAPSTONE-MASTERY-001"
    assert level["labs"][0]["mode"] == "REPLAY"
    assert level["labs"][0]["view"] == "ws_lab_advanced_capstone"
    assert curriculum["nav_collections"][-1] == {
        "label": "Advanced Capstone",
        "views": ["ws_lab_advanced_capstone"],
    }
    assessments = json.loads((ROOT / "learning" / "academy" / "assessments.json").read_text(encoding="utf-8"))
    assert len(assessments["challenges"]) == 10
    competency = assessments["advanced_capstone_competencies"]
    assert competency["lab_id"] == "LAB-ADVANCED-CAPSTONE-MASTERY-001"
    assert "DEMONSTRATED" in competency["states"]
    assert "NOT ASSESSED" in competency["states"]
    nav = (ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml").read_text(encoding="utf-8")
    assert nav.index("ws_lab_multi_stage_incident") < nav.index("ws_lab_advanced_capstone")
    assert nav.index("ws_lab_advanced_capstone") < nav.index("ws_agentsec_mastery")
    assert "LAB-ADVANCED-CAPSTONE-MASTERY-001" not in nav


def test_capstone_is_a_different_problem_from_agent_2026_009():
    packet = _packet()
    assert packet["incident_id"] == "MASTER-2026-001"
    assert packet["schema_version"] == "1.9.0"
    assert packet["external_evidence_contract"] == "1.0.0"
    assert packet["pdp"] == "CTRL-MCP-001"
    assert packet["not_a_new_attack"] is True
    raw = json.dumps(packet)
    assert "2437f64a-fff4-424f-8a83-0f04285662e4" not in raw
    assert "AGENT-2026-009" not in raw
    assert packet["canonical_runs"]["attack"]["mcp_decision"] == "ALLOW"
    assert packet["canonical_runs"]["attack"]["goal_decision"] == "OBSERVE"
    assert packet["canonical_runs"]["retest"]["goal_decision"] == "DENY"
    assert packet["canonical_runs"]["attack"]["effective_action"] != packet["canonical_runs"]["retest"]["effective_action"]


def test_hypotheses_false_leads_gap_and_causal_semantics():
    packet = _packet()
    assert len(packet["initial_hypotheses"]) >= 3
    dispositions = {row["id"]: row["disposition"] for row in packet["initial_hypotheses"]}
    assert dispositions["H2"] == "REFUTED"
    assert dispositions["H3"] == "REFUTED"
    assert dispositions["H1"] == "SUPPORTED"
    assert len(packet["false_leads"]) >= 2
    assert packet["evidence_gap"]["state"] == "NOT PROVEN"
    for rule in (
        "CORRELATED != CAUSED",
        "PRECEDES != CAUSED",
        "SAME HASH != SAME EXECUTION",
        "SAME RUN != EVERY EVENT CAUSED EVERY OTHER EVENT",
    ):
        assert rule in packet["causal_rules"]
    assert packet["shared_fingerprints"]["task_hash"]
    assert "not the same execution" in packet["shared_fingerprints"]["note"]


def test_authorization_execution_privacy_and_external_planes():
    packet = _packet()
    attack = packet["canonical_runs"]["attack"]
    assert attack["mcp_reason"] == "tool_granted"
    assert attack["wrong_goal_handler"] == 1
    assert packet["canonical_runs"]["retest"]["wrong_goal_handler"] == 0
    assert packet["canonical_runs"]["retest"]["in_task_handler"] == 1
    assert packet["planes"]["authorize_tool"] == ["CTRL-MCP-001"]
    assert "Splunk" in packet["planes"]["observe"]
    privacy = packet["privacy"]
    for key in ("required", "available", "sent", "returned", "logged", "persisted", "proven"):
        assert privacy[key]
    assert "NOT PROVEN" in privacy["returned"]
    for row in packet["external_evidence"]:
        assert row["inside_ctrl_mcp_001"] is False
        assert row["classification"] == "UNRELATED"


def test_controls_containment_remediation_retest_and_baseline():
    packet = _packet()
    goal = next(row for row in packet["controls"] if row["id"] == "CTRL-GOAL-INTEGRITY-001")
    mcp = next(row for row in packet["controls"] if row["id"] == "CTRL-MCP-001")
    assert "FAILED" in goal["attack"]
    assert "SUCCEEDED" in goal["retest"]
    assert "ENFORCE" in mcp["mode"]
    assert "NOT APPLICABLE" in mcp["attack"]
    assert any("Justified" in item for item in packet["containment"])
    assert any("Not justified" in item for item in packet["containment"])
    for item in packet["remediation"]:
        for key in ("problem", "control", "placement", "expected_effect", "evidence_required", "residual_risk"):
            assert item[key]
    assert "GOAL / TASK" in packet["remediation"][0]["placement"]
    assert "SAME RELEVANT INPUT" in packet["retest_design"]["preserve"]
    assert "EXPECTED LEGITIMATE FUNCTIONALITY" in packet["retest_design"]["preserve"]
    assert packet["canonical_runs"]["baseline"]["effective_action"] == "summarize_lending_policy"
    assert packet["canonical_runs"]["baseline"]["mcp_decision"] == "ALLOW"


def test_detection_hunt_threat_model_and_reports():
    packet = _packet()
    detection = packet["detection_candidate"]
    assert detection["installed"] is False
    for key in ("hypothesis", "observables", "expected_attack", "expected_retest", "expected_baseline", "false_positives", "blind_spots"):
        assert detection[key]
    assert packet["hunt"]["starts_from_run_id"] is False
    revised = packet["revised_threat_model"]
    for key in ("wrong_assumption", "missed_threat", "boundary", "authority", "missing_telemetry", "control_change", "residual_risk"):
        assert revised[key]
    for audience in ("soc", "engineering", "executive"):
        text = packet["reports"][audience].lower()
        assert "breach" not in text
        assert "compromised" not in text
        assert "safe" not in text
    assert len(packet["mastery_dimensions"]) == 15
    assert packet["competency_states"] == [
        "DEMONSTRATED", "PARTIALLY DEMONSTRATED", "NOT YET DEMONSTRATED", "NOT ASSESSED",
    ]
    assert len(packet["reflection_prompts"]) >= 7


def test_mission_hides_answers_and_expert_mode_has_no_query():
    early = _markdown(EARLY_TABS)
    packet = _packet()
    for run in packet["canonical_runs"].values():
        assert run["run_id"] not in early
    assert "H2 disposition is REFUTED" not in early
    assert "wrong-goal handler count was 1" not in early
    mission = _definition()["visualizations"]["viz_mission"]["options"]["markdown"]
    assert "Expert mode" in mission
    assert "index=agentsec_telemetry" not in mission
    assert "2026-09-18" in mission
    assert "Deliverables" in mission
    whole = _markdown()
    assert "REPLAY workshop" in whole
    assert "Path B" in whole
    assert "not policy" in whole.lower()
    assert "NOT PROVEN" in whole
    assert "dc(_raw)" in whole
    path_b = _definition()["visualizations"]["viz_path_b"]["options"]["markdown"]
    assert packet["canonical_runs"]["attack"]["run_id"] in path_b
    assert "H2 disposition is REFUTED" in path_b
    assert _definition()["inputs"] == {}


def test_searches_are_not_one_answer_and_detection_is_not_installed():
    expected = {
        "Q-L10-DISCOVER.spl", "Q-L10-SEQUENCE.spl", "Q-L10-EXTERNAL.spl",
        "Q-L10-HUNT.spl", "Q-L10-COMPARE.spl", "Q-L10-DETECTION-CANDIDATE.spl",
    }
    assert {path.name for path in (LAB / "searches").glob("*.spl")} == expected
    for name in expected:
        text = (LAB / "searches" / name).read_text(encoding="utf-8")
        assert "index=agentsec_telemetry" in text
        assert "index=*" not in text
        assert "transaction" not in text
        for run in _packet()["canonical_runs"].values():
            assert run["run_id"] not in text
    discover = (LAB / "searches" / "Q-L10-DISCOVER.spl").read_text(encoding="utf-8")
    assert "2026-09-18T22:47:40Z" in discover
    assert "dc(_raw)" in discover
    hunt = (LAB / "searches" / "Q-L10-HUNT.spl").read_text(encoding="utf-8")
    assert "CTRL-GOAL-INTEGRITY-001" in hunt
    assert "fd994587" not in hunt
    candidate = (LAB / "searches" / "Q-L10-DETECTION-CANDIDATE.spl").read_text(encoding="utf-8")
    assert "DETECTION CANDIDATE — NOT INSTALLED" in candidate
    saved = (ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf").read_text(encoding="utf-8")
    assert "DET-L10" not in saved
    assert "Q-L10-DETECTION-CANDIDATE" not in saved


def test_schema_and_external_contract_unchanged():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["properties"]["agentsec.schema.version"]["const"] == "1.9.0"
    from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION

    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    assert '"const": "1.9.0"' in SCHEMA.read_text(encoding="utf-8")


def test_failure_language_and_no_safe_conclusion():
    md = _markdown()
    assert "NO EVIDENCE FOUND" in md
    assert "INSUFFICIENT EVIDENCE" in md
    assert "Never write SAFE" in md or "does not" in md.lower()
    packet = _packet()
    assert packet["evidence_gap"]["state"] != "SAFE"
