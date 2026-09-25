"""Offline contracts for the bounded L9 integrated incident."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.mcp.authorize import authorize_tool
from agentsec.mcp.policy import coded_policy

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-MULTI-STAGE-INCIDENT-001"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_multi_stage_incident.xml"


def _json(name: str) -> dict:
    return json.loads((LAB / name).read_text(encoding="utf-8"))


def _definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def _markdown(layouts: tuple[str, ...] | None = None) -> str:
    definition = _definition()
    ids = [
        viz_id for viz_id, viz in definition["visualizations"].items()
        if viz["type"] == "splunk.markdown"
    ] if layouts is None else [
        row["item"] for layout_id in layouts
        for row in definition["layout"]["layoutDefinitions"][layout_id]["structure"]
        if definition["visualizations"][row["item"]]["type"] == "splunk.markdown"
    ]
    return "\n".join(definition["visualizations"][viz_id]["options"]["markdown"] for viz_id in ids)


def test_l9_curriculum_navigation_and_artifacts():
    curriculum = json.loads((ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8"))
    assert [row["id"] for row in curriculum["levels"]][-4:] == ["L7", "L8", "L9", "L10"]
    assert next(row for row in curriculum["levels"] if row["id"] == "L8")["next"] == "L9"
    level = next(row for row in curriculum["levels"] if row["id"] == "L9")
    assert level["exit"] == "AGENTIC INCIDENT RESPONDER / SECURITY ARCHITECT"
    assert level["labs"][0]["lab_id"] == "LAB-MULTI-STAGE-INCIDENT-001"
    assert curriculum["nav_collections"][-2] == {"label": "Integrated Incident", "views": ["ws_lab_multi_stage_incident"]}
    for path in (
        DEFINITION, VIEW, LAB / "README.md", LAB / "incident.json",
        LAB / "incident-brief.md", LAB / "evidence-graph.json",
        LAB / "control-analysis.json", LAB / "investigations.json",
        LAB / "incident-artifact-template.md",
        ROOT / "scripts" / "build_lab_multi_stage_incident_dashboard.py",
    ):
        assert path.is_file(), path


def test_incident_fixture_is_one_coherent_existing_packet():
    incident = _json("incident.json")
    assert incident["incident_id"] == "AGENT-2026-009"
    assert incident["evidence_mode"] == "REPLAY"
    assert incident["canonical_runs"]["attack"] == {
        "retrieve": "2a248113-7436-46a7-9b1d-0243489ac000",
        "write": "348c8f18-fdfb-4501-ad8a-3f1bcda64c34",
        "recall": "2437f64a-fff4-424f-8a83-0f04285662e4",
    }
    assert incident["canonical_runs"]["retest"]["recall"] == "8d2c016f-cadc-4463-939a-23a183221b3d"
    assert incident["canonical_runs"]["baseline"] == {
        "retrieve": "5a15fe04-4bb1-4f70-8ec0-ab83f423dcde",
        "write": "5dd71f94-5b12-4c52-b5ed-93a0b6832d45",
        "recall": "3d2b66a1-9ef1-4b1d-b993-444db50fd3ee",
    }
    assert incident["shared_fingerprint"].startswith("sha256:")
    assert incident["domains"]["GOAL_INTEGRITY"] == "RELEVANT BUT NOT OBSERVED"
    assert incident["domains"]["IDENTITY_DELEGATION"] == "RELEVANT BUT NOT OBSERVED"
    assert incident["domains"]["PRIVACY"].startswith("RELEVANT BUT NOT INVOLVED")


def test_workflow_hints_answer_gating_and_failure_states():
    definition = _definition()
    assert [row["label"] for row in definition["layout"]["tabs"]["items"]] == [
        "INCIDENT", "INVESTIGATE", "TIMELINE", "EVIDENCE", "CONTROLS",
        "DATA IMPACT", "RESPOND", "THREAT MODEL", "REPORT", "PATH B",
    ]
    investigations = _json("investigations.json")
    assert investigations["workflow"] == ["DISCOVER", "NARROW", "CORRELATE", "SEQUENCE", "COMPARE", "CHALLENGE"]
    assert [row["level"] for row in investigations["hints"]] == ["PLANE", "EVIDENCE_TYPE", "FIELDS", "EXAMPLE_SPL"]
    assert investigations["answer_gating"] == "PEDAGOGICAL"
    assert investigations["progress_persistence"] is False
    failures = " ".join(investigations["failure_states"].values())
    assert "NO EVIDENCE FOUND" in failures and "INSUFFICIENT EVIDENCE" in failures
    assert "not SAFE" in failures
    early = _markdown(tuple(f"layout_{name}" for name in ("incident", "investigate", "timeline", "evidence", "controls", "data", "respond", "model", "report")))
    review = _markdown(("layout_answer",))
    for answer in ("On ATTACK, CTRL-MCP-001 recorded", "handler count was 1"):
        assert answer not in early
        assert answer in review


def test_attack_chain_states_graph_semantics_and_no_unsupported_causality():
    incident = _json("incident.json")
    states = {row["stage"]: row["state"] for row in incident["attack_chain"]}
    assert states["ENTRY"] == "PROVEN"
    assert states["INTENT / GOAL"] == "NOT OBSERVED"
    assert states["AUTHORITY"] == "PROVEN"
    graph = _json("evidence-graph.json")
    allowed = set(graph["allowed_edge_semantics"])
    assert "CAUSED" not in allowed
    assert all(edge["semantic"] in allowed for edge in graph["edges"])
    assert not any(edge["semantic"] == "CAUSED" for edge in graph["edges"])
    assert any(node["state"] == "REFUTED" for node in graph["nodes"])
    assert all(node["state"] for node in graph["nodes"])


def test_timeline_authorization_execution_privacy_memory_identity_and_false_lead():
    md = _markdown()
    for term in (
        "REQUEST → DECISION → INVOCATION → COMPLETION → OUTCOME",
        "influence", "CTRL-MCP-001", "Authorized execution does not establish appropriate data use",
        "WRITE → PERSIST → RECALL → REUSE", "NOT OBSERVED", "NOT MODELED",
        "Scanner HIGH != exploitation", "Evaluation PASS != safe",
    ):
        assert term.lower() in md.lower(), term
    incident = _json("incident.json")
    assert incident["false_lead"]["state"] == "REFUTED AS INCIDENT CAUSE"
    assert incident["garak_context"]["state"] == "INSUFFICIENT TO CORRELATE"
    assert incident["domains"]["AUTHENTICATION"] == "NOT MODELED"


def test_control_analysis_response_retest_detection_hunt_and_model_updates():
    controls = _json("control-analysis.json")
    assert set(controls["states"]) == {
        "CONTROL PRESENT", "CONTROL TRIGGERED", "CONTROL SUCCEEDED",
        "CONTROL FAILED", "CONTROL NOT APPLICABLE", "CONTROL NOT MODELED",
    }
    mcp = next(row for row in controls["controls"] if row["control"] == "CTRL-MCP-001")
    assert "FAILED" in mcp["attack_result"]
    assert "SUCCEEDED" in mcp["retest_result"]
    md = _markdown()
    for term in (
        "Immediate containment", "Root-cause remediation", "Architectural hardening",
        "Candidate detection—not installed", "False-positive review", "Hunt expansion",
        "Threat-model update", "Privacy-model update", "residual",
    ):
        assert term.lower() in md.lower(), term
    saved = (ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf").read_text(encoding="utf-8")
    assert "DET-L9" not in saved


def test_searches_are_bounded_and_candidate_detection_is_not_installed():
    expected = {
        "Q-L9-DISCOVER.spl", "Q-L9-TIMELINE.spl", "Q-L9-COMPARE.spl",
        "Q-L9-EXTERNAL-PIVOT.spl", "Q-L9-DETECTION-CANDIDATE.spl", "Q-L9-HUNT.spl",
    }
    assert {path.name for path in (LAB / "searches").glob("*.spl")} == expected
    for name in expected:
        text = (LAB / "searches" / name).read_text(encoding="utf-8")
        assert "index=agentsec_telemetry" in text
        assert "index=*" not in text
        assert "transaction" not in text
    candidate = (LAB / "searches" / "Q-L9-DETECTION-CANDIDATE.spl").read_text(encoding="utf-8")
    assert "DETECTION CANDIDATE — NOT INSTALLED" in candidate
    compare = (LAB / "searches" / "Q-L9-COMPARE.spl").read_text(encoding="utf-8")
    assert "dc(_raw)" in compare and "DUPLICATE INDEXED COPIES" in compare


def test_artifact_requires_ledger_root_causes_and_three_reports():
    template = (LAB / "incident-artifact-template.md").read_text(encoding="utf-8")
    for term in (
        "Initial hypothesis", "Evidence-backed timeline", "Evidence graph",
        "Evidence ledger", "Alternative explanation", "Missing evidence",
        "Root cause and contributing factors", "Immediate containment",
        "Candidate detection", "Expanded hunt", "Threat-model update",
        "Privacy-model update", "SOC / incident-response report",
        "Engineering / architecture report", "Executive / CISO report",
    ):
        assert term.lower() in template.lower()
    assert "CLAIM STRENGTH <= EVIDENCE STRENGTH" in template


def test_framework_security_schema_and_pdp_invariants():
    md = _markdown()
    for term in (
        "EDUCATIONAL MAPPING", "OWASP", "MITRE ATLAS", "MAESTRO",
        "NIST AI RMF", "NIST Privacy Framework", "not certification",
        "not compliance validation",
    ):
        assert term.lower() in md.lower()
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    assert coded_policy().allowed_tools == frozenset({"lookup_policy"})
    assert not any("external" in name or "evidence" in name for name in inspect.signature(authorize_tool).parameters)
    assert "CTRL-MCP-001" in md
    assert "Splunk" in md
