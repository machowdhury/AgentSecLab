"""Offline contracts for the threat-modeling REPLAY architecture workbench."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.mcp.authorize import authorize_tool

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-THREAT-MODELING-001"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = (
    ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    / "ws_lab_threat_modeling.xml"
)


def _json(name: str) -> dict:
    return json.loads((LAB / name).read_text(encoding="utf-8"))


def _definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def _markdown(layout_ids: tuple[str, ...] | None = None) -> str:
    definition = _definition()
    if layout_ids is None:
        ids = definition["visualizations"]
    else:
        ids = [
            row["item"]
            for layout_id in layout_ids
            for row in definition["layout"]["layoutDefinitions"][layout_id]["structure"]
        ]
    return "\n".join(
        definition["visualizations"][viz_id]["options"]["markdown"] for viz_id in ids
    )


def test_curriculum_route_and_bounded_artifacts():
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    assert [row["id"] for row in curriculum["levels"]][-3:] == ["L6", "L7", "L8"]
    assert next(row for row in curriculum["levels"] if row["id"] == "L6")["next"] == "L7"
    level = next(row for row in curriculum["levels"] if row["id"] == "L7")
    assert level["exit"] == "SECURITY ARCHITECT"
    assert level["labs"] == [
        {
            "lab_id": "LAB-THREAT-MODELING-001",
            "title": "AcmeBank Agentic Customer Operations Platform",
            "mode": "REPLAY",
            "view": "ws_lab_threat_modeling",
        }
    ]
    assert curriculum["nav_collections"][-2] == {
        "label": "Security Architecture",
        "views": ["ws_lab_threat_modeling"],
    }
    for path in (
        DEFINITION,
        VIEW,
        LAB / "README.md",
        LAB / "challenge.md",
        LAB / "threat-model-template.md",
        LAB / "knowledge-check.md",
        LAB / "architecture.json",
        LAB / "threat-catalog.json",
        LAB / "investigations.json",
        ROOT / "scripts" / "build_lab_threat_modeling_dashboard.py",
    ):
        assert path.is_file(), path


def test_progressive_workflow_hints_and_answer_gating():
    definition = _definition()
    assert [row["label"] for row in definition["layout"]["tabs"]["items"]] == [
        "FOUNDATIONS",
        "SYSTEM · ARCHITECTURE",
        "MODEL · ANALYZE",
        "ARCHITECT CHALLENGE",
        "PATH B · REVIEW",
    ]
    investigations = _json("investigations.json")
    assert [row["id"] for row in investigations["hints"]] == [
        "HINT_1",
        "HINT_2",
        "HINT_3",
        "HINT_4",
    ]
    assert investigations["answer_gating"] == "PEDAGOGICAL"
    assert investigations["progress_persistence"] is False
    early = _markdown(
        ("layout_foundations", "layout_system", "layout_model", "layout_challenge")
    )
    review = _markdown(("layout_review",))
    for answer in (
        "A defensible model identifies",
        "Likely threat prompts include",
        "Residual risk remains because",
    ):
        assert answer not in early
        assert answer in review


def test_system_asset_actor_flow_boundary_and_authority_models():
    architecture = _json("architecture.json")
    assert architecture["runtime_schema"] == "1.9.0"
    assert architecture["external_evidence_contract"] == "1.0.0"
    assert {row["category"] for row in architecture["assets"]} == {
        "DATA",
        "AUTHORITY",
        "SYSTEM",
        "BUSINESS",
        "SECURITY EVIDENCE",
    }
    assert {row["kind"] for row in architecture["actors"]} >= {
        "HUMAN",
        "THREAT ACTOR",
        "SOFTWARE ACTOR",
        "SOFTWARE DEPENDENCY",
    }
    assert len(architecture["data_flows"]) == 10
    assert len(architecture["trust_boundaries"]) == 7
    authority = architecture["authority"]
    assert authority["authorizer"] == "CTRL-MCP-001 in McpServer.authorize"
    assert "opaque allow ticket" in authority["execution_gate"]
    assert authority["authentication"] == "NOT MODELED"
    assert authority["human_approval"] == "NOT MODELED"
    assert "cryptographic delegation NOT MODELED" in authority["delegation"]


def test_threat_control_telemetry_gap_and_residual_risk_reasoning():
    catalog = _json("threat-catalog.json")
    assert catalog["catalog_role"] == "REASONING PROMPTS / NOT A COMPLETED THREAT MODEL"
    for prompt in catalog["threats"]:
        assert prompt["assets"]
        assert prompt["boundaries"]
        assert prompt["existing_controls"]
        assert prompt["telemetry_required"]
        assert prompt["gap"]
        assert prompt["residual_risk"]
    md = _markdown()
    for needle in (
        "INFLUENCE != AUTHORITY",
        "CONTROL IMPLEMENTED != RISK ELIMINATED",
        "preventive, detective, corrective, or recovery",
        "OBSERVE",
        "ENFORCE",
        "NOT LOGGED",
        "NOT CRYPTOGRAPHICALLY ESTABLISHED",
        "what each event can and cannot prove",
    ):
        assert needle in md


def test_framework_lenses_are_validated_and_clearly_labeled():
    source = (
        ROOT / "docs" / "THREAT_MODEL_FRAMEWORK_VALIDATION.md"
    ).read_text(encoding="utf-8")
    md = _markdown()
    for needle in (
        "OWASP Top 10 for Agentic Applications 2026",
        "MITRE ATLAS",
        "MAESTRO",
        "EDUCATIONAL MAPPING",
        "This is not certification",
        "This is not compliance validation",
        "This is not complete framework coverage",
        "NEEDS_EXTERNAL_VALIDATION",
    ):
        assert needle in source
        assert needle in md
    assert "CSA MAESTRO v2" in md
    assert "NIST AI Risk Management Framework 1.0" in source
    assert "NIST AI RMF 1.0" in md
    for official_host in (
        "genai.owasp.org",
        "atlas.mitre.org",
        "cloudsecurityalliance.org",
        "nist.gov",
    ):
        assert official_host in source


def test_architect_artifact_communication_and_competency_progression():
    template = (LAB / "threat-model-template.md").read_text(encoding="utf-8")
    challenge = (LAB / "challenge.md").read_text(encoding="utf-8")
    for heading in (
        "Critical assets",
        "Data flows",
        "Trust boundaries",
        "Authority map",
        "Threat and control analysis",
        "Telemetry requirements",
        "Evidence gaps",
        "Residual risk",
        "Engineering",
        "SOC / Security Operations",
        "CISO / Leadership",
    ):
        assert heading in template
    assert "Do not assign a numerical risk score" in challenge
    assessments = json.loads(
        (ROOT / "learning" / "academy" / "assessments.json").read_text(encoding="utf-8")
    )
    competency = assessments["threat_modeling_competencies"]
    assert competency["tracking"] == "SELF_ASSESSED / NO PERSISTENCE / NOT CERTIFICATION"
    assert {"ANALYZE AUTHORITY", "STATE EVIDENCE GAPS", "COMMUNICATE"} <= set(
        competency["dimensions"]
    )


def test_security_semantics_schema_contract_and_no_new_detector():
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    params = inspect.signature(authorize_tool).parameters
    assert not any("external" in name or "evidence" in name for name in params)
    source = (
        ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
    ).read_text(encoding="utf-8")
    assert "external_evidence" not in source
    saved = (
        ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
    ).read_text(encoding="utf-8")
    assert saved.count("[AgentSec -") == 1
    assert "DET-THREAT" not in saved
    architecture = _json("architecture.json")
    assert architecture["model_boundaries"]["authentication"] == "NOT MODELED"
    assert architecture["model_boundaries"]["human_approval"] == "NOT MODELED"
