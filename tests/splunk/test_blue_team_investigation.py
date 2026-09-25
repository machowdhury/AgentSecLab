"""Offline contracts for the blue-team REPLAY workbench.

These tests do not execute SPL against Splunk and do not prove browser
rendering, event completeness, or control effectiveness.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.mcp.authorize import authorize_tool

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-BLUE-TEAM-INCIDENT-001"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_blue_team_incident.xml"
)
SEARCHES = LAB / "searches"


def _definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def _markdown() -> str:
    return "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz.get("type") == "splunk.markdown"
    )


def test_route_builder_and_curriculum_registration():
    assert (ROOT / "scripts" / "build_lab_blue_team_incident_dashboard.py").is_file()
    assert DEFINITION.is_file()
    assert VIEW.is_file()
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    level = next(row for row in curriculum["levels"] if row["id"] == "L6")
    assert level["labs"] == [
        {
            "lab_id": "LAB-BLUE-TEAM-INCIDENT-001",
            "title": "AcmeBank Incident AI-2026-001",
            "mode": "REPLAY",
            "view": "ws_lab_blue_team_incident",
        }
    ]
    assert next(row for row in curriculum["levels"] if row["id"] == "L5")["labs"][0][
        "mode"
    ] == "LIVE"
    for relative in (
        "docs/BLUE_TEAM_INVESTIGATION_AND_THREAT_HUNTING.md",
        "docs/BLUE_TEAM_LIVE_SPLUNK_VALIDATION.md",
        "docs/learning-notes/blue-team-investigation.md",
        "docs/reviews/splunk-ko-review-blue-team-incident-2026-09-24.md",
        "docs/reviews/logic-proof-blue-team-incident-2026-09-24.md",
        "docs/reviews/ui-review-blue-team-incident-2026-09-24.md",
    ):
        assert (ROOT / relative).is_file(), relative


def test_hint_progression_and_answer_separation():
    definition = _definition()
    labels = [row["label"] for row in definition["layout"]["tabs"]["items"]]
    assert labels == [
        "INCIDENT",
        "INVESTIGATE",
        "EVIDENCE · WORKBENCH",
        "PATH B · ANSWERS",
    ]
    investigate = definition["visualizations"]["viz_hints"]["options"]["markdown"]
    assert investigate.index("HINT 1") < investigate.index("HINT 2")
    assert investigate.index("HINT 2") < investigate.index("HINT 3")
    assert investigate.index("HINT 3") < investigate.index("HINT 4")
    incident = definition["visualizations"]["viz_mission"]["options"]["markdown"]
    for leaked in (
        "vulnerable_profile_fail_open",
        "tool_not_granted",
        "CTRL-MCP-001 ALLOW",
        "CTRL-MCP-001 DENY",
        "handler invocation count",
    ):
        assert leaked not in incident
    assert "Write an initial hypothesis" in incident


def test_methodology_levels_ledger_report_and_competencies():
    md = _markdown()
    for needle in (
        "INITIAL HYPOTHESIS",
        "SUPPORT / REFUTE",
        "REVISED HYPOTHESIS",
        "LEVEL 1 — GUIDED ANALYST",
        "LEVEL 2 — INVESTIGATOR",
        "LEVEL 3 — THREAT HUNTER",
        "FACT / INFERENCE / HYPOTHESIS / UNKNOWN",
        "Executive Summary",
        "Technical",
        "Executive",
        "Threat-model bridge",
    ):
        assert needle in md
    assessments = json.loads(
        (ROOT / "learning" / "academy" / "assessments.json").read_text(encoding="utf-8")
    )
    competencies = assessments["blue_team_competencies"]
    assert competencies["tracking"] == "SELF_ASSESSED / NO PERSISTENCE / NOT CERTIFICATION"
    assert competencies["dimensions"] == [
        "SEARCH",
        "CORRELATE",
        "RECONSTRUCT",
        "HYPOTHESIZE",
        "VALIDATE",
        "CHALLENGE",
        "DETECT",
        "REPORT",
        "THREAT MODEL",
    ]


def test_spl_contracts_and_sourcetype_separation():
    names = {path.name for path in SEARCHES.glob("*.spl")}
    assert names == {
        "Q-INCIDENT-CANDIDATES.spl",
        "Q-INCIDENT-TIMELINE.spl",
        "Q-INCIDENT-COMPARE.spl",
    }
    blob = "\n".join(path.read_text(encoding="utf-8") for path in SEARCHES.glob("*.spl"))
    assert "index=agentsec_telemetry sourcetype=otel:agentic:json" in blob
    assert "index=*" not in blob
    assert "transaction" not in blob
    assert "agentsec.sequence" in blob
    md = _markdown()
    assert "agentsec:scanner:finding" in md
    assert "agentsec:external:evaluation" in md
    assert "otel:agentic:json" in md
    assert "No causal join is defensible" in md


def test_correlation_and_execution_claims_are_bounded():
    md = _markdown()
    for needle in (
        "Correlation is not causation",
        "Authorization is not execution",
        "Execution started is not completion",
        "No evidence is not safe",
        "MATCH != MALICIOUS",
        "NOT MODELED",
        "NOT OBSERVED",
        "NOT PROVEN",
    ):
        assert needle in md
    investigations = json.loads((LAB / "investigations.json").read_text(encoding="utf-8"))
    assert investigations["unsupported_links"]["retrieve_output_to_write"] == "NOT MODELED"
    assert investigations["unsupported_links"]["external_evidence_to_runtime"] == "NOT OBSERVED"
    assert investigations["unsupported_links"]["universal_retest_resistance"] == "NOT PROVEN"


def test_failure_states_are_explicit_and_not_safe():
    definition = _definition()
    messages = "\n".join(
        viz["options"].get("noDataMessage", "")
        for viz in definition["visualizations"].values()
    )
    assert "NO EVIDENCE FOUND" in messages
    assert "Splunk availability" in messages
    assert "evidence-pack availability" in messages
    assert "not SAFE" in messages or "not make the candidate malicious or safe" in messages


def test_pdp_and_contract_invariants():
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    params = inspect.signature(authorize_tool).parameters
    assert not any("external" in name or "evidence" in name for name in params)
    authorization_source = (
        ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
    ).read_text(encoding="utf-8")
    assert "external_evidence" not in authorization_source
    saved = (
        ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
    ).read_text(encoding="utf-8")
    assert saved.count("[AgentSec -") == 1
    assert "DET-BLUE" not in saved


def test_knowledge_check_and_attribution_boundaries():
    check = (LAB / "knowledge-check.md").read_text(encoding="utf-8")
    for needle in (
        "request",
        "authorization",
        "invocation",
        "completion",
        "matching content hash",
        "external",
        "technical",
        "executive",
    ):
        assert needle.lower() in check.lower()
    assert "Cisco scanner findings and garak evaluations" in (
        LAB / "workshop.md"
    ).read_text(encoding="utf-8")
