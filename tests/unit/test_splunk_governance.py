"""Governance files for AgentSec Splunk knowledge-object review.

These tests do not execute SPL and do not prove live Splunk behavior.
They lock the Cursor discovery path and review gates.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULE = ROOT / ".cursor" / "rules" / "33-splunk-agent-skills.mdc"
SKILL = ROOT / ".cursor" / "skills" / "splunk-ko-review" / "SKILL.md"
SKILL_REF = ROOT / ".cursor" / "skills" / "splunk-ko-review" / "reference.md"
INVENTORY = ROOT / "docs" / "SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md"
GOVERNANCE = ROOT / "docs" / "SPLUNK_ENGINEERING_GOVERNANCE.md"
BASELINE = ROOT / "docs" / "reviews" / "splunk-ko-review-baseline-2026-09-15.md"
NOTE = ROOT / "docs" / "learning-notes" / "splunk-engineering-governance.md"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
AFTER = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AFTER-DENY.spl"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
DELEGATION = ROOT / "learning" / "level_1" / "LAB-MCP-006" / "searches" / "Q-MCP-DELEGATION.spl"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
RUNTIME = ROOT / "src" / "agentsec" / "mcp" / "delegation.py"


def test_governance_files_exist():
    for path in (RULE, SKILL, SKILL_REF, INVENTORY, GOVERNANCE, BASELINE, NOTE):
        assert path.is_file(), path


def test_rule_is_glob_scoped_not_always_apply():
    text = RULE.read_text(encoding="utf-8")
    assert "alwaysApply: false" in text
    assert "alwaysApply: true" not in text
    assert "splunk_app/**" in text
    assert "learning/**/searches/**" in text
    assert "write SPL first" in text
    assert "SECURITY / OPERATIONAL QUESTION" in text
    assert "TELEMETRY GAP" in text
    assert "DETECTION ANALYZED" in text
    assert "splunk-ko-review" in text
    assert "https://splunkbase.splunk.com/skills" in text


def test_skill_has_required_review_template():
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---")
    assert "name: splunk-ko-review" in text
    for needle in (
        "SPLUNK KNOWLEDGE OBJECT REVIEW",
        "INDEXED FIELDS VERIFIED:",
        "FIELD CONTRACT:",
        "CORRELATION CONTRACT:",
        "DETECTION READINESS:",
        "LIVE SPLUNK VALIDATION:",
        "DASHBOARD CONSUMER:",
        "TELEMETRY SOURCE:",
        "VERDICT:",
        "DO NOT PUBLISH",
        "HUNT ONLY",
        "CIM:",
        "ALLOW does not mean execution",
    ):
        assert needle in text, needle
    assert "write SPL first" in text


def test_official_skills_are_catalog_names_not_invented():
    ref = SKILL_REF.read_text(encoding="utf-8")
    for skill in (
        "Splunk Search",
        "Search Performance Optimizer",
        "Search and Dashboard Troubleshooter",
        "Field Extraction and CIM Mapping",
        "Knowledge Object Governance",
        "Dashboard, Report, and Alert Performance Advisor",
        "Report Authoring Specialist",
        "Alerting and Notable Workflows",
        "Data Model and Search Acceleration",
        "Data Source Onboarding Advisor",
        "Ingestion Pipeline Design",
        "HEC Setup and Troubleshooting",
        "App and Add-on Lifecycle Advisor",
    ):
        assert skill in ref, skill
    assert "Do not invent" in ref


def test_inventory_covers_required_labs_and_objects():
    text = INVENTORY.read_text(encoding="utf-8")
    for needle in (
        "LAB-PI-001",
        "LAB-MCP-001",
        "LAB-MCP-003",
        "LAB-MCP-004",
        "LAB-MCP-005",
        "LAB-MCP-006",
        "Q-RUN-EVENTS",
        "Q-MCP-AUTHZ",
        "Q-MCP-AFTER-DENY",
        "Q-MCP-RESOURCE-AUTHZ",
        "Q-MCP-RESULT-AUTHORITY",
        "Q-MCP-DELEGATION",
        "Q-MCP-CATALOG-AUTHORITY",
        "Q-RAG-CONTEXT-AUTHORITY",
        "Q-MEMORY-CONTEXT-AUTHORITY",
        "DET-MCP-001",
        "ws_lab_mcp_006",
        "ws_lab_mcp_catalog",
        "ws_lab_scanner_runtime_evidence",
        "ws_lab_external_evaluation_garak",
        "Q-SCANNER-WHO",
        "Q-GARAK-EVALUATION",
        "Q-EXTERNAL-EVIDENCE-PLANES",
        "savedsearches.conf",
        "Q-RUN",
        "Q-DENY",
        "agentsec_index",
        "VALIDATION STATUS",
        "DASHBOARD CONSUMER",
        "DETECTION/HUNT",
        "SCHEMA VERSION DEPENDENCY",
    ):
        assert needle in text, needle


def test_discoverability_docs_point_at_rule_and_skill():
    blob = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (GOVERNANCE, NOTE, ROOT / "docs" / "MCP_SEARCH_CONTRACT.md")
    )
    assert ".cursor/rules/33-splunk-agent-skills.mdc" in blob
    assert ".cursor/skills/splunk-ko-review/SKILL.md" in blob
    assert ".cursor/rules/32-ui-design-system.mdc" in blob
    assert "/ui-review" in blob
    assert "/logic-proof" in blob
    assert "splunk-ko-review for all new or materially changed" in GOVERNANCE.read_text(
        encoding="utf-8"
    )


def test_baseline_reviews_cover_required_sample():
    text = BASELINE.read_text(encoding="utf-8")
    for obj in (
        "Q-MCP-AUTHZ",
        "Q-MCP-AFTER-DENY",
        "DET-MCP-001",
        "ds_q_delegation",
        "Q-MCP-DELEGATION",
    ):
        assert obj in text, obj
    assert text.count("SPLUNK KNOWLEDGE OBJECT REVIEW") >= 5
    assert "does not redesign" in text.lower()


def test_governance_did_not_rewrite_validated_spl():
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0")
    assert '"event.name"=agentsec.control.decision' in authz
    after = AFTER.read_text(encoding="utf-8")
    assert "sequence>deny_seq" in after
    det = DET.read_text(encoding="utf-8")
    assert "sequence>deny_sequence" in det
    assert "__RUN_ID__" not in det
    delegation = DELEGATION.read_text(encoding="utf-8")
    assert "CTRL-DELEGATION-001" in delegation
    assert "deputy_not_on_indexed_hop1" in delegation


def test_schema_and_runtime_markers_still_present():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert "1.4.0" in schema
    runtime = RUNTIME.read_text(encoding="utf-8")
    assert "CTRL-DELEGATION-001" in runtime
    assert "ambient_deputy" in runtime
