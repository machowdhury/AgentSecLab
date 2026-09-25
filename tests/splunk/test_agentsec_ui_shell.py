"""Global AgentSec UI shell contracts: navigation, dropdown hunts, no raw UUID fields."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"

LEARNER_VIEWS = (
    "ws_lab_pi_001.xml",
    "ws_lab_mcp_001.xml",
    "ws_lab_mcp_003.xml",
    "ws_lab_mcp_004.xml",
    "ws_lab_mcp_005.xml",
    "ws_lab_mcp_006.xml",
    "ws_lab_mcp_catalog.xml",
    "ws_lab_scanner_runtime_evidence.xml",
    "ws_lab_external_evaluation_garak.xml",
    "ws_lab_rag_context.xml",
    "ws_lab_memory_security.xml",
    "ws_lab_agent_goal_integrity.xml",
    "ws_lab_agent_delegation.xml",
    "ws_lab_agentsec_capstone.xml",
    "ws_lab_blue_team_incident.xml",
    "ws_lab_threat_modeling.xml",
    "ws_lab_privacy_data_governance.xml",
    "ws_lab_multi_stage_incident.xml",
    "ws_lab_advanced_capstone.xml",
)


def _definition(xml_name: str) -> dict:
    xml = (VIEWS / xml_name).read_text(encoding="utf-8")
    start = xml.index("<![CDATA[") + len("<![CDATA[")
    end = xml.index("]]>")
    return json.loads(xml[start:end].strip())


def test_nav_is_grouped_and_home_is_default():
    nav = NAV.read_text(encoding="utf-8")
    assert 'name="ws_agentsec_home" default="true"' in nav
    for label in (
        "Foundations",
        "Context Security",
        "Agent Intent",
        "Capstone",
        "Blue Team",
        "Security Architecture",
        "Privacy &amp; Data Governance",
        "Integrated Incident",
        "Advanced Capstone",
    ):
        assert f'<collection label="{label}">' in nav
    assert "Attack Labs" not in nav
    assert "Agent Authority" not in nav
    assert "Supply Chain" not in nav
    assert nav.index("Foundations") < nav.index("Context Security") < nav.index(
        "Agent Intent"
    ) < nav.index("Capstone")
    assert nav.index("ws_lab_agent_goal_integrity") < nav.index("ws_lab_agentsec_capstone")
    assert nav.index("ws_lab_agent_delegation") < nav.index("ws_lab_agentsec_capstone")
    assert nav.index("ws_lab_agentsec_capstone") < nav.index("ws_lab_blue_team_incident")
    assert nav.index("ws_lab_blue_team_incident") < nav.index("ws_lab_threat_modeling")
    assert nav.index("ws_lab_threat_modeling") < nav.index("ws_lab_privacy_data_governance")
    assert nav.index("ws_lab_privacy_data_governance") < nav.index("ws_lab_multi_stage_incident")
    assert nav.index("ws_lab_multi_stage_incident") < nav.index("ws_lab_advanced_capstone")
    assert "<collection label=" in nav
    assert not re.search(r"<view name=\"ws_lab_[^\"]+\" default=", nav)
    # LAB-* ids must not be the visible nav labels; they live in XML descriptions.
    assert "LAB-AGENT-GOAL-INTEGRITY-001" not in nav
    assert "ws_lab_agent_goal_integrity" in nav
    assert "ws_lab_agent_delegation" in nav
    assert "LAB-AGENT-DELEGATION-001" not in nav
    assert "<view name=\"search\"" in nav
    assert ">Scope Escalation</view>" in nav
    assert ">Goal / Instruction Integrity</view>" in nav
    assert "LAB-AGENT-GOAL-INTEGRITY-001" not in nav


def test_learner_views_use_dropdown_not_uuid_text():
    for name in LEARNER_VIEWS:
        definition = _definition(name)
        assert definition["layout"]["options"]["submitButton"] is False, name
        assert definition["layout"]["options"]["submitOnDashboardLoad"] is True, name
        for inp in definition["inputs"].values():
            assert inp["type"] == "input.dropdown", f"{name} {inp}"
            assert "Investigate" in inp["title"], f"{name} {inp['title']}"
            items = inp["options"]["items"]
            assert items, name
            for item in items:
                assert item["label"]
                assert item["value"]
                assert item["label"] != item["value"]
                assert " " in item["label"] or "—" in item["label"]
        titles = {inp["title"] for inp in definition["inputs"].values()}
        assert "Hunt" not in titles, name
        assert "Hunt run_id" not in titles, name
        assert "BASELINE" not in titles, name
        assert "ATTACK" not in titles, name
        assert "RETEST" not in titles, name


def test_xml_labels_are_human_readable():
    expected = {
        "ws_lab_pi_001.xml": "Direct Prompt Injection",
        "ws_lab_mcp_001.xml": "Tool Authorization",
        "ws_lab_mcp_003.xml": "Scope Escalation",
        "ws_lab_mcp_004.xml": "Parameter / Resource Authorization",
        "ws_lab_mcp_005.xml": "Tool Result Trust",
        "ws_lab_mcp_006.xml": "Confused Deputy",
        "ws_lab_mcp_catalog.xml": "Tool Catalog",
        "ws_lab_scanner_runtime_evidence.xml": "Scanner + Runtime Evidence",
        "ws_lab_external_evaluation_garak.xml": "External Security Toolbox",
        "ws_lab_rag_context.xml": "RAG / Retrieved Context",
        "ws_lab_memory_security.xml": "Persistent Memory",
        "ws_lab_agent_goal_integrity.xml": "Goal / Instruction Integrity",
        "ws_lab_agent_delegation.xml": "Agent Identity / Delegation",
        "ws_lab_agentsec_capstone.xml": "Lending Assistant Investigation",
        "ws_lab_blue_team_incident.xml": "AcmeBank Incident AI-2026-001",
        "ws_lab_threat_modeling.xml": "Threat Modeling and Security Architecture",
        "ws_lab_privacy_data_governance.xml": "Privacy and Data Governance",
        "ws_lab_multi_stage_incident.xml": "Acme Bank Incident AGENT-2026-009",
        "ws_lab_advanced_capstone.xml": "Acme Bank Capstone MASTER-2026-001",
        "ws_agentsec_home.xml": "Home",
        "ws_agentsec_mastery.xml": "Mastery Check",
    }
    for name, label in expected.items():
        xml = (VIEWS / name).read_text(encoding="utf-8")
        assert f"<label>{label}</label>" in xml, name
        if name not in {"ws_agentsec_home.xml", "ws_agentsec_mastery.xml"}:
            assert "LAB-" in xml, name


def test_schema_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema


def test_no_gfm_tables_in_studio_markdown():
    for name in LEARNER_VIEWS + ("ws_agentsec_home.xml", "ws_agentsec_mastery.xml"):
        definition = _definition(name)
        for viz_id, viz in definition["visualizations"].items():
            if viz.get("type") != "splunk.markdown":
                continue
            md = viz["options"]["markdown"]
            assert "| --- |" not in md, f"{name} {viz_id}"
            assert "|---|" not in md.replace(" ", ""), f"{name} {viz_id}"
            # Catch leftover GFM table cells (sentence + trailing pipe), not ASCII trees.
            for line in md.splitlines():
                if re.search(r"[A-Za-z0-9.]\s+\|\s*$", line):
                    raise AssertionError(f"{name} {viz_id} trailing GFM pipe: {line}")


def test_nav_learner_labels_are_human():
    nav = NAV.read_text(encoding="utf-8")
    for match in re.finditer(r'<view name="(ws_lab_[^"]+)"(?:\s*/>|>([^<]*)</view>)', nav):
        name, inner = match.group(1), (match.group(2) or "").strip()
        assert inner, f"{name} missing human nav label"
        assert not inner.startswith("ws_lab_"), inner
        assert not inner.startswith("LAB-"), inner


def test_no_paste_uuid_into_removed_hunt_field():
    for name in LEARNER_VIEWS:
        definition = _definition(name)
        for viz_id, viz in definition["visualizations"].items():
            if viz.get("type") != "splunk.markdown":
                continue
            md = viz["options"]["markdown"]
            lowered = md.lower()
            assert "paste the attack" not in lowered, f"{name} {viz_id}"
            assert "paste the retest" not in lowered, f"{name} {viz_id}"
            assert "into **hunt run.id**" not in lowered, f"{name} {viz_id}"


def test_view_xml_is_well_formed():
    import xml.etree.ElementTree as ET

    for xml_path in sorted(VIEWS.glob("ws_*.xml")):
        ET.parse(xml_path)
        text = xml_path.read_text(encoding="utf-8")
        assert "PLACEHOLDER" not in text, xml_path.name
        assert "</description>" in text, xml_path.name
        assert "<![CDATA[" in text, xml_path.name
