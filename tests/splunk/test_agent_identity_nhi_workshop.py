"""Offline contracts for the Agent Identity and Non-Human IAM workshop.

These tests do not execute SPL against Splunk and do not prove browser
rendering, authentication, or control effectiveness.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.authorize import CONTROL_ID

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-AGENT-IDENTITY-NHI"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_agent_identity_nhi.xml"
)
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def _markdown() -> str:
    definition = _definition()
    parts = []
    for viz in definition["visualizations"].values():
        if viz.get("type") == "splunk.markdown":
            parts.append(viz["options"]["markdown"])
    return "\n".join(parts)


def _tab(layout_id: str) -> str:
    definition = _definition()
    parts = []
    for row in definition["layout"]["layoutDefinitions"][layout_id]["structure"]:
        viz = definition["visualizations"][row["item"]]
        if viz.get("type") == "splunk.markdown":
            parts.append(viz["options"]["markdown"])
    return "\n".join(parts)


def test_checkpoint_sits_between_l7_and_l8():
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    ids = [row["id"] for row in curriculum["levels"]]
    assert ids == ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10"]
    checkpoint = next(row for row in curriculum["checkpoints"] if row["id"] == "AGENT-IDENTITY-NHI")
    assert checkpoint["placement"] == "L7 → Identity/NHI Workshop → L8"
    assert checkpoint["mode"] == "REPLAY"
    assert checkpoint["live_launcher"] is False
    assert checkpoint["lab_id"] == "LAB-AGENT-IDENTITY-NHI"
    assert checkpoint["lab_id"] not in known_lab_ids()
    assert not (LAB / "lab-manifest.json").is_file()
    labels = [row["label"] for row in curriculum["nav_collections"]]
    assert labels.index("Security Architecture") < labels.index("Agent Identity") < labels.index(
        "Privacy & Data Governance"
    )
    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_lab_threat_modeling") < nav.index("ws_lab_agent_identity_nhi")
    assert nav.index("ws_lab_agent_identity_nhi") < nav.index("ws_lab_privacy_data_governance")
    l8 = next(row for row in curriculum["levels"] if row["id"] == "L8")
    assert "Agent Identity and Non-Human IAM workshop" in l8["prerequisites"]


def test_mission_starts_from_a_question_not_a_run():
    mission = _tab("layout_mission")
    assert "Who or what requested the delegated operation" in mission
    assert UUID.search(mission) is None
    assert "tool_not_granted" not in mission
    assert "vulnerable_profile_fail_open" not in mission
    assert _definition()["inputs"] == {}
    assert [row["label"] for row in _definition()["layout"]["tabs"]["items"]] == [
        "MISSION",
        "DISCOVER",
        "IDENTITY",
        "AUTHORITY",
        "EXECUTION",
        "COMPARE",
        "EVIDENCE LEDGER",
        "GAPS",
        "PATH B · REVIEW",
    ]


def test_searches_use_the_indexed_workflow_not_the_lab_contract():
    queries = "\n".join(
        ds["options"]["query"] for ds in _definition()["dataSources"].values()
    )
    assert '"agentsec.workflow.entry"="/identity/delegate"' in queries
    assert "LAB-AGENT-DELEGATION-001" not in queries
    assert "earliest=0" in queries
    assert "index=*" not in queries
    for name in ("Q-ID-MODES.spl", "Q-ID-CONTROLS.spl", "Q-ID-STARTS.spl"):
        text = (LAB / "searches" / name).read_text(encoding="utf-8")
        assert "LAB-AGENT-DELEGATION-001" not in text
        assert "agentsec.testbed.mode" in text or name == "Q-ID-STARTS.spl"


def test_claim_boundaries_stay_bounded():
    text = _markdown()
    assert "CTRL-IDENTITY-001" in text
    assert "does not authenticate a principal" in text
    assert "does not authorize a tool" in text
    assert "tool policy decision point" in text
    assert CONTROL_ID == "CTRL-MCP-001"
    assert "agentsec.mcp.started" in text
    assert "bounded to observed runtime execution" in text
    assert "`applicant-web` is a human. Boundary: **NOT PROVEN**" in text
    assert "`applicant-web` authenticated. Boundary: **NOT PROVEN / NOT MODELED**" in text
    assert "acme-agent-advisor-005" in text
    assert "acme-agent-fulfillment-006" in text
    assert "possessed legitimate delegated authority. Boundary: **NOT PROVEN**" in text
    assert "`gen_ai.agent.id` proves execution. Boundary: **FALSE**" in text
    assert "agentsec.principal.type" in text
    assert "does not mean an authenticated human" in text
    assert "LABELED AUTHORIZATION FAULT" in text
    assert "not authenticated delegation" in text
    assert "FUTURE / NOT MODELED" in text
    assert "short-lived credentials" in text
    assert "NOT MODELED" in text
    assert "SAFE" in text
    assert "Do not say SAFE" in text or "Do not fill the gap with SAFE" in text


def test_runtime_contracts_are_unchanged():
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    saved = SAVED.read_text(encoding="utf-8")
    assert "LAB-AGENT-IDENTITY-NHI" not in saved
    assert "DET-MCP-001" in saved
    assert "disabled = 1" in saved
    assert VIEW.is_file()
    xml = VIEW.read_text(encoding="utf-8")
    assert "<label>Agent Identity and Non-Human IAM</label>" in xml
    assert "LAB-AGENT-IDENTITY-NHI" in xml
