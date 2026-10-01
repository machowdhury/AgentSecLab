"""Offline contracts for the bounded HITL approval workshop.

These tests inspect static artifacts. They do not prove a runtime approval
service, approver authentication, approval authority, or resource impact.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.authorize import CONTROL_ID

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-HITL-APPROVAL"
PACKET = LAB / "evidence.packet.json"
DEFINITION = LAB / "dashboard.definition.json"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"


def _packet() -> dict:
    return json.loads(PACKET.read_text(encoding="utf-8"))


def test_workshop_is_replay_and_not_a_live_lab():
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    matches = [row for row in curriculum["checkpoints"] if row["id"] == "HITL-APPROVAL"]
    assert len(matches) == 1
    checkpoint = matches[0]
    assert checkpoint["live_launcher"] is False
    assert checkpoint["lab_id"] not in known_lab_ids()
    assert not (LAB / "lab-manifest.json").exists()
    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_lab_a2a_auth_delegation") < nav.index(
        "ws_lab_hitl_approval"
    ) < nav.index("ws_lab_privacy_data_governance")


def test_attack_and_retest_share_the_mutated_request():
    modes = {row["mode"]: row for row in _packet()["modes"]}
    attack = modes["ATTACK"]
    retest = modes["RETEST"]
    baseline = modes["BASELINE"]
    for row in (attack, retest):
        assert row["submitted_tool"] == "lookup_policy"
        assert row["submitted_resource"] == "executive-restricted"
        assert row["binding"] == "MISMATCH"
        assert row["approval_validity"] == "INSIDE WINDOW"
    assert attack["ctrl_mcp_001_decision"] == "ALLOW"
    assert attack["ctrl_mcp_001_reason"] == (
        "vulnerable_profile_fail_open:stale_approval_accepted"
    )
    assert retest["ctrl_mcp_001_decision"] == "DENY"
    assert retest["ctrl_mcp_001_reason"] == "approval_binding_mismatch"
    assert "do not infer" in retest["execution_observed"].lower()
    assert baseline["submitted_resource"] == "lending-basics"
    assert baseline["binding"] == "MATCH"
    assert baseline["ctrl_mcp_001_decision"] == "ALLOW"
    assert baseline["ctrl_mcp_001_reason"] == "tool_granted"


def test_approval_is_simulated_and_not_schema_or_secrets():
    packet = _packet()
    approval = packet["approval"]
    assert approval["record_label"] == "SIMULATED APPROVAL DECISION"
    assert approval["approver_authentication"] == "SIMULATED APPROVER AUTHENTICATION RESULT"
    assert approval["approval_authority"] == "NOT PROVEN"
    assert "not schema principal.type" in approval["approver_type_claim"]
    assert approval["credential_reference"] == "sim-auth-ref-approver-001"
    serialized = json.dumps(packet)
    assert "-----BEGIN" not in serialized
    assert "eyJ" not in serialized
    assert "principal.type" not in serialized or "not schema principal.type" in serialized
    definition = DEFINITION.read_text(encoding="utf-8")
    assert "| --- |" not in definition
    assert "Approved tool" in definition or "Approved tool" in definition
    assert "lending-basics" in definition
    assert "executive-restricted" in definition


def test_runtime_boundaries_stay_unchanged():
    assert CONTROL_ID == "CTRL-MCP-001"
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert "REQUIRE_APPROVAL" not in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-HITL" not in saved
    assert "approval_binding_mismatch" not in (
        ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
    ).read_text(encoding="utf-8")
