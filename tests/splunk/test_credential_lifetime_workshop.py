"""Offline contracts for the bounded credential-lifetime workshop.

These tests inspect static artifacts. They do not prove credential issuance,
expiry enforcement, revocation, or tool authorization.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.authorize import CONTROL_ID

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-CREDENTIAL-LIFETIME"
PACKET = LAB / "evidence.packet.json"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"


def _packet() -> dict:
    return json.loads(PACKET.read_text(encoding="utf-8"))


def test_workshop_is_replay_after_hitl():
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    matches = [row for row in curriculum["checkpoints"] if row["id"] == "CREDENTIAL-LIFETIME"]
    assert len(matches) == 1
    assert matches[0]["live_launcher"] is False
    assert matches[0]["lab_id"] not in known_lab_ids()
    assert not (LAB / "lab-manifest.json").exists()
    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_lab_hitl_approval") < nav.index(
        "ws_lab_credential_lifetime"
    ) < nav.index("ws_lab_privacy_data_governance")


def test_expired_credential_request_is_shared_by_attack_and_retest():
    modes = {row["mode"]: row for row in _packet()["modes"]}
    attack, retest, baseline = modes["ATTACK"], modes["RETEST"], modes["BASELINE"]
    for row in (attack, retest):
        assert row["credential_reference"] == "sim-cred-expired-001"
        assert row["credential_status"] == "EXPIRED"
        assert row["requested_tool"] == "lookup_customer_tier"
        assert row["requested_resource"] == "cust-001"
    assert attack["ctrl_mcp_001_decision"] == "ALLOW"
    assert attack["ctrl_mcp_001_reason"] == (
        "vulnerable_profile_fail_open:expired_credential_accepted"
    )
    assert retest["ctrl_mcp_001_decision"] == "DENY"
    assert retest["ctrl_mcp_001_reason"] == "expired_credential"
    assert baseline["credential_status"] == "CURRENT"
    assert baseline["requested_tool"] == "lookup_policy"
    assert baseline["ctrl_mcp_001_reason"] == "tool_granted"
    assert "did not itself authorize" in baseline["note"]


def test_synthetic_references_and_separate_approval_clock():
    packet = _packet()
    serialized = json.dumps(packet)
    assert packet["not_oauth"] is True
    assert packet["not_pki"] is True
    assert packet["approval_expires_at"] == "2026-10-01T16:05:00Z"
    assert packet["credentials"][0]["expires_at"] == "2026-10-01T13:00:00Z"
    assert "-----BEGIN" not in serialized
    assert "eyJ" not in serialized
    assert "sk_live_" not in serialized
    assert "AKIA" not in serialized
    authorize = (ROOT / "src" / "agentsec" / "mcp" / "authorize.py").read_text(encoding="utf-8")
    assert "expired_credential" not in authorize
    assert CONTROL_ID == "CTRL-MCP-001"
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
