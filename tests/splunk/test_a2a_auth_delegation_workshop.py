"""Offline contracts for the bounded A2A Authentication and Delegation workshop.

These tests inspect static artifacts. They do not prove runtime authentication,
delegation enforcement, live Splunk behavior, or downstream resource impact.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.authorize import CONTROL_ID

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-A2A-AUTH-DELEGATION"
PACKET = LAB / "evidence.packet.json"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_a2a_auth_delegation.xml"
)
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"


def _packet() -> dict:
    return json.loads(PACKET.read_text(encoding="utf-8"))


def _markdown() -> str:
    definition = json.loads(DEFINITION.read_text(encoding="utf-8"))
    return "\n".join(
        viz["options"]["markdown"]
        for viz in definition["visualizations"].values()
        if viz.get("type") == "splunk.markdown"
    )


def test_workshop_exists_once_in_the_required_replay_placement():
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    assert [row["id"] for row in curriculum["levels"]] == [
        "L0",
        "L1",
        "L2",
        "L3",
        "L4",
        "L5",
        "L6",
        "L7",
        "L8",
        "L9",
        "L10",
    ]
    matches = [row for row in curriculum["checkpoints"] if row["id"] == "A2A-AUTH-DELEGATION"]
    assert len(matches) == 1
    checkpoint = matches[0]
    assert checkpoint["placement"] == (
        "L7 → Identity/NHI Workshop → A2A Authentication & Delegation Workshop → L8"
    )
    assert checkpoint["mode"] == "REPLAY"
    assert checkpoint["live_launcher"] is False
    assert checkpoint["evidence_class"] == "SIMULATED / REPLAYED"
    assert checkpoint["lab_id"] not in known_lab_ids()
    assert not (LAB / "lab-manifest.json").exists()
    assert len(list(ROOT.glob("learning/**/LAB-A2A-AUTH-DELEGATION"))) == 1

    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_lab_agent_identity_nhi") < nav.index(
        "ws_lab_a2a_auth_delegation"
    ) < nav.index("ws_lab_privacy_data_governance")


def test_packet_implements_the_reviewed_three_mode_semantics():
    packet = _packet()
    assert packet["evidence_classification"] == "SIMULATED / REPLAYED"
    modes = {row["mode"]: row for row in packet["modes"]}
    assert set(modes) == {"ATTACK", "RETEST", "BASELINE"}

    attack = modes["ATTACK"]
    retest = modes["RETEST"]
    baseline = modes["BASELINE"]
    for row in (attack, retest):
        assert row["requested_tool"] == "lookup_customer_tier"
        assert row["requested_resource"] == "cust-001"
        assert row["delegated_tool"] == "lookup_policy"
        assert row["delegated_resource"] == "lending-basics"
        assert row["delegation_evaluation"] == "MISMATCH"
    assert attack["ctrl_mcp_001_decision"] == "ALLOW"
    assert "vulnerable_profile_fail_open" in attack["ctrl_mcp_001_reason"]
    assert retest["ctrl_mcp_001_decision"] == "DENY"
    assert retest["ctrl_mcp_001_reason"] == "tool_not_granted"

    assert baseline["requested_tool"] == baseline["delegated_tool"] == "lookup_policy"
    assert baseline["requested_resource"] == baseline["delegated_resource"] == "lending-basics"
    assert baseline["delegation_evaluation"] == "MATCH"
    assert baseline["ctrl_mcp_001_decision"] == "ALLOW"
    assert baseline["ctrl_mcp_001_reason"] == "tool_granted"


def test_authentication_and_delegation_are_labeled_simulated_and_secret_free():
    packet = _packet()
    assert packet["not_runtime_telemetry"] is True
    assert packet["not_production_iam"] is True
    serialized = json.dumps(packet)
    for row in packet["authentication"]:
        assert row["record_label"] == "SIMULATED AUTHENTICATION RESULT"
        assert row["principal_type"] == "agent"
        assert row["credential_reference"].startswith("sim-auth-ref-")
        assert row["result"] == "AUTHENTICATED"
    for row in packet["modes"]:
        assert row["delegation_record_label"] == "SIMULATED DELEGATION DECISION"
        assert row["delegation_id"].startswith("sim-delegation-")

    forbidden_secret_markers = (
        "BEGIN PRIVATE KEY",
        "BEGIN CERTIFICATE",
        "Authorization: Bearer",
        "sk_live_",
        "ghp_",
        "AKIA",
    )
    assert not any(marker in serialized for marker in forbidden_secret_markers)
    assert ".env" not in serialized


def test_workshop_preserves_control_and_evidence_boundaries():
    text = _markdown()
    for required in (
        "CTRL-IDENTITY-001 observes a claim",
        "CTRL-MCP-001 remains the tool PDP",
        "authenticated agent = authorized request",
        "MATCH is not ALLOW",
        "MISMATCH is not DENY",
        "agentsec.mcp.started",
        "resource impact",
        "same-tool / different-resource",
        "NOT MODELED",
        "HISTORICAL CLAIM-ONLY CORPUS",
        "SIMULATED / REPLAYED",
    ):
        assert required in text
    assert CONTROL_ID == "CTRL-MCP-001"
    assert "CTRL-A2A-PDP" not in text
    assert "`applicant-web` is an authenticated human — **NOT PROVEN**" in text
    assert "does not transform it into measured authentication" in text


def test_runtime_detector_schema_and_external_contract_are_unchanged():
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    assert "LAB-A2A-AUTH-DELEGATION" not in known_lab_ids()
    saved = SAVED.read_text(encoding="utf-8")
    assert saved.count("disabled = 1") == 3
    assert "disabled = 0" not in saved
    assert "enableSched = 1" not in saved
    assert VIEW.is_file()
    assert "<label>A2A Authentication and Delegation</label>" in VIEW.read_text(
        encoding="utf-8"
    )
