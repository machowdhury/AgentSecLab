"""Guided investigation metadata is learning-only, not policy."""

from __future__ import annotations

from agentsec.investigations import REQUIRED_KEYS, load_investigations, validate_investigations


def test_pi_investigations_are_learning_metadata_not_policy():
    data = load_investigations("LAB-PI-001")
    rows = validate_investigations("LAB-PI-001")
    assert data["lab_id"] == "LAB-PI-001"
    assert data["not_authorization"] is True
    assert data["studio_token_binding"] == "NOT SUPPORTED / DO NOT BUILD"
    ids = [row["investigation_id"] for row in rows]
    assert ids == [
        "PI-I1-FIND-THE-RUN",
        "PI-I2-RECONSTRUCT-SEQUENCE",
        "PI-I3-SECURITY-DECISION",
        "PI-I4-DID-EXECUTION-OCCUR",
        "PI-I5-BASELINE-VS-ATTACK",
        "PI-I6-WHAT-CAN-YOU-PROVE",
        "PI-I7-ATTACK-VS-RETEST",
    ]
    hunts = {row["related_hunt"] for row in rows}
    assert hunts <= {
        "Q-RUN-EVENTS",
        "Q-CONTROL-DECISION",
        "Q-LLM-EXECUTED",
        "Q-LLM-AFTER-DENY",
    }
    for row in rows:
        for key in REQUIRED_KEYS:
            assert key in row
        assert "DET-" not in row["related_hunt"]


def test_investigation_sequence_teaches_splunk_not_enforcement():
    rows = {row["investigation_id"]: row for row in validate_investigations("LAB-PI-001")}
    deny = rows["PI-I3-SECURITY-DECISION"]
    exec_row = rows["PI-I4-DID-EXECUTION-OCCUR"]
    prove = rows["PI-I6-WHAT-CAN-YOU-PROVE"]
    assert "Splunk" in deny["security_interpretation"]
    assert "not" in deny["security_interpretation"].lower()
    blob = exec_row["does_not_prove"].lower()
    assert "incomplete" in blob or "missing" in blob
    assert "DENY" in prove["hint_2"]
    assert "HEC" in prove["hint_2"]
    assert rows["PI-I5-BASELINE-VS-ATTACK"]["does_not_prove"].startswith("BASELINE is not SAFE")
    i7 = rows["PI-I7-ATTACK-VS-RETEST"]
    assert i7["investigation_kind"] == "paired_run"
    assert i7["studio_tab"] == "COMPARE"
    assert i7["pair_modes"] == ["ATTACK", "RETEST"]
    assert "Splunk did not ALLOW or DENY" in i7["security_interpretation"] or "Splunk did not" in i7["security_interpretation"]


def test_mcp_investigations_reuse_q_mcp_and_are_not_policy():
    data = load_investigations("LAB-MCP-001")
    rows = validate_investigations("LAB-MCP-001")
    assert data["not_authorization"] is True
    ids = [row["investigation_id"] for row in rows]
    assert ids == [
        "MCP-I1-FIND-THE-RUN",
        "MCP-I2-FIND-THE-REQUEST",
        "MCP-I3-AUTHORIZATION-DECISION",
        "MCP-I4-DID-HANDLER-START",
        "MCP-I5-WHAT-CAN-YOU-PROVE",
        "MCP-I6-ATTACK-VS-RETEST",
    ]
    hunts = {row["related_hunt"] for row in rows}
    assert hunts <= {
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
    }
    assert "DET-MCP-001" not in hunts
    i6 = {row["investigation_id"]: row for row in rows}["MCP-I6-ATTACK-VS-RETEST"]
    assert i6["studio_tab"] == "COMPARE"
    assert i6["investigation_kind"] == "paired_run"
