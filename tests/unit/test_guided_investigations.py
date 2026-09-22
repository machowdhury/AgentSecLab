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


def test_rag_investigations_are_learning_metadata_not_policy():
    data = load_investigations("LAB-RAG-CONTEXT")
    rows = validate_investigations("LAB-RAG-CONTEXT")
    assert data["not_authorization"] is True
    assert data["studio_token_binding"] == "NOT SUPPORTED / DO NOT BUILD"
    ids = [row["investigation_id"] for row in rows]
    assert ids == [
        "RAG-I1-FIND-RETRIEVED-CONTEXT",
        "RAG-I2-TRUST-CLASSIFICATION",
        "RAG-I3-INFLUENCE",
        "RAG-I4-WHO-AUTHORIZED",
        "RAG-I5-DID-HANDLER-START",
        "RAG-I6-SAME-CONTENT",
        "RAG-I7-WHAT-CAN-YOU-PROVE",
    ]
    hunts = {row["related_hunt"] for row in rows}
    assert hunts <= {
        "Q-RAG-CONTEXT-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-WHO",
    }
    assert "DET-RAG" not in hunts
    assert "DET-MCP-001" not in hunts
    by_id = {row["investigation_id"]: row for row in rows}
    assert by_id["RAG-I6-SAME-CONTENT"]["investigation_kind"] == "paired_run"
    assert by_id["RAG-I6-SAME-CONTENT"]["studio_tab"] == "COMPARE"
    assert "CTRL-RAG-CONTEXT-001" in by_id["RAG-I2-TRUST-CLASSIFICATION"]["related_control"]
    assert "CTRL-MCP-001" in by_id["RAG-I4-WHO-AUTHORIZED"]["related_control"]
    assert "INCORRECT" in by_id["RAG-I7-WHAT-CAN-YOU-PROVE"]["hint_2"]


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


def test_memory_investigations_reuse_q_memory_and_are_not_policy():
    data = load_investigations("LAB-MEMORY-001")
    rows = validate_investigations("LAB-MEMORY-001")
    assert data["not_authorization"] is True
    assert data["studio_token_binding"] == "NOT SUPPORTED / DO NOT BUILD"
    ids = [row["investigation_id"] for row in rows]
    assert ids == [
        "MEMORY-I1-FIND-THE-WRITE",
        "MEMORY-I2-FIND-THE-LATER-RECALL",
        "MEMORY-I3-VERIFY-THE-MEMORY-FINGERPRINT",
        "MEMORY-I4-DETERMINE-TRUST-CLASSIFICATION",
        "MEMORY-I5-DID-MEMORY-INFLUENCE-A-REQUEST",
        "MEMORY-I6-WHO-AUTHORIZED-THE-TOOL",
        "MEMORY-I7-DID-EXECUTION-OCCUR",
        "MEMORY-I8-ATTACK-VS-RETEST",
        "MEMORY-I9-WHAT-CAN-YOU-PROVE",
    ]
    hunts = {row["related_hunt"] for row in rows}
    assert hunts <= {
        "Q-MEMORY-CONTEXT-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-WHO",
    }
    assert "DET-MEMORY" not in hunts
    assert "DET-MCP-001" not in hunts
    by_id = {row["investigation_id"]: row for row in rows}
    assert by_id["MEMORY-I8-ATTACK-VS-RETEST"]["investigation_kind"] == "paired_run"
    assert by_id["MEMORY-I8-ATTACK-VS-RETEST"]["studio_tab"] == "COMPARE"
    assert "CTRL-MEMORY-CONTEXT-001" in by_id["MEMORY-I4-DETERMINE-TRUST-CLASSIFICATION"]["related_control"]
    assert "CTRL-MCP-001" in by_id["MEMORY-I6-WHO-AUTHORIZED-THE-TOOL"]["related_control"]
    assert "INCORRECT" in by_id["MEMORY-I9-WHAT-CAN-YOU-PROVE"]["hint_2"]
    assert by_id["MEMORY-I9-WHAT-CAN-YOU-PROVE"]["studio_tab"] == "PROVE"


def test_goal_investigations_reuse_q_goal_and_are_not_policy():
    data = load_investigations("LAB-AGENT-GOAL-INTEGRITY-001")
    rows = validate_investigations("LAB-AGENT-GOAL-INTEGRITY-001")
    assert data["not_authorization"] is True
    assert data["studio_token_binding"] == "NOT SUPPORTED / DO NOT BUILD"
    ids = [row["investigation_id"] for row in rows]
    assert ids == [
        "GOAL-I1-FIND-THE-RUN",
        "GOAL-I2-FIND-THE-AUTHORITATIVE-TASK",
        "GOAL-I3-INSPECT-THE-UNTRUSTED-INSTRUCTION",
        "GOAL-I4-RECONSTRUCT-THE-PROPOSED-GOAL",
        "GOAL-I5-EVALUATE-GOAL-INTEGRITY",
        "GOAL-I6-EVALUATE-TOOL-AUTHORIZATION",
        "GOAL-I7-DETERMINE-WHAT-EXECUTED",
        "GOAL-I8-ATTACK-VS-RETEST",
        "GOAL-I9-WHAT-CAN-YOU-PROVE",
    ]
    hunts = {row["related_hunt"] for row in rows}
    assert hunts <= {
        "Q-GOAL-INTEGRITY-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-WHO",
    }
    assert "DET-GOAL" not in hunts
    assert "DET-MCP-001" not in hunts
    by_id = {row["investigation_id"]: row for row in rows}
    assert by_id["GOAL-I8-ATTACK-VS-RETEST"]["investigation_kind"] == "paired_run"
    assert by_id["GOAL-I8-ATTACK-VS-RETEST"]["studio_tab"] == "COMPARE"
    assert "CTRL-GOAL-INTEGRITY-001" in by_id["GOAL-I5-EVALUATE-GOAL-INTEGRITY"]["related_control"]
    assert "CTRL-MCP-001" in by_id["GOAL-I6-EVALUATE-TOOL-AUTHORIZATION"]["related_control"]
    assert "INCORRECT" in by_id["GOAL-I9-WHAT-CAN-YOU-PROVE"]["hint_2"]
    assert by_id["GOAL-I9-WHAT-CAN-YOU-PROVE"]["studio_tab"] == "PROVE"
    assert all(row.get("not_authorization") is True for row in rows)


def test_identity_investigations_reuse_q_delegation_and_are_not_policy():
    data = load_investigations("LAB-AGENT-DELEGATION-001")
    rows = validate_investigations("LAB-AGENT-DELEGATION-001")
    assert data["not_authorization"] is True
    assert data["studio_token_binding"] == "NOT SUPPORTED / DO NOT BUILD"
    ids = [row["investigation_id"] for row in rows]
    assert ids == [
        "IDENTITY-I1-FIND-THE-EXPERIMENT",
        "IDENTITY-I2-IDENTIFY-THE-ACTORS",
        "IDENTITY-I3-INSPECT-THE-DELEGATION-CLAIM",
        "IDENTITY-I4-EVALUATE-IDENTITY-TRUST",
        "IDENTITY-I5-INSPECT-ACTUAL-CODED-AUTHORITY",
        "IDENTITY-I6-FIND-THE-PRIVILEGED-REQUEST",
        "IDENTITY-I7-WHO-AUTHORIZED-IT",
        "IDENTITY-I8-DETERMINE-WHETHER-EXECUTION-OCCURRED",
        "IDENTITY-I9-ATTACK-VS-RETEST",
        "IDENTITY-I10-WHAT-CAN-YOU-PROVE",
    ]
    hunts = {row["related_hunt"] for row in rows}
    assert hunts <= {
        "Q-AGENT-DELEGATION-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-WHO",
    }
    assert "DET-A2A" not in hunts
    assert "DET-MCP-001" not in hunts
    by_id = {row["investigation_id"]: row for row in rows}
    assert by_id["IDENTITY-I9-ATTACK-VS-RETEST"]["investigation_kind"] == "paired_run"
    assert by_id["IDENTITY-I9-ATTACK-VS-RETEST"]["studio_tab"] == "COMPARE"
    assert "CTRL-IDENTITY-001" in by_id["IDENTITY-I4-EVALUATE-IDENTITY-TRUST"]["related_control"]
    assert "CTRL-MCP-001" in by_id["IDENTITY-I7-WHO-AUTHORIZED-IT"]["related_control"]
    assert "INCORRECT" in by_id["IDENTITY-I10-WHAT-CAN-YOU-PROVE"]["hint_2"]
    assert by_id["IDENTITY-I10-WHAT-CAN-YOU-PROVE"]["studio_tab"] == "PROVE"
    assert all(row.get("not_authorization") is True for row in rows)


def test_capstone_investigations_reuse_existing_hunts_and_are_not_policy():
    data = load_investigations("LAB-AGENTSEC-CAPSTONE-001")
    rows = validate_investigations("LAB-AGENTSEC-CAPSTONE-001")
    assert data["not_authorization"] is True
    assert data["studio_token_binding"] == "NOT SUPPORTED / DO NOT BUILD"
    ids = [row["investigation_id"] for row in rows]
    assert len(ids) == 16
    assert ids[0] == "CAP-I1-FIND-THE-RUNS"
    assert ids[-1] == "CAP-I16-CLASSIFY-PROOF"
    hunts = {row["related_hunt"] for row in rows}
    assert "Q-CAPSTONE" not in hunts
    assert "DET-CAPSTONE" not in hunts
    by_id = {row["investigation_id"]: row for row in rows}
    assert by_id["CAP-I14-ATTACK-VS-RETEST"]["investigation_kind"] == "paired_run"
    assert "NOT REQUIRED" in by_id["CAP-I12-GOAL-INTEGRITY-REQUIRED"]["expected_result_shape"]
    assert "NOT REQUIRED" in by_id["CAP-I13-IDENTITY-DELEGATION-REQUIRED"]["expected_result_shape"]
    assert "INCORRECT" in by_id["CAP-I16-CLASSIFY-PROOF"]["hint_2"]
    assert all(row["starter_guidance"] and row["hint_1"] and row["hint_2"] for row in rows)


