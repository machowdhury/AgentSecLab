"""Deterministic L8 privacy comparison."""

from __future__ import annotations

import inspect

import pytest

from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_COMPLETED
from agentsec.mcp.authorize import authorize_tool
from agentsec.mcp.policy import coded_policy
from agentsec.privacy.pipeline import (
    FULL_RECORD,
    LAB_ID,
    MINIMIZED_RECORD,
    PRIVACY_ATTACK_ID,
    REQUIRED_FIELDS,
    run_privacy_specimen,
    validate_synthetic_record,
)
from agentsec.telemetry import FanoutSink, MemorySink


def _run(mode: str):
    memory = MemorySink()
    return run_privacy_specimen(
        mode=mode, sink=FanoutSink([memory]), memory=memory, write_evidence=False
    )


def _event(result, name: str) -> dict:
    return next(event for event in result.events if event["event.name"] == name)


def test_full_and_minimized_records_are_obviously_synthetic():
    assert set(MINIMIZED_RECORD) == REQUIRED_FIELDS
    assert set(FULL_RECORD) > REQUIRED_FIELDS
    assert FULL_RECORD["email"].endswith("@example.invalid")
    assert "synthetic" in FULL_RECORD["customer_id"]
    assert "synthetic" in FULL_RECORD["internal_case_note"]
    assert validate_synthetic_record(dict(FULL_RECORD)) == dict(FULL_RECORD)
    assert validate_synthetic_record(dict(MINIMIZED_RECORD)) == dict(MINIMIZED_RECORD)


def test_same_authorization_and_execution_with_different_data_exposure():
    full = _run("ATTACK")
    minimized = _run("RETEST")
    for result in (full, minimized):
        assert result.blocked is False
        assert result.handler_invoke_count == 1
        assert result.terminal == "completed_allowed"
        control = _event(result, EVENT_CONTROL_DECISION)
        assert control["agentsec.lab.id"] == LAB_ID
        assert control["agentsec.control.id"] == "CTRL-MCP-001"
        assert control["agentsec.control.decision"] == "ALLOW"
        assert control["agentsec.control.reason"] == "tool_granted"
        assert control["gen_ai.tool.name"] == "prepare_support_contact"
        assert control["agentsec.mcp.requested_scope"] == "support:contact:prepare"
        assert control["agentsec.operation.executed"] is False
        assert _event(result, EVENT_MCP_COMPLETED)["agentsec.operation.executed"] is True
        assert "agentsec.attack.id" not in control

    assert full.final_output is not None
    assert minimized.final_output is not None
    assert set(full.final_output["received_fields"]) == set(FULL_RECORD)
    assert set(full.final_output["unnecessary_fields"]) == set(FULL_RECORD) - REQUIRED_FIELDS
    assert minimized.final_output["received_fields"] == sorted(REQUIRED_FIELDS)
    assert minimized.final_output["unnecessary_fields"] == []
    full_control = _event(full, EVENT_CONTROL_DECISION)
    minimized_control = _event(minimized, EVENT_CONTROL_DECISION)
    assert "account_balance_band" in full_control["agentsec.content.preview"]
    assert "account_balance_band" not in minimized_control["agentsec.content.preview"]
    assert full_control["agentsec.content.hash"] != minimized_control["agentsec.content.hash"]


@pytest.mark.parametrize("record", [
    {},
    {"customer_id": "cust-synthetic-001"},
    {"customer_id": "cust-synthetic-001", "preferred_channel": "email", "password": "synthetic-password"},
    {"customer_id": "cust-synthetic-001", "preferred_channel": "email", "email": "person@real-looking.example.com"},
])
def test_malformed_or_secret_shaped_fixtures_fail_before_execution(record):
    with pytest.raises(ValueError):
        validate_synthetic_record(record)


def test_privacy_slice_does_not_change_tool_pdp_or_coded_policy():
    params = inspect.signature(authorize_tool).parameters
    assert not any("privacy" in name or "data_use" in name for name in params)
    assert coded_policy().allowed_tools == frozenset({"lookup_policy"})
    assert PRIVACY_ATTACK_ID == "PRIVACY-001"
