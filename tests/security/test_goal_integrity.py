"""LAB-AGENT-GOAL-INTEGRITY-001: untrusted instruction is not task authority (INV-002 / INV-006)."""

from __future__ import annotations

import json

from agentsec.events import EVENT_MCP_COMPLETED, EVENT_MCP_FAILED, EVENT_MCP_STARTED
from agentsec.goal.fixtures import (
    AUTHORITY_LIKE_FIELDS,
    CLOSED_EXPANSION_ACTION,
    GOAL_AGENT_ID,
    MALICIOUS_NOTE,
    PERMITTED_ACTION,
    PERMITTED_TOOL,
    PRINCIPAL_ID,
    TASK_ID,
    adversarial_goal_payload,
    baseline_goal_payload,
    goal_agent_policy,
)
from agentsec.goal.influence import parse_goal_request
from agentsec.goal.pipeline import run_goal_integrity, write_goal_specimen_pack
from agentsec.goal.task import authoritative_task_contract
from agentsec.goal.trust import GOAL_CONTROL_ID, GOAL_FAIL_OPEN_REASON, GoalDerivedOverlay
from agentsec.mcp.policy import coded_policy, policy_unchanged_by_goal_instruction
from agentsec.mcp.registry import default_registry
from agentsec.mcp.server import AllowTicket
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import assert_all_schema_valid, assert_correlation, control_events, event_names

SECRET_MARKERS = (
    "access_token",
    "refresh_token",
    "id_token",
    "Authorization",
    "Bearer ",
    "eyJ",
    "BEGIN CERTIFICATE",
    "BEGIN PRIVATE KEY",
    "client_secret",
    "password",
)


def _vulnerable_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-goal-vuln"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    return get_settings()


def _run(settings, memory, *, mode: str, payload: object, registry=None, **kwargs):
    return run_goal_integrity(
        payload=payload,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=registry or default_registry(),
        **kwargs,
    )


def test_task_contract_is_server_owned_and_immutable():
    first = authoritative_task_contract()
    second = authoritative_task_contract()
    assert first == second
    assert first.fingerprint == second.fingerprint
    assert first.task_id == TASK_ID
    assert first.permitted_action == PERMITTED_ACTION
    assert first.permitted_tool == PERMITTED_TOOL
    assert "run.id" not in first.canonical_dict()
    assert "profile" not in first.canonical_dict()
    try:
        first.task_id = "hijack"  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("TaskContract must be frozen")


def test_baseline_in_task_tool_executes_wrong_goal_does_not(settings, memory):
    result = _run(settings, memory, mode="BASELINE", payload=baseline_goal_payload())
    assert result.goal_control_decision == "OBSERVE"
    assert result.goal_control_reason == "untrusted_instruction_cannot_redefine_task"
    assert result.proposed_action == PERMITTED_ACTION
    assert result.effective_action == PERMITTED_ACTION
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == "tool_granted"
    assert result.in_task_lookup_policy_count == 1
    assert result.wrong_goal_lookup_policy_count == 0
    assert result.overlay_applied is False
    names = event_names(result.events)
    assert EVENT_MCP_STARTED in names
    assert EVENT_MCP_COMPLETED in names
    assert_all_schema_valid(result.events)
    assert_correlation(result.events, result.run_id, workflow_entry="/goal/evaluate")
    goal_ctrl = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == GOAL_CONTROL_ID
    ]
    assert goal_ctrl[0]["agentsec.control.decision"] == "OBSERVE"
    assert goal_ctrl[0]["agentsec.goal.proposed"] == PERMITTED_ACTION
    assert "SAFE" not in result.expected_behavior


def test_attack_uses_labeled_overlay_and_executes_wrong_goal(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    before = coded_policy()
    task_before = authoritative_task_contract()
    registry = default_registry()
    result = _run(
        settings, memory, mode="ATTACK", payload=adversarial_goal_payload(), registry=registry
    )
    after = coded_policy()
    assert result.goal_control_decision == "OBSERVE"
    assert result.goal_control_reason == GOAL_FAIL_OPEN_REASON
    assert result.proposed_action == CLOSED_EXPANSION_ACTION
    assert result.effective_action == CLOSED_EXPANSION_ACTION
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == "tool_granted"
    assert result.wrong_goal_lookup_policy_count == 1
    assert result.in_task_lookup_policy_count == 0
    assert result.overlay_applied is True
    assert result.overlay_run_id == result.run_id
    assert before == after
    assert task_before == authoritative_task_contract()
    assert EVENT_MCP_STARTED in event_names(result.events)
    assert_all_schema_valid(result.events)


def test_retest_same_input_rejects_expansion(settings, memory):
    result = _run(settings, memory, mode="RETEST", payload=adversarial_goal_payload())
    assert result.frozen_change is not None
    assert result.frozen_change.instruction == MALICIOUS_NOTE
    assert result.proposed_action == CLOSED_EXPANSION_ACTION
    assert result.goal_control_decision == "DENY"
    assert result.goal_control_reason == "unauthorized_task_expansion"
    assert result.effective_action == PERMITTED_ACTION
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == "tool_granted"
    assert result.wrong_goal_lookup_policy_count == 0
    assert result.in_task_lookup_policy_count == 1
    assert result.overlay_applied is False
    assert EVENT_MCP_STARTED in event_names(result.events)
    goal_ctrl = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == GOAL_CONTROL_ID
    ][0]
    mcp = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == "CTRL-MCP-001"
    ][0]
    assert goal_ctrl["gen_ai.tool.name"] == CLOSED_EXPANSION_ACTION
    assert mcp["gen_ai.tool.name"] == PERMITTED_TOOL
    assert_all_schema_valid(result.events)


def test_attack_retest_equivalence_and_divergent_outcomes(tmp_path, monkeypatch, settings, memory):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    vuln_memory = MemorySink()
    attack = _run(vuln, vuln_memory, mode="ATTACK", payload=adversarial_goal_payload())
    retest = _run(settings, memory, mode="RETEST", payload=adversarial_goal_payload())
    assert attack.task_fingerprint == retest.task_fingerprint
    assert attack.instruction_hash == retest.instruction_hash
    assert attack.proposed_fingerprint == retest.proposed_fingerprint
    assert attack.proposed_action == retest.proposed_action == CLOSED_EXPANSION_ACTION
    assert attack.frozen_change is not None and retest.frozen_change is not None
    assert attack.frozen_change.canonical_dict() == retest.frozen_change.canonical_dict()
    assert attack.frozen_task.canonical_dict() == retest.frozen_task.canonical_dict()
    assert attack.effective_action == CLOSED_EXPANSION_ACTION
    assert retest.effective_action == PERMITTED_ACTION
    assert attack.wrong_goal_lookup_policy_count == 1
    assert retest.wrong_goal_lookup_policy_count == 0
    assert attack.goal_control_reason == GOAL_FAIL_OPEN_REASON
    assert retest.goal_control_reason == "unauthorized_task_expansion"


def test_task_authority_is_not_tool_authority(settings, memory):
    result = _run(settings, memory, mode="RETEST", payload=adversarial_goal_payload())
    policy = goal_agent_policy()
    assert PERMITTED_TOOL in policy.allowed_tools
    assert result.follow_on_decision == "ALLOW"
    assert result.goal_control_decision == "DENY"
    assert result.wrong_goal_lookup_policy_count == 0
    global_policy = coded_policy()
    assert global_policy.allowed_tools == policy.allowed_tools


def test_goal_control_cannot_mint_allow_ticket(settings, memory):
    result = _run(settings, memory, mode="RETEST", payload=adversarial_goal_payload())
    goal = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == GOAL_CONTROL_ID
    ][0]
    assert goal["agentsec.control.decision"] == "DENY"
    assert "AllowTicket" not in json.dumps(result.events)
    assert not isinstance(result.frozen_change, AllowTicket)


def test_overlay_does_not_mutate_or_persist(tmp_path, monkeypatch, settings, memory):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    vuln_memory = MemorySink()
    before = coded_policy()
    task_before = authoritative_task_contract()
    attack = _run(vuln, vuln_memory, mode="ATTACK", payload=adversarial_goal_payload())
    after_attack = coded_policy()
    assert before == after_attack
    assert policy_unchanged_by_goal_instruction(before, attack.frozen_change) is before
    assert authoritative_task_contract() == task_before
    retest = _run(settings, memory, mode="RETEST", payload=adversarial_goal_payload())
    assert retest.overlay_applied is False
    assert coded_policy() == before
    assert attack.overlay_run_id == attack.run_id
    assert retest.overlay_run_id is None


def test_check_use_uses_frozen_snapshot(settings, memory):
    payload = adversarial_goal_payload()
    task = authoritative_task_contract()
    parsed = parse_goal_request(payload, task=task)
    assert parsed.ok and parsed.change is not None
    payload["instruction"] = baseline_goal_payload()["instruction"]
    result = run_goal_integrity(
        payload=payload,
        frozen_task=task,
        frozen_change=parsed.change,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        registry=default_registry(),
    )
    assert result.frozen_change is parsed.change
    assert result.frozen_change.proposed_action == CLOSED_EXPANSION_ACTION
    assert result.check_use_consistent is True
    assert result.goal_control_decision == "DENY"
    assert result.wrong_goal_lookup_policy_count == 0


def test_authority_like_keys_are_unknown_fields(settings, memory):
    for key in sorted(AUTHORITY_LIKE_FIELDS):
        payload = baseline_goal_payload()
        payload[key] = "1"
        result = _run(settings, memory, mode="BASELINE", payload=payload)
        assert result.goal_control_decision == "ERROR"
        assert result.goal_control_reason.startswith("unknown_fields")
        assert result.lookup_policy_handler_count == 0
        assert result.follow_on_decision is None


def test_goal_errors_are_error_not_deny(settings, memory):
    cases = [
        ({**baseline_goal_payload(), "agent": "unknown-agent"}, "unknown_agent"),
        ({k: v for k, v in baseline_goal_payload().items() if k != "principal"}, "missing_principal"),
        ({k: v for k, v in baseline_goal_payload().items() if k != "agent"}, "missing_agent"),
        ({k: v for k, v in baseline_goal_payload().items() if k != "instruction"}, "missing_instruction"),
        ({**baseline_goal_payload(), "instruction": ""}, "missing_instruction"),
        ({**baseline_goal_payload(), "principal": "other"}, "unknown_principal"),
        ("not-a-dict", "malformed_input"),
    ]
    for payload, reason in cases:
        result = _run(settings, memory, mode="BASELINE", payload=payload)
        assert result.goal_control_decision == "ERROR", (reason, result.goal_control_reason)
        assert result.goal_control_reason.startswith(reason)
        assert result.follow_on_decision is None
        assert result.lookup_policy_handler_count == 0


def test_control_exception_does_not_fail_open(settings, memory):
    def boom(**kwargs):
        raise RuntimeError("injected goal follow-on failure")

    registry = default_registry()
    result = run_goal_integrity(
        payload=adversarial_goal_payload(),
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        registry=registry,
        authorize_fn=boom,
    )
    assert result.goal_control_decision == "DENY"
    assert result.follow_on_decision == "ERROR"
    assert "control_evaluation_failure" in (result.follow_on_reason or "")
    assert result.wrong_goal_lookup_policy_count == 0
    assert result.hops[1].mcp_started is False


def test_handler_exception_after_allow_is_execution(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected handler failure")

    registry.replace_handler("lookup_policy", boom)
    result = _run(
        settings, memory, mode="ATTACK", payload=adversarial_goal_payload(), registry=registry
    )
    assert result.follow_on_decision == "ALLOW"
    assert result.wrong_goal_lookup_policy_count == 1
    follow = result.hops[1]
    assert follow.mcp_started is True
    assert follow.mcp_failed is True
    assert follow.handler_invoked is True
    assert EVENT_MCP_FAILED in event_names(result.events)


def test_no_secret_bearing_goal_material(settings, memory, tmp_path, monkeypatch):
    baseline = _run(settings, memory, mode="BASELINE", payload=baseline_goal_payload())
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    vuln_memory = MemorySink()
    attack = _run(vuln, vuln_memory, mode="ATTACK", payload=adversarial_goal_payload())
    blob = json.dumps(baseline.events) + json.dumps(attack.events)
    for marker in SECRET_MARKERS:
        assert marker not in blob
    assert "authenticated=true" not in blob
    assert "trusted_instruction=true" not in blob


def test_invariants_on_goal_and_mcp_rows(settings, memory):
    result = _run(settings, memory, mode="RETEST", payload=adversarial_goal_payload())
    goal = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == GOAL_CONTROL_ID
    ][0]
    mcp = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == "CTRL-MCP-001"
    ][0]
    assert "INV-002" in goal["agentsec.invariant.id"]
    assert "INV-006" in goal["agentsec.invariant.id"]
    assert "INV-009" not in goal["agentsec.invariant.id"]
    assert goal["agentsec.instruction.trust"] == "untrusted_instruction"
    assert goal["agentsec.task.id"] == TASK_ID
    assert goal["agentsec.principal.id"] == PRINCIPAL_ID
    assert mcp["agentsec.control.type"] == "mcp_allowlist"
    assert mcp["gen_ai.agent.id"] == GOAL_AGENT_ID


def test_overlay_refuses_extension():
    try:
        GoalDerivedOverlay(
            run_id="00000000-0000-0000-0000-000000000000",
            accepted_action=PERMITTED_ACTION,
            task_fingerprint="sha256:" + ("a" * 64),
            proposed_fingerprint="sha256:" + ("b" * 64),
        )
    except ValueError as exc:
        assert "not extensible" in str(exc)
    else:
        raise AssertionError("overlay must refuse other actions")


def test_normal_and_malicious_fixtures_are_deterministic():
    task = authoritative_task_contract()
    normal = parse_goal_request(baseline_goal_payload(), task=task)
    malicious = parse_goal_request(adversarial_goal_payload(), task=task)
    assert normal.ok and malicious.ok
    assert normal.change is not None and malicious.change is not None
    assert normal.change.proposed_action == PERMITTED_ACTION
    assert malicious.change.proposed_action == CLOSED_EXPANSION_ACTION
    assert normal.change.resulting_tool == malicious.change.resulting_tool == PERMITTED_TOOL
    again = parse_goal_request(adversarial_goal_payload(), task=task)
    assert again.change is not None
    assert again.change.fingerprint == malicious.change.fingerprint
    assert again.change.instruction_hash == malicious.change.instruction_hash


def test_specimen_packs_record_local_limitations(tmp_path, monkeypatch, settings, memory):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    vuln_memory = MemorySink()
    baseline = _run(settings, memory, mode="BASELINE", payload=baseline_goal_payload())
    attack = _run(vuln, vuln_memory, mode="ATTACK", payload=adversarial_goal_payload())
    retest_memory = MemorySink()
    retest = _run(settings, retest_memory, mode="RETEST", payload=adversarial_goal_payload())
    packs = [
        write_goal_specimen_pack(label="A", result=baseline, settings=settings),
        write_goal_specimen_pack(label="B", result=attack, settings=vuln),
        write_goal_specimen_pack(label="C", result=retest, settings=settings),
    ]
    for path in packs:
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["schema.version"] == "1.9.0"
        assert manifest["splunk.verified"] is False
        assert manifest["task.hash"]
        for name in ("events.jsonl", "request.json", "result.json", "export.json", "limitations.json"):
            assert (path / name).is_file()
        limitations = json.loads((path / "limitations.json").read_text(encoding="utf-8"))
        assert limitations["splunk.verified"] is False
