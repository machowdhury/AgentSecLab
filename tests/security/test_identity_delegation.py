"""LAB-AGENT-DELEGATION-001: identity claim is not a grant (INV-001 / INV-002 / INV-005)."""

from __future__ import annotations

import json

from agentsec.events import EVENT_MCP_COMPLETED, EVENT_MCP_FAILED, EVENT_MCP_STARTED
from agentsec.identity.fixtures import (
    AUTHORITY_LIKE_FIELDS,
    CALLEE_AGENT_ID,
    CALLER_AGENT_ID,
    CLOSED_PRIVILEGED_RESOURCE,
    CLOSED_PRIVILEGED_SCOPE,
    CLOSED_PRIVILEGED_TOOL,
    PRINCIPAL_ID,
    adversarial_a2a_payload,
    baseline_a2a_payload,
    identity_agent_policy,
)
from agentsec.identity.pipeline import run_identity_delegation, write_identity_specimen_pack
from agentsec.identity.request import parse_a2a_delegation_request
from agentsec.identity.trust import IDENTITY_CONTROL_ID, IDENTITY_FAIL_OPEN_REASON, IdentityDerivedOverlay
from agentsec.mcp.policy import coded_policy, policy_unchanged_by_identity_claim
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
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-identity-vuln"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    return get_settings()


def _run(settings, memory, *, mode: str, payload: object, registry=None, **kwargs):
    return run_identity_delegation(
        payload=payload,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=registry or default_registry(),
        **kwargs,
    )


def test_baseline_policy_tool_executes_privileged_does_not(settings, memory):
    result = _run(settings, memory, mode="BASELINE", payload=baseline_a2a_payload())
    assert result.identity_control_decision == "OBSERVE"
    assert result.identity_control_reason == "identity_claim_is_not_grant"
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == "tool_granted"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert result.overlay_applied is False
    names = event_names(result.events)
    assert EVENT_MCP_STARTED in names
    assert EVENT_MCP_COMPLETED in names
    assert_all_schema_valid(result.events)
    assert_correlation(result.events, result.run_id, workflow_entry="/identity/delegate")
    identity_ctrl = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == IDENTITY_CONTROL_ID
    ]
    assert identity_ctrl[0]["agentsec.control.decision"] == "OBSERVE"
    assert "SAFE" not in result.expected_behavior
    assert "authenticated" not in json.dumps(result.events)


def test_attack_uses_labeled_overlay_and_executes(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    before = coded_policy()
    registry = default_registry()
    result = _run(
        settings, memory, mode="ATTACK", payload=adversarial_a2a_payload(), registry=registry
    )
    after = coded_policy()
    assert result.identity_control_decision == "OBSERVE"
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == IDENTITY_FAIL_OPEN_REASON
    assert result.lookup_customer_tier_handler_count == 1
    assert result.lookup_policy_handler_count == 0
    assert result.overlay_applied is True
    assert result.overlay_run_id == result.run_id
    assert before == after
    assert before.allowed_tools == frozenset({"lookup_policy"})
    assert "customer:read" not in before.allowed_scopes
    assert EVENT_MCP_STARTED in event_names(result.events)
    assert EVENT_MCP_COMPLETED in event_names(result.events)
    assert_all_schema_valid(result.events)


def test_retest_same_request_denies_without_overlay(settings, memory):
    payload = adversarial_a2a_payload()
    result = _run(settings, memory, mode="RETEST", payload=payload)
    assert result.frozen_request is not None
    assert result.frozen_request.requested_tool == CLOSED_PRIVILEGED_TOOL
    assert result.frozen_request.requested_scope == CLOSED_PRIVILEGED_SCOPE
    assert result.frozen_request.resource == CLOSED_PRIVILEGED_RESOURCE
    assert result.identity_control_decision == "OBSERVE"
    assert result.follow_on_decision == "DENY"
    assert result.follow_on_reason == "tool_not_granted"
    assert result.lookup_customer_tier_handler_count == 0
    assert result.overlay_applied is False
    follow = result.hops[1]
    assert follow.mcp_started is False
    assert follow.handler_invoked is False
    assert follow.operation_attempted is False
    assert follow.operation_executed is False
    assert follow.operation_outcome == "prevented"
    assert EVENT_MCP_STARTED not in event_names(result.events)
    assert_all_schema_valid(result.events)


def test_attack_retest_request_equivalence(tmp_path, monkeypatch, settings, memory):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    vuln_memory = MemorySink()
    attack = _run(vuln, vuln_memory, mode="ATTACK", payload=adversarial_a2a_payload())
    retest = _run(settings, memory, mode="RETEST", payload=adversarial_a2a_payload())
    assert attack.frozen_request is not None and retest.frozen_request is not None
    assert attack.frozen_request.canonical_dict() == retest.frozen_request.canonical_dict()
    assert attack.follow_on_decision == "ALLOW"
    assert retest.follow_on_decision == "DENY"
    assert attack.lookup_customer_tier_handler_count == 1
    assert retest.lookup_customer_tier_handler_count == 0
    assert attack.identity_control_decision == retest.identity_control_decision == "OBSERVE"


def test_neither_agent_owns_customer_read():
    for agent_id in (CALLER_AGENT_ID, CALLEE_AGENT_ID):
        policy = identity_agent_policy(agent_id)
        assert "lookup_customer_tier" not in policy.allowed_tools
        assert "customer:read" not in policy.allowed_scopes
        assert CLOSED_PRIVILEGED_RESOURCE not in policy.allowed_policy_ids
    global_policy = coded_policy()
    assert "customer:read" not in global_policy.allowed_scopes
    assert CALLER_AGENT_ID != global_policy.agent_id
    assert CALLEE_AGENT_ID != global_policy.agent_id


def test_identity_claim_cannot_mint_allow_ticket(settings, memory):
    result = _run(settings, memory, mode="RETEST", payload=adversarial_a2a_payload())
    identity = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == IDENTITY_CONTROL_ID
    ][0]
    assert identity["agentsec.control.decision"] == "OBSERVE"
    assert identity["agentsec.control.decision"] != "ALLOW"
    assert "AllowTicket" not in json.dumps(result.events)
    assert not isinstance(result.frozen_request, AllowTicket)


def test_overlay_does_not_mutate_or_persist(tmp_path, monkeypatch, settings, memory):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    vuln_memory = MemorySink()
    before = coded_policy()
    attack = _run(vuln, vuln_memory, mode="ATTACK", payload=adversarial_a2a_payload())
    after_attack = coded_policy()
    assert before == after_attack
    assert policy_unchanged_by_identity_claim(before, attack.frozen_request) is before
    retest = _run(settings, memory, mode="RETEST", payload=adversarial_a2a_payload())
    assert retest.overlay_applied is False
    assert coded_policy() == before
    assert attack.overlay_run_id == attack.run_id
    assert retest.overlay_run_id is None


def test_authority_amplification_rejected_on_defended_path(settings, memory):
    result = _run(settings, memory, mode="RETEST", payload=adversarial_a2a_payload())
    callee = identity_agent_policy(CALLEE_AGENT_ID)
    caller = identity_agent_policy(CALLER_AGENT_ID)
    union_scopes = callee.allowed_scopes | caller.allowed_scopes
    assert CLOSED_PRIVILEGED_SCOPE not in union_scopes
    assert result.follow_on_decision == "DENY"
    assert result.lookup_customer_tier_handler_count == 0


def test_check_use_uses_frozen_snapshot(settings, memory):
    payload = adversarial_a2a_payload()
    parsed = parse_a2a_delegation_request(payload)
    assert parsed.ok and parsed.request is not None
    payload["requested_tool"] = "lookup_policy"
    payload["requested_scope"] = "policy:read"
    payload["resource"] = "lending-basics"
    result = run_identity_delegation(
        payload=payload,
        frozen_request=parsed.request,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        registry=default_registry(),
    )
    assert result.frozen_request is parsed.request
    assert result.frozen_request.requested_tool == CLOSED_PRIVILEGED_TOOL
    assert result.check_use_consistent is True
    assert result.follow_on_reason == "tool_not_granted"
    assert result.hops[1].tool_name == CLOSED_PRIVILEGED_TOOL


def test_caller_authority_keys_are_unknown_fields(settings, memory):
    for key in sorted(AUTHORITY_LIKE_FIELDS):
        payload = baseline_a2a_payload()
        payload[key] = "1"
        result = _run(settings, memory, mode="BASELINE", payload=payload)
        assert result.identity_control_decision == "ERROR"
        assert result.identity_control_reason.startswith("unknown_fields")
        assert result.lookup_customer_tier_handler_count == 0
        assert result.lookup_policy_handler_count == 0
        assert result.follow_on_decision is None


def test_identity_errors_are_error_not_deny(settings, memory):
    cases = [
        ({**baseline_a2a_payload(), "caller_agent": "unknown-agent"}, "unknown_caller"),
        ({**baseline_a2a_payload(), "callee_agent": "unknown-agent"}, "unknown_callee"),
        (
            {**baseline_a2a_payload(), "caller_agent": CALLEE_AGENT_ID, "callee_agent": CALLEE_AGENT_ID},
            "unsupported_self_delegation",
        ),
        ({k: v for k, v in baseline_a2a_payload().items() if k != "principal"}, "missing_principal"),
        ({k: v for k, v in baseline_a2a_payload().items() if k != "caller_agent"}, "missing_caller"),
        ({k: v for k, v in baseline_a2a_payload().items() if k != "callee_agent"}, "missing_callee"),
        ({**baseline_a2a_payload(), "requested_tool": ""}, "empty_requested_tool"),
        ({**baseline_a2a_payload(), "requested_scope": 1}, "invalid_scope_type"),
        ({**baseline_a2a_payload(), "resource": 1}, "invalid_resource"),
        (
            {**baseline_a2a_payload(), "caller_agent": CALLER_AGENT_ID, "caller_agent_id": CALLER_AGENT_ID},
            "ambiguous_identity_keys",
        ),
        ({**baseline_a2a_payload(), "delegation_claim": "not-an-object"}, "malformed_delegation_claim"),
    ]
    for payload, reason in cases:
        result = _run(settings, memory, mode="BASELINE", payload=payload)
        assert result.identity_control_decision == "ERROR", (reason, result.identity_control_reason)
        assert result.identity_control_reason.startswith(reason)
        assert result.follow_on_decision is None
        assert result.lookup_policy_handler_count == 0


def test_unknown_tool_is_mcp_error_after_observe(settings, memory):
    payload = {**baseline_a2a_payload(), "requested_tool": "no_such_tool"}
    result = _run(settings, memory, mode="BASELINE", payload=payload)
    assert result.identity_control_decision == "OBSERVE"
    assert result.follow_on_decision == "ERROR"
    assert result.follow_on_reason == "unknown_tool"
    assert result.lookup_policy_handler_count == 0


def test_invalid_catalog_resource_is_mcp_error(settings, memory):
    payload = {**baseline_a2a_payload(), "resource": "does-not-exist"}
    result = _run(settings, memory, mode="BASELINE", payload=payload)
    assert result.identity_control_decision == "OBSERVE"
    assert result.follow_on_decision == "ERROR"
    assert result.follow_on_reason == "unknown_resource"


def test_control_exception_does_not_fail_open(settings, memory):
    def boom(**kwargs):
        raise RuntimeError("injected identity follow-on failure")

    registry = default_registry()
    result = run_identity_delegation(
        payload=adversarial_a2a_payload(),
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        registry=registry,
        authorize_fn=boom,
    )
    assert result.identity_control_decision == "OBSERVE"
    assert result.follow_on_decision == "ERROR"
    assert "control_evaluation_failure" in (result.follow_on_reason or "")
    assert result.lookup_customer_tier_handler_count == 0
    assert result.hops[1].mcp_started is False


def test_handler_exception_after_allow_is_execution(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected handler failure")

    registry.replace_handler("lookup_customer_tier", boom)
    result = _run(
        settings, memory, mode="ATTACK", payload=adversarial_a2a_payload(), registry=registry
    )
    assert result.follow_on_decision == "ALLOW"
    assert result.lookup_customer_tier_handler_count == 1
    follow = result.hops[1]
    assert follow.mcp_started is True
    assert follow.mcp_failed is True
    assert follow.handler_invoked is True
    assert EVENT_MCP_FAILED in event_names(result.events)


def test_no_secret_bearing_identity_material(settings, memory, tmp_path, monkeypatch):
    baseline = _run(settings, memory, mode="BASELINE", payload=baseline_a2a_payload())
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    vuln_memory = MemorySink()
    attack = _run(vuln, vuln_memory, mode="ATTACK", payload=adversarial_a2a_payload())
    blob = json.dumps(baseline.events) + json.dumps(attack.events)
    for marker in SECRET_MARKERS:
        assert marker not in blob
    assert "authenticated=true" not in blob
    assert "verified_identity" not in blob
    assert "cryptographic_passport_valid" not in blob


def test_invariants_on_identity_and_mcp_rows(settings, memory):
    result = _run(settings, memory, mode="RETEST", payload=adversarial_a2a_payload())
    identity = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == IDENTITY_CONTROL_ID
    ][0]
    mcp = [
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == "CTRL-MCP-001"
    ][0]
    assert "INV-001" in identity["agentsec.invariant.id"]
    assert "INV-002" in identity["agentsec.invariant.id"]
    assert "INV-005" in identity["agentsec.invariant.id"]
    assert "INV-009" not in identity["agentsec.invariant.id"]
    assert "INV-001" in mcp["agentsec.invariant.id"]
    assert "INV-005" in mcp["agentsec.invariant.id"]
    assert identity["agentsec.identity.claim.trust"] == "untrusted_claim"
    assert identity["agentsec.identity.caller_agent_id"] == CALLER_AGENT_ID
    assert identity["agentsec.identity.callee_agent_id"] == CALLEE_AGENT_ID
    assert identity["agentsec.principal.id"] == PRINCIPAL_ID


def test_overlay_refuses_extension():
    try:
        IdentityDerivedOverlay(
            run_id="00000000-0000-0000-0000-000000000000",
            allowed_tool="lookup_policy",
            allowed_scope=CLOSED_PRIVILEGED_SCOPE,
            allowed_resource=CLOSED_PRIVILEGED_RESOURCE,
            request_fingerprint="sha256:" + ("a" * 64),
        )
    except ValueError as exc:
        assert "not extensible" in str(exc)
    else:
        raise AssertionError("overlay must refuse other tools")


def test_specimen_packs_record_local_limitations(tmp_path, monkeypatch, settings, memory):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    vuln_memory = MemorySink()
    baseline = _run(settings, memory, mode="BASELINE", payload=baseline_a2a_payload())
    attack = _run(vuln, vuln_memory, mode="ATTACK", payload=adversarial_a2a_payload())
    retest_memory = MemorySink()
    retest = _run(settings, retest_memory, mode="RETEST", payload=adversarial_a2a_payload())
    packs = [
        write_identity_specimen_pack(label="A", result=baseline, settings=settings),
        write_identity_specimen_pack(label="B", result=attack, settings=vuln),
        write_identity_specimen_pack(label="C", result=retest, settings=settings),
    ]
    for path in packs:
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["schema.version"] == "1.9.0"
        assert manifest["splunk.verified"] is False
        assert (path / "events.jsonl").is_file()
        assert (path / "request.json").is_file()
        assert (path / "result.json").is_file()
        assert (path / "export.json").is_file()
        assert (path / "limitations.json").is_file()
        limitations = json.loads((path / "limitations.json").read_text(encoding="utf-8"))
        assert limitations["splunk.verified"] is False
        assert "NOT PROVEN" in limitations["authenticated"]
