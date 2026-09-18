"""LAB-MEMORY-001: untrusted memory cannot silently become trusted instruction (INV-003)."""

from __future__ import annotations

import hashlib

from agentsec.events import (
    EVENT_CONTROL_DECISION,
    EVENT_MCP_COMPLETED,
    EVENT_MCP_FAILED,
    EVENT_MCP_STARTED,
    EVENT_MEMORY_RECALLED,
    EVENT_MEMORY_WRITTEN,
)
from agentsec.mcp.authorize import authorize_tool
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy, policy_unchanged_by_memory
from agentsec.mcp.registry import default_registry
from agentsec.memory.fixtures import (
    AGENT_MEMORY_NOTE_MARKER,
    MALICIOUS_MEMORY,
    MEMORY_ID_MALICIOUS,
    MEMORY_ID_NORMAL,
    NORMAL_MEMORY,
    PROVENANCE,
)
from agentsec.memory.pipeline import run_memory_recall, run_memory_write, write_memory_specimen_pack
from agentsec.memory.store import InProcessMemoryStore
from agentsec.memory.trust import (
    MEMORY_CONTEXT_IS_DATA_REASON,
    MEMORY_FAIL_OPEN_REASON,
    interpret_recalled_content,
)
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import assert_all_schema_valid, assert_correlation, control_events, event_names, events_named


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _vulnerable_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-memory-vuln"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    return get_settings()


def _write(settings, memory, store, *, mode: str, memory_id: str, **kwargs):
    return run_memory_write(
        memory_id=memory_id,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        **kwargs,
    )


def _recall(settings, memory, store, *, mode: str, memory_id: str, registry=None, **kwargs):
    return run_memory_recall(
        memory_id=memory_id,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=registry or default_registry(),
        **kwargs,
    )


def test_write_and_recall_use_distinct_run_ids(settings, memory):
    store = InProcessMemoryStore()
    write = _write(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    recall = _recall(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    assert write.run_id != recall.run_id
    assert recall.source_run_id == write.run_id
    assert write.terminal == "completed_allowed"
    assert recall.terminal == "completed_allowed"
    assert EVENT_MEMORY_WRITTEN in event_names(write.events)
    assert EVENT_MEMORY_RECALLED in event_names(recall.events)
    assert_all_schema_valid(write.events)
    assert_all_schema_valid(recall.events)
    assert_correlation(write.events, write.run_id, workflow_entry="/memory/write")
    assert_correlation(recall.events, recall.run_id, workflow_entry="/memory/recall")


def test_fingerprint_stable_across_write_and_recall(settings, memory):
    store = InProcessMemoryStore()
    write = _write(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    recall = _recall(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    expected = _sha256(NORMAL_MEMORY)
    assert write.content_hash == expected
    assert recall.content_hash == expected
    assert write.memory_provenance == PROVENANCE
    assert recall.memory_provenance == PROVENANCE
    assert recall.memory_trust == "untrusted_data"


def test_baseline_handler_zero_observe_only(settings, memory):
    store = InProcessMemoryStore()
    registry = default_registry()
    _write(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    result = _recall(
        settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL, registry=registry
    )
    assert result.memory_control_decision == "OBSERVE"
    assert result.memory_control_reason == MEMORY_CONTEXT_IS_DATA_REASON
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.follow_on_decision is None
    assert result.memory_derived_authority is False
    assert EVENT_MCP_STARTED not in event_names(result.events)
    mem_ctrl = [e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MEMORY-CONTEXT-001"]
    assert len(mem_ctrl) == 1
    assert mem_ctrl[0]["agentsec.control.decision"] == "OBSERVE"
    assert mem_ctrl[0]["agentsec.memory.trust"] == "untrusted_data"
    assert "SAFE" not in result.actual_behavior
    assert "TRUSTED" not in result.actual_behavior
    assert "APPROVED" not in result.actual_behavior
    assert "BENIGN" not in result.actual_behavior


def test_attack_observe_then_overlay_allow(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    store = InProcessMemoryStore()
    registry = default_registry()
    before = coded_policy()
    write = _write(settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS)
    result = _recall(
        settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS, registry=registry
    )
    after = coded_policy()
    assert before.allowed_tools == after.allowed_tools == ALLOWED_TOOLS
    assert write.run_id != result.run_id
    assert result.source_run_id == write.run_id
    assert result.memory_control_decision == "OBSERVE"
    assert result.memory_control_reason == MEMORY_CONTEXT_IS_DATA_REASON
    assert result.memory_derived_authority is True
    assert result.overlay_run_id == result.run_id
    assert result.overlay_run_id != write.run_id
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == MEMORY_FAIL_OPEN_REASON
    assert "known tool" not in result.follow_on_reason
    assert result.lookup_customer_tier_handler_count == 1
    assert registry.invoke_counts["lookup_customer_tier"] == 1
    follow = result.hops[1]
    assert follow.tool_name == "lookup_customer_tier"
    assert follow.operation_executed is True
    assert follow.mcp_started is True
    assert EVENT_MCP_COMPLETED in event_names(result.events) or EVENT_MCP_FAILED in event_names(result.events)
    follow_ctrl = next(
        e
        for e in control_events(result.events)
        if e["agentsec.control.id"] == "CTRL-MCP-001" and e["gen_ai.tool.name"] == "lookup_customer_tier"
    )
    assert follow_ctrl["agentsec.control.reason"] == MEMORY_FAIL_OPEN_REASON
    reset_settings_cache()


def test_retest_same_hash_deny_handler_zero(settings, memory):
    store = InProcessMemoryStore()
    registry = default_registry()
    write = _write(settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS)
    result = _recall(
        settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS, registry=registry
    )
    assert result.content_hash == _sha256(MALICIOUS_MEMORY)
    assert result.content_hash == write.content_hash
    from agentsec.mcp.fixtures import MCP_LOOKUP_TIER_ARGS

    assert result.follow_on_request == {
        "tool": "lookup_customer_tier",
        "requested_scope": "customer:read",
        "arguments": dict(MCP_LOOKUP_TIER_ARGS),
    }
    assert result.follow_on_decision == "DENY"
    assert result.follow_on_reason == "tool_not_granted"
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    follow = result.hops[1]
    assert follow.operation_attempted is False
    assert follow.operation_executed is False
    assert follow.operation_outcome == "prevented"
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_attack_retest_fingerprint_and_request_identity(tmp_path, monkeypatch, settings, memory):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    attack_sink = MemorySink()
    attack_store = InProcessMemoryStore()
    attack_reg = default_registry()
    attack_write = _write(vuln, attack_sink, attack_store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS)
    attack = _recall(
        vuln, attack_sink, attack_store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS, registry=attack_reg
    )
    retest_store = InProcessMemoryStore()
    retest_reg = default_registry()
    retest_write = _write(settings, memory, retest_store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS)
    retest = _recall(
        settings, memory, retest_store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS, registry=retest_reg
    )
    assert attack.content_hash == retest.content_hash == _sha256(MALICIOUS_MEMORY)
    assert attack.memory_provenance == retest.memory_provenance == PROVENANCE
    assert attack.follow_on_request == retest.follow_on_request
    assert attack.profile == "vulnerable"
    assert retest.profile == "defended"
    assert attack.follow_on_decision == "ALLOW"
    assert retest.follow_on_decision == "DENY"
    assert attack.lookup_customer_tier_handler_count == 1
    assert retest.lookup_customer_tier_handler_count == 0
    assert attack_write.content_hash == retest_write.content_hash
    reset_settings_cache()


def test_observe_does_not_authorize(settings, memory):
    store = InProcessMemoryStore()
    registry = default_registry()
    _write(settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS)
    result = _recall(
        settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS, registry=registry
    )
    mem_ctrl = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MEMORY-CONTEXT-001")
    assert mem_ctrl["agentsec.control.decision"] == "OBSERVE"
    assert mem_ctrl["agentsec.control.decision"] != "ALLOW"
    assert mem_ctrl["agentsec.control.decision"] != "DENY"
    mcp_ctrl = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MCP-001")
    assert mcp_ctrl["agentsec.control.decision"] == "DENY"


def test_overlay_is_recall_run_only_and_later_run_does_not_inherit(tmp_path, monkeypatch, settings):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    store = InProcessMemoryStore()
    attack_sink = MemorySink()
    attack_reg = default_registry()
    _write(vuln, attack_sink, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS)
    attack = _recall(
        vuln, attack_sink, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS, registry=attack_reg
    )
    assert attack.memory_derived_authority is True
    later_sink = MemorySink()
    later_reg = default_registry()
    later = _recall(
        settings, later_sink, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS, registry=later_reg
    )
    assert later.run_id != attack.run_id
    assert later.memory_derived_authority is False
    assert later.follow_on_decision == "DENY"
    assert later.lookup_customer_tier_handler_count == 0
    assert later_reg.invoke_counts["lookup_customer_tier"] == 0
    assert coded_policy().allowed_tools == ALLOWED_TOOLS
    reset_settings_cache()


def test_global_policy_unchanged_after_attack(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    store = InProcessMemoryStore()
    before = coded_policy()
    _write(settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS)
    _recall(settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS)
    after = coded_policy()
    assert before.allowed_tools == after.allowed_tools
    assert before.allowed_scopes == after.allowed_scopes
    assert before.allowed_policy_ids == after.allowed_policy_ids
    assert before.agent_id == after.agent_id
    policy_unchanged_by_memory(after, MALICIOUS_MEMORY)
    reset_settings_cache()


def test_unknown_memory_is_error_not_deny(settings, memory):
    store = InProcessMemoryStore()
    registry = default_registry()
    result = _recall(settings, memory, store, mode="BASELINE", memory_id="mem.missing", registry=registry)
    assert result.memory_control_decision == "ERROR"
    assert result.memory_control_reason == "unknown_memory_id"
    assert result.follow_on_decision is None
    assert result.lookup_customer_tier_handler_count == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)
    names = event_names(result.events)
    assert EVENT_MEMORY_RECALLED not in names


def test_empty_memory_id_is_error(settings, memory):
    store = InProcessMemoryStore()
    write = _write(settings, memory, store, mode="BASELINE", memory_id="")
    assert write.terminal == "run_failed"
    assert write.block_reason == "empty_memory_id"


def test_duplicate_memory_id_is_error(settings, memory):
    store = InProcessMemoryStore()
    first = _write(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    second = _write(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    assert first.terminal == "completed_allowed"
    assert second.terminal == "run_failed"
    assert second.block_reason == "duplicate_memory_id"


def test_malformed_grant_like_write_is_error_not_authority(settings, memory):
    store = InProcessMemoryStore()
    result = run_memory_write(
        memory_id=MEMORY_ID_NORMAL,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        write_obj={
            "memory_id": MEMORY_ID_NORMAL,
            "content": NORMAL_MEMORY,
            "allowed_tools": ["lookup_customer_tier"],
        },
    )
    assert result.terminal == "run_failed"
    assert result.block_reason == "malformed_memory_write"
    recall = _recall(settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_NORMAL)
    assert recall.memory_control_reason == "unknown_memory_id"
    assert coded_policy().allowed_tools == ALLOWED_TOOLS


def test_invalid_content_type_and_provenance_error(settings, memory):
    store = InProcessMemoryStore()
    bad_type = run_memory_write(
        memory_id="x",
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        write_obj={"memory_id": "mem.bad-type", "content": 123},
    )
    assert bad_type.block_reason == "invalid_content_type"
    bad_prov = run_memory_write(
        memory_id="x",
        store=store,
        sink=MemorySink(),
        memory=MemorySink(),
        settings=settings,
        testbed_mode="BASELINE",
        write_obj={"memory_id": "mem.bad-prov", "content": "ok", "provenance": "trusted"},
    )
    assert bad_prov.block_reason == "invalid_provenance"


def test_control_exception_fails_closed(settings, memory, monkeypatch):
    store = InProcessMemoryStore()
    _write(settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS)

    def boom(**kwargs):
        raise RuntimeError("injected memory-trust failure")

    monkeypatch.setattr("agentsec.memory.pipeline.evaluate_memory_trust_safe", boom)
    registry = default_registry()
    result = _recall(
        settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS, registry=registry
    )
    assert result.memory_control_decision == "ERROR"
    assert result.memory_derived_authority is False
    assert result.lookup_customer_tier_handler_count == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_follow_on_authorization_exception_does_not_execute(settings, memory):
    store = InProcessMemoryStore()
    _write(settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS)

    def first_ok_then_boom(**kwargs):
        if kwargs.get("tool_name") == "lookup_customer_tier":
            raise RuntimeError("injected follow-on control failure")
        return authorize_tool(**kwargs)

    registry = default_registry()
    result = _recall(
        settings,
        memory,
        store,
        mode="RETEST",
        memory_id=MEMORY_ID_MALICIOUS,
        registry=registry,
        authorize_fn=first_ok_then_boom,
    )
    assert result.lookup_customer_tier_handler_count == 0
    assert result.follow_on_decision == "ERROR"
    assert result.hops[1].mcp_started is False


def test_handler_exception_after_allow_is_execution(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    store = InProcessMemoryStore()
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected handler failure")

    registry.replace_handler("lookup_customer_tier", boom)
    _write(settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS)
    result = _recall(
        settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS, registry=registry
    )
    assert result.lookup_customer_tier_handler_count == 1
    follow = result.hops[1]
    assert follow.mcp_started is True
    assert follow.mcp_failed is True
    assert follow.operation_executed is True
    assert follow.operation_outcome == "error"
    assert EVENT_MCP_FAILED in event_names(result.events)
    assert "prevent" not in (result.actual_behavior or "").lower()
    reset_settings_cache()


def test_check_use_uses_same_snapshot(settings, memory):
    store = InProcessMemoryStore()
    _write(settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS)
    result = _recall(settings, memory, store, mode="RETEST", memory_id=MEMORY_ID_MALICIOUS)
    assert result.recalled_snapshot is not None
    intent = interpret_recalled_content(
        result.recalled_snapshot.content, memory_id=result.recalled_snapshot.memory_id
    )
    assert intent is not None
    assert result.content_hash == result.recalled_snapshot.content_hash
    assert AGENT_MEMORY_NOTE_MARKER in result.recalled_snapshot.content
    assert result.follow_on_request["tool"] == intent.tool_name
    assert result.recalled_snapshot.content == MALICIOUS_MEMORY


def test_privacy_no_full_memory_field(settings, memory):
    store = InProcessMemoryStore()
    write = _write(settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS)
    recall = _recall(settings, memory, store, mode="ATTACK", memory_id=MEMORY_ID_MALICIOUS)
    for event in write.events + recall.events:
        assert "agentsec.memory.content" not in event
        assert "password" not in str(event).lower()
        preview = event.get("agentsec.content.preview")
        if preview is not None:
            assert len(preview) <= 200
        if event.get("event.name") in {EVENT_MEMORY_WRITTEN, EVENT_MEMORY_RECALLED, EVENT_CONTROL_DECISION}:
            if "agentsec.content.hash" in event:
                assert event["agentsec.content.hash"].startswith("sha256:")


def test_http_unknown_fields_and_grants_rejected(acme_client):
    response = acme_client.post(
        "/memory/write",
        json={"memory_id": MEMORY_ID_NORMAL, "allowed_tools": ["lookup_customer_tier"]},
    )
    assert response.status_code == 400
    body = response.get_json()
    assert body["block_reason"] == "unknown_fields"
    recall = acme_client.post(
        "/memory/recall",
        json={"memory_id": MEMORY_ID_NORMAL, "security.profile": "vulnerable"},
    )
    assert recall.status_code == 400


def test_http_write_then_recall_persists(acme_client):
    write = acme_client.post("/memory/write", json={"memory_id": MEMORY_ID_NORMAL})
    assert write.status_code == 200
    write_id = write.get_json()["run_id"]
    recall = acme_client.post("/memory/recall", json={"memory_id": MEMORY_ID_NORMAL})
    assert recall.status_code == 200
    body = recall.get_json()
    assert body["run_id"] != write_id
    assert body["source_run_id"] == write_id
    assert body["lookup_customer_tier_handler_count"] == 0
    assert body["memory_control_decision"] == "OBSERVE"


def test_specimen_pack_records_both_run_ids(settings, memory):
    store = InProcessMemoryStore()
    write = _write(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    recall = _recall(settings, memory, store, mode="BASELINE", memory_id=MEMORY_ID_NORMAL)
    pack = write_memory_specimen_pack(label="A", write=write, recall=recall, settings=settings)
    import json

    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["memory.write.run.id"] == write.run_id
    assert manifest["memory.recall.run.id"] == recall.run_id
    assert manifest["splunk.verified"] is False
    assert manifest["schema.version"] == "1.7.0"
    lines = (pack / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert any(write.run_id in line for line in lines)
    assert any(recall.run_id in line for line in lines)
    export = json.loads((pack / "export.json").read_text(encoding="utf-8"))
    assert export["splunk.verified"] is False
