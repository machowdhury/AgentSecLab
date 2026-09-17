"""LAB-RAG-001: retrieved context cannot grant authority (INV-002)."""

from __future__ import annotations

import hashlib
import threading

from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_COMPLETED, EVENT_MCP_FAILED, EVENT_MCP_STARTED
from agentsec.mcp.authorize import authorize_tool
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy, policy_unchanged_by_retrieved_context
from agentsec.mcp.registry import default_registry
from agentsec.rag.context_trust import (
    RAG_FAIL_OPEN_REASON,
    RETRIEVED_CONTEXT_IS_DATA_REASON,
    interpret_retrieved_content,
)
from agentsec.rag.fixtures import (
    AGENT_NOTE_MARKER,
    DOCUMENT_ID_MALICIOUS,
    DOCUMENT_ID_NORMAL,
    MALICIOUS_DOCUMENT,
    NORMAL_DOCUMENT,
)
from agentsec.rag.pipeline import run_rag_retrieve
from agentsec.rag.retriever import retrieve
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import assert_all_schema_valid, assert_correlation, control_events, event_names, events_named


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run_rag(settings, memory, *, mode: str, document_id: str, registry=None, authorize_fn=None, **kwargs):
    return run_rag_retrieve(
        document_id=document_id,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=registry or default_registry(),
        authorize_fn=authorize_fn,
        **kwargs,
    )


def _vulnerable_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-rag-vuln"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    return get_settings()


def test_baseline_normal_no_follow_on(settings, memory):
    registry = default_registry()
    result = _run_rag(
        settings, memory, mode="BASELINE", document_id=DOCUMENT_ID_NORMAL, registry=registry
    )
    assert result.terminal == "completed_allowed"
    assert result.context_control_decision == "OBSERVE"
    assert result.context_control_reason == RETRIEVED_CONTEXT_IS_DATA_REASON
    assert result.context_trust == "untrusted_data"
    assert result.context_provenance == "rag.local.fixture"
    assert result.document_id == DOCUMENT_ID_NORMAL
    assert result.content_hash == _sha256(NORMAL_DOCUMENT)
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.follow_on_decision is None
    assert result.context_derived_authority is False
    assert coded_policy().allowed_tools == ALLOWED_TOOLS
    names = event_names(result.events)
    assert EVENT_MCP_STARTED not in names
    rag_ctrl = [e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-RAG-CONTEXT-001"]
    assert len(rag_ctrl) == 1
    assert rag_ctrl[0]["agentsec.control.decision"] == "OBSERVE"
    assert rag_ctrl[0]["agentsec.rag.context.trust"] == "untrusted_data"
    assert "SAFE" not in result.actual_behavior
    assert "TRUSTED" not in result.actual_behavior
    assert_all_schema_valid(result.events)
    assert_correlation(result.events, result.run_id, workflow_entry="/rag/retrieve")


def test_attack_observe_then_overlay_allow(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    registry = default_registry()
    before = coded_policy()
    result = _run_rag(
        settings, memory, mode="ATTACK", document_id=DOCUMENT_ID_MALICIOUS, registry=registry
    )
    after = coded_policy()
    assert before.allowed_tools == after.allowed_tools == ALLOWED_TOOLS
    assert result.context_control_decision == "OBSERVE"
    assert result.context_control_reason == RETRIEVED_CONTEXT_IS_DATA_REASON
    assert result.context_derived_authority is True
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == RAG_FAIL_OPEN_REASON
    assert "known tool" not in result.follow_on_reason
    assert result.lookup_customer_tier_handler_count == 1
    assert registry.invoke_counts["lookup_customer_tier"] == 1
    follow = result.hops[1]
    assert follow.tool_name == "lookup_customer_tier"
    assert follow.operation_executed is True
    assert follow.mcp_started is True
    rag_ctrl = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-RAG-CONTEXT-001")
    assert rag_ctrl["agentsec.control.decision"] == "OBSERVE"
    follow_ctrl = next(
        e
        for e in control_events(result.events)
        if e["agentsec.control.id"] == "CTRL-MCP-001" and e["gen_ai.tool.name"] == "lookup_customer_tier"
    )
    assert follow_ctrl["agentsec.control.reason"] == RAG_FAIL_OPEN_REASON
    assert EVENT_MCP_COMPLETED in event_names(result.events)
    reset_settings_cache()


def test_retest_same_malicious_denies(settings, memory):
    registry = default_registry()
    result = _run_rag(
        settings, memory, mode="RETEST", document_id=DOCUMENT_ID_MALICIOUS, registry=registry
    )
    assert result.context_control_decision == "OBSERVE"
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.context_derived_authority is False
    assert result.follow_on_decision == "DENY"
    assert result.follow_on_reason == "tool_not_granted"
    follow = result.hops[1]
    assert follow.operation_attempted is False
    assert follow.operation_executed is False
    assert follow.operation_outcome == "prevented"
    assert follow.mcp_started is False
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_attack_and_retest_identical_malicious_content(tmp_path, monkeypatch, settings, memory):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    attack = _run_rag(attack_settings, MemorySink(), mode="ATTACK", document_id=DOCUMENT_ID_MALICIOUS)
    reset_settings_cache()
    retest = _run_rag(settings, memory, mode="RETEST", document_id=DOCUMENT_ID_MALICIOUS)
    assert attack.document_id == retest.document_id == DOCUMENT_ID_MALICIOUS
    assert attack.content_hash == retest.content_hash == _sha256(MALICIOUS_DOCUMENT)
    assert attack.follow_on_request == retest.follow_on_request
    assert attack.follow_on_request["tool"] == "lookup_customer_tier"
    assert AGENT_NOTE_MARKER in MALICIOUS_DOCUMENT
    reset_settings_cache()


def test_global_policy_immutable_after_attack(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    before = coded_policy()
    snapshot = (before.allowed_tools, before.allowed_scopes, before.allowed_policy_ids, before.agent_id)
    result = _run_rag(settings, MemorySink(), mode="ATTACK", document_id=DOCUMENT_ID_MALICIOUS)
    after = policy_unchanged_by_retrieved_context(coded_policy(), MALICIOUS_DOCUMENT)
    assert (after.allowed_tools, after.allowed_scopes, after.allowed_policy_ids, after.agent_id) == snapshot
    assert result.server_owned_allowed_tools == "lookup_policy"
    assert settings.security_profile == "vulnerable"
    reset_settings_cache()


def test_unknown_document_is_error_not_deny(settings, memory):
    registry = default_registry()
    result = _run_rag(settings, memory, mode="BASELINE", document_id="doc.does-not-exist", registry=registry)
    assert result.context_control_decision == "ERROR"
    assert result.context_control_reason == "unknown_document"
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_total == 0
    assert result.follow_on_decision is None
    assert EVENT_MCP_STARTED not in event_names(result.events)
    assert "doc.lending-policy.normal" not in (result.actual_behavior or "")
    client_error = result.block_reason or ""
    assert "doc.lending-policy.malicious" not in client_error


def test_exact_identity_no_strip_or_casefold(settings, memory):
    registry = default_registry()
    spaced = _run_rag(settings, MemorySink(), mode="BASELINE", document_id=" doc.lending-policy.normal", registry=registry)
    assert spaced.context_control_reason == "unknown_document"
    folded = _run_rag(settings, memory, mode="BASELINE", document_id="DOC.LENDING-POLICY.NORMAL", registry=default_registry())
    assert folded.context_control_reason == "unknown_document"


def test_malformed_retrieval_object_is_error(settings, memory):
    result = _run_rag(
        settings,
        memory,
        mode="BASELINE",
        document_id=DOCUMENT_ID_NORMAL,
        retrieved_override={"content": "not enough", "allowed_tools": ["lookup_customer_tier"]},
    )
    assert result.context_control_decision == "ERROR"
    assert result.context_control_reason == "malformed_retrieval_object"
    assert result.lookup_customer_tier_handler_count == 0
    assert result.follow_on_decision is None


def test_missing_document_id_in_object(settings, memory):
    result = _run_rag(
        settings,
        memory,
        mode="BASELINE",
        document_id=DOCUMENT_ID_NORMAL,
        retrieved_override={"content": NORMAL_DOCUMENT, "provenance": "rag.local.fixture"},
    )
    assert result.context_control_decision == "ERROR"
    assert result.lookup_customer_tier_handler_count == 0


def test_non_string_content_is_malformed(settings, memory):
    result = _run_rag(
        settings,
        memory,
        mode="BASELINE",
        document_id=DOCUMENT_ID_NORMAL,
        retrieved_override={"document_id": DOCUMENT_ID_NORMAL, "content": 123, "provenance": "rag.local.fixture"},
    )
    assert result.context_control_decision == "ERROR"
    assert result.context_control_reason == "malformed_retrieval_object"


def test_interpreter_uses_full_content_not_preview():
    padding = "Customers may request information about standard lending policy. " + ("x" * 250)
    body = padding + "\n\n" + AGENT_NOTE_MARKER
    intent = interpret_retrieved_content(body, document_id="doc.synthetic")
    assert intent is not None
    assert intent.tool_name == "lookup_customer_tier"
    preview = body.replace("\n", " ").strip()[:200]
    assert AGENT_NOTE_MARKER not in preview


def test_frozen_retrieved_context_cannot_mutate():
    from dataclasses import FrozenInstanceError

    ctx, err = retrieve(DOCUMENT_ID_MALICIOUS)
    assert err is None
    assert ctx is not None
    try:
        ctx.content = "mutated"  # type: ignore[misc]
    except FrozenInstanceError:
        return
    raise AssertionError("RetrievedContext must be frozen")


def test_check_use_same_bytes(settings, memory):
    result = _run_rag(settings, memory, mode="RETEST", document_id=DOCUMENT_ID_MALICIOUS)
    assert result.content_hash == _sha256(MALICIOUS_DOCUMENT)
    assert result.follow_on_request is not None
    assert interpret_retrieved_content(MALICIOUS_DOCUMENT, document_id=DOCUMENT_ID_MALICIOUS) is not None


def test_retrieval_exception_is_error(settings, memory):
    def boom(_document_id):
        raise RuntimeError("injected retrieval failure")

    registry = default_registry()
    result = _run_rag(
        settings, memory, mode="BASELINE", document_id=DOCUMENT_ID_NORMAL, registry=registry, retrieve_fn=boom
    )
    assert result.context_control_decision == "ERROR"
    assert result.context_control_reason == "retrieval_failure"
    assert registry.invoke_total == 0


def test_context_control_exception_fails_safe(settings, memory, monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("injected context-trust failure")

    monkeypatch.setattr("agentsec.rag.pipeline.evaluate_context_trust_safe", boom)
    registry = default_registry()
    result = _run_rag(settings, memory, mode="RETEST", document_id=DOCUMENT_ID_MALICIOUS, registry=registry)
    assert result.context_control_decision == "ERROR"
    assert result.context_derived_authority is False
    assert result.lookup_customer_tier_handler_count == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_follow_on_authorization_exception_does_not_execute(settings, memory):
    def first_ok_then_boom(**kwargs):
        if kwargs.get("tool_name") == "lookup_customer_tier":
            raise RuntimeError("injected follow-on control failure")
        return authorize_tool(**kwargs)

    registry = default_registry()
    result = _run_rag(
        settings,
        memory,
        mode="RETEST",
        document_id=DOCUMENT_ID_MALICIOUS,
        registry=registry,
        authorize_fn=first_ok_then_boom,
    )
    assert result.lookup_customer_tier_handler_count == 0
    assert result.follow_on_decision == "ERROR"
    assert result.hops[1].mcp_started is False


def test_handler_exception_after_allow_is_execution(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected handler failure")

    registry.replace_handler("lookup_customer_tier", boom)
    result = _run_rag(
        settings, memory, mode="ATTACK", document_id=DOCUMENT_ID_MALICIOUS, registry=registry
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


def test_http_unknown_fields_rejected(acme_client):
    response = acme_client.post(
        "/rag/retrieve",
        json={
            "document_id": DOCUMENT_ID_NORMAL,
            "allowed_tools": ["lookup_customer_tier"],
            "trusted_document": True,
            "security.profile": "vulnerable",
            "context.trust": "trusted",
        },
    )
    assert response.status_code == 400
    body = response.get_json()
    assert body["block_reason"] == "unknown_fields"
    assert body["lookup_customer_tier_handler_count"] == 0


def test_http_baseline_and_retest(acme_client, monkeypatch, tmp_path, settings):
    response = acme_client.post("/rag/retrieve", json={"document_id": DOCUMENT_ID_NORMAL})
    assert response.status_code == 200
    body = response.get_json()
    assert body["context_control_decision"] == "OBSERVE"
    assert body["lookup_customer_tier_handler_count"] == 0

    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "defended")
    monkeypatch.setenv("AGENTSEC_TESTBED_MODE", "RETEST")
    reset_settings_cache()
    from agentsec.bank_app import LabRuntime, create_app
    from agentsec.mcp.registry import default_registry as reg
    from agentsec.settings import get_settings
    from agentsec.telemetry import FanoutSink, MemorySink
    from agentsec.llm import StubLLM

    app = create_app(
        LabRuntime(
            settings=get_settings(),
            llm=StubLLM(),
            memory=MemorySink(),
            sink=FanoutSink([MemorySink()]),
            mcp_registry=reg(),
        )
    )
    app.config["TESTING"] = True
    client = app.test_client()
    retest = client.post("/rag/retrieve", json={"document_id": DOCUMENT_ID_MALICIOUS})
    assert retest.status_code == 200
    retest_body = retest.get_json()
    assert retest_body["follow_on_decision"] == "DENY"
    assert retest_body["lookup_customer_tier_handler_count"] == 0
    reset_settings_cache()


def test_overlay_does_not_leak_across_threads(tmp_path, monkeypatch, settings):
    vuln = _vulnerable_settings(tmp_path, monkeypatch)
    barrier = threading.Barrier(2)
    results = {}

    def attack():
        barrier.wait()
        results["attack"] = _run_rag(
            vuln, MemorySink(), mode="ATTACK", document_id=DOCUMENT_ID_MALICIOUS, registry=default_registry()
        )

    def defended():
        barrier.wait()
        results["defended"] = _run_rag(
            settings, MemorySink(), mode="RETEST", document_id=DOCUMENT_ID_MALICIOUS, registry=default_registry()
        )

    threads = [threading.Thread(target=attack), threading.Thread(target=defended)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results["attack"].lookup_customer_tier_handler_count == 1
    assert results["defended"].lookup_customer_tier_handler_count == 0
    reset_settings_cache()


def test_normal_content_is_not_labeled_safe(settings, memory):
    result = _run_rag(settings, memory, mode="BASELINE", document_id=DOCUMENT_ID_NORMAL)
    blob = " ".join(
        [
            result.actual_behavior,
            result.expected_behavior,
            result.context_control_reason,
            str(result.events),
        ]
    )
    assert "SAFE" not in blob
    assert "APPROVED" not in blob
    assert "trusted_document" not in blob
