"""LAB-MCP-CATALOG event sequence and schema 1.5.0 honesty."""

from __future__ import annotations

from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_STARTED
from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.schema import validate_event
from tests.helpers import assert_all_schema_valid, assert_sequence_ordering, control_events, event_names, events_named


def _run(settings, memory, *, mode: str):
    return run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        attack_id="MCP-CATALOG-001",
        registry=default_registry(),
    )


def test_catalog_events_are_schema_1_5_0(settings, memory):
    result = _run(settings, memory, mode="RETEST")
    assert_all_schema_valid(result.events)
    assert_sequence_ordering(result.events)
    for event in result.events:
        validate_event(event)
        assert event["agentsec.schema.version"] == "1.9.0"
        assert event["agentsec.attack.id"] == "MCP-CATALOG-001"
    meta = next(e for e in control_events(result.events) if e["agentsec.control.type"] == "mcp_metadata_trust")
    assert meta["agentsec.control.id"] == "CTRL-MCP-METADATA-001"
    assert meta["agentsec.trust_boundary"] == "mcp.catalog.metadata"
    assert meta["agentsec.mcp.metadata.trust"] == "untrusted_data"
    assert meta["agentsec.mcp.metadata.provenance"] == "mcp.catalog.snapshot"
    assert "agentsec.mcp.result.trust" not in meta
    assert len(meta["agentsec.content.preview"]) <= 200
    assert meta["agentsec.content.hash"].startswith("sha256:")


def test_retest_sequence_is_observe_then_allow_then_deny_without_follow_on_start(settings, memory):
    result = _run(settings, memory, mode="RETEST")
    names = event_names(result.events)
    meta_idx = next(i for i, e in enumerate(result.events) if e.get("agentsec.control.id") == "CTRL-MCP-METADATA-001")
    first_allow_idx = next(
        i
        for i, e in enumerate(result.events)
        if e.get("agentsec.control.id") == "CTRL-MCP-001" and e.get("gen_ai.tool.name") == "lookup_policy"
    )
    follow_idx = next(
        i
        for i, e in enumerate(result.events)
        if e.get("agentsec.control.id") == "CTRL-MCP-001" and e.get("gen_ai.tool.name") == "lookup_customer_tier"
    )
    assert meta_idx < first_allow_idx < follow_idx
    assert result.events[meta_idx]["agentsec.control.decision"] == "OBSERVE"
    assert result.events[first_allow_idx]["agentsec.control.decision"] == "ALLOW"
    assert result.events[follow_idx]["agentsec.control.decision"] == "DENY"
    started = [e["gen_ai.tool.name"] for e in events_named(result.events, EVENT_MCP_STARTED)]
    assert started == ["lookup_policy"]
    assert names.count(EVENT_CONTROL_DECISION) >= 3
