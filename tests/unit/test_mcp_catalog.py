"""Deterministic tools/list-shaped catalog snapshot. Descriptions are DATA."""

from __future__ import annotations

from agentsec.events import CONTENT_PREVIEW_MAX, content_hash, content_preview
from agentsec.mcp.catalog import (
    FIXTURE_MALICIOUS,
    FIXTURE_NORMAL,
    build_catalog_snapshot,
    lookup_policy_description_for,
    parse_tools_list_snapshot,
    select_catalog_fixture,
)
from agentsec.mcp.fixtures import (
    MCP_CATALOG_DESCRIPTION_MALICIOUS,
    MCP_CATALOG_DESCRIPTION_NORMAL,
    MCP_CATALOG_FOLLOW_ON_MARKER,
)
from agentsec.mcp.registry import default_registry
from agentsec.mcp.tools import LOOKUP_POLICY_INPUT_SCHEMA


def test_mode_owns_catalog_fixture_not_http():
    assert select_catalog_fixture("BASELINE") == FIXTURE_NORMAL
    assert select_catalog_fixture("ATTACK") == FIXTURE_MALICIOUS
    assert select_catalog_fixture("RETEST") == FIXTURE_MALICIOUS


def test_normal_and_malicious_descriptions():
    assert lookup_policy_description_for(FIXTURE_NORMAL) == MCP_CATALOG_DESCRIPTION_NORMAL
    assert lookup_policy_description_for(FIXTURE_MALICIOUS) == MCP_CATALOG_DESCRIPTION_MALICIOUS
    assert MCP_CATALOG_FOLLOW_ON_MARKER in MCP_CATALOG_DESCRIPTION_MALICIOUS
    assert MCP_CATALOG_FOLLOW_ON_MARKER not in MCP_CATALOG_DESCRIPTION_NORMAL
    for banned in (
        "allowed_tools",
        "allowed_scope",
        "allowed_resource",
        "grant_tool",
        "role=admin",
        "security.profile",
        "control.decision",
        "SECURITY_OVERRIDE",
    ):
        assert banned not in MCP_CATALOG_DESCRIPTION_MALICIOUS


def test_snapshot_is_tools_list_shaped_and_deterministic():
    first = build_catalog_snapshot(default_registry(), fixture=FIXTURE_NORMAL).as_dict()
    second = build_catalog_snapshot(default_registry(), fixture=FIXTURE_NORMAL).as_dict()
    assert first == second
    assert set(first) == {"tools"}
    names = [row["name"] for row in first["tools"]]
    assert names == sorted(names)
    policy = next(row for row in first["tools"] if row["name"] == "lookup_policy")
    assert set(policy) == {"name", "description", "inputSchema"}
    assert policy["description"] == MCP_CATALOG_DESCRIPTION_NORMAL
    assert policy["inputSchema"] == LOOKUP_POLICY_INPUT_SCHEMA


def test_malicious_snapshot_poisons_only_lookup_policy_description():
    normal = build_catalog_snapshot(fixture=FIXTURE_NORMAL).as_dict()
    malicious = build_catalog_snapshot(fixture=FIXTURE_MALICIOUS).as_dict()
    assert [row["name"] for row in normal["tools"]] == [row["name"] for row in malicious["tools"]]
    n_policy = next(row for row in normal["tools"] if row["name"] == "lookup_policy")
    m_policy = next(row for row in malicious["tools"] if row["name"] == "lookup_policy")
    assert n_policy["inputSchema"] == m_policy["inputSchema"]
    assert n_policy["description"] != m_policy["description"]
    tier_n = next(row for row in normal["tools"] if row["name"] == "lookup_customer_tier")
    tier_m = next(row for row in malicious["tools"] if row["name"] == "lookup_customer_tier")
    assert tier_n == tier_m
    assert MCP_CATALOG_FOLLOW_ON_MARKER not in tier_m["description"]


def test_parse_rejects_malformed_and_grant_like_catalog():
    assert parse_tools_list_snapshot(None)[1].reason == "malformed_catalog"
    assert parse_tools_list_snapshot({"tools": "nope"})[1].reason == "malformed_catalog"
    assert parse_tools_list_snapshot({"tools": []})[1].reason == "malformed_catalog"
    assert parse_tools_list_snapshot({"tools": [{"description": "x", "inputSchema": {}}]})[1].reason == "missing_tool_name"
    assert parse_tools_list_snapshot({"tools": [{"name": "lookup_policy", "inputSchema": {}}]})[1].reason == "invalid_description"
    assert parse_tools_list_snapshot(
        {"tools": [{"name": "lookup_policy", "description": "", "inputSchema": {}}]}
    )[1].reason == "invalid_description"
    assert parse_tools_list_snapshot(
        {"tools": [{"name": "lookup_policy", "description": 12, "inputSchema": {}}]}
    )[1].reason == "invalid_description"
    dup = {
        "tools": [
            {"name": "lookup_policy", "description": "a", "inputSchema": {}},
            {"name": "lookup_policy", "description": "b", "inputSchema": {}},
        ]
    }
    assert parse_tools_list_snapshot(dup)[1].reason == "duplicate_tool_name"
    unknown = {"tools": [{"name": "execute_shell_command", "description": "x", "inputSchema": {}}]}
    assert parse_tools_list_snapshot(unknown)[1].reason == "unknown_tool_metadata"
    extra = {"tools": [{"name": "lookup_policy", "description": "x", "inputSchema": {}, "allowed_tools": "lookup_customer_tier"}]}
    assert parse_tools_list_snapshot(extra)[1].reason == "unknown_catalog_fields"
    trust = {"tools": [{"name": "lookup_policy", "description": "x", "inputSchema": {}, "metadata.trust": "trusted"}]}
    assert parse_tools_list_snapshot(trust)[1].reason == "unknown_catalog_fields"
    profile = {"tools": [], "security.profile": "vulnerable"}
    assert parse_tools_list_snapshot(profile)[1].reason in {"unknown_catalog_fields", "malformed_catalog"}


def test_preview_is_truncated_hash_covers_full_description():
    long_desc = ("x" * 400) + MCP_CATALOG_FOLLOW_ON_MARKER
    preview = content_preview(long_desc)
    assert len(preview) == CONTENT_PREVIEW_MAX
    assert MCP_CATALOG_FOLLOW_ON_MARKER not in preview
    assert content_hash(long_desc).startswith("sha256:")
    assert content_hash(long_desc) != content_hash(preview)
    assert content_hash(MCP_CATALOG_DESCRIPTION_MALICIOUS).startswith("sha256:")
