"""Scanner modules must not enter the MCP authorization path."""

from __future__ import annotations

import ast
from pathlib import Path

from agentsec.mcp.authorize import CONTROL_ID, authorize_tool
from agentsec.mcp.catalog import FIXTURE_MALICIOUS
from agentsec.mcp.fixtures import MCP_POLICY_SCOPE
from agentsec.mcp.metadata_trust import METADATA_CONTROL_ID, evaluate_metadata_trust_safe
from agentsec.mcp.policy import ALLOWED_POLICY_IDS, ALLOWED_SCOPES, ALLOWED_TOOLS, coded_policy
from agentsec.mcp.catalog import build_catalog_snapshot
from agentsec.scanners.catalog_export import catalog_export_bytes
from agentsec.scanners.cisco_mcp_scanner import run_static_yara_scan

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "agentsec" / "mcp"
AUTHZ_PATHS = (
    SRC / "authorize.py",
    SRC / "policy.py",
    SRC / "metadata_trust.py",
    SRC / "pipeline.py",
    SRC / "tools.py",
    SRC / "registry.py",
    SRC / "server.py",
    SRC / "catalog.py",
    SRC / "result_trust.py",
    SRC / "delegation.py",
    SRC / "delegation_pipeline.py",
)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_mcp_authorization_path_does_not_import_scanners():
    for path in AUTHZ_PATHS:
        imported = _imported_modules(path)
        assert not any(name == "agentsec.scanners" or name.startswith("agentsec.scanners.") for name in imported), path
        assert not any(
            name == "agentsec.external_evidence" or name.startswith("agentsec.external_evidence.")
            for name in imported
        ), path
        text = path.read_text(encoding="utf-8")
        assert "cisco_mcp_scanner" not in text
        assert "OBSERVED_SCANNER" not in text
        assert "ExternalEvidence" not in text
        assert "cisco_normalized_to_external" not in text


def test_coded_policy_and_catalog_unchanged_by_export():
    before = coded_policy()
    catalog_export_bytes(FIXTURE_MALICIOUS)
    after = coded_policy()
    assert before.allowed_tools == ALLOWED_TOOLS == after.allowed_tools
    assert before.allowed_scopes == ALLOWED_SCOPES == after.allowed_scopes
    assert before.allowed_policy_ids == ALLOWED_POLICY_IDS == after.allowed_policy_ids
    assert CONTROL_ID == "CTRL-MCP-001"
    assert METADATA_CONTROL_ID == "CTRL-MCP-METADATA-001"


def test_authorize_and_metadata_ignore_scanner_findings():
    policy = coded_policy()
    result = authorize_tool(
        tool_name="lookup_policy",
        requested_scope=MCP_POLICY_SCOPE,
        profile="defended",
        policy=policy,
        tool_registered=True,
    )
    assert result.decision == "ALLOW"
    assert result.reason == "tool_granted"
    snapshot = build_catalog_snapshot(fixture=FIXTURE_MALICIOUS)
    meta, _intent, overlay = evaluate_metadata_trust_safe(
        profile="defended",
        snapshot=snapshot,
        parse_error=None,
        run_id="scan-isolation",
    )
    assert meta.decision == "OBSERVE"
    assert overlay is None
    denied = authorize_tool(
        tool_name="lookup_customer_tier",
        requested_scope="customer:read",
        profile="defended",
        policy=coded_policy(),
        tool_registered=True,
    )
    assert denied.decision == "DENY"
    assert denied.reason == "tool_not_granted"


def test_wrapper_source_does_not_call_authorize():
    source = Path(run_static_yara_scan.__code__.co_filename).read_text(encoding="utf-8")
    assert "authorize_tool" not in source
    assert "coded_policy" not in source
    hec = (ROOT / "src" / "agentsec" / "scanners" / "hec_events.py").read_text(encoding="utf-8")
    assert "authorize_tool" not in hec
    assert "coded_policy" not in hec
    assert "CTRL-MCP-001" not in hec
    assert "otel:agentic:json" not in hec
    cisco = (ROOT / "src" / "agentsec" / "external_evidence" / "cisco.py").read_text(encoding="utf-8")
    assert "authorize_tool" not in cisco
    assert "CTRL-MCP-001" not in cisco
    contract = (ROOT / "src" / "agentsec" / "external_evidence" / "contract.py").read_text(encoding="utf-8")
    assert "authorize_tool" not in contract
    assert "agentsec.mcp" not in contract
