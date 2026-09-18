"""LAB-MCP-CATALOG local evidence packs. Splunk not verified."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.mcp.fixtures import MCP_CATALOG_DESCRIPTION_MALICIOUS, MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry

REQUIRED = (
    "manifest.json",
    "events.jsonl",
    "request.json",
    "result.json",
    "export.json",
    "limitations.json",
)


def test_catalog_retest_evidence_bundle_is_honest(settings, memory):
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-CATALOG-001",
        registry=default_registry(),
    )
    root = Path(result.evidence_dir)
    for name in REQUIRED:
        assert (root / name).exists(), name
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema.version"] == "1.7.0"
    assert manifest["attack.id"] == "MCP-CATALOG-001"
    assert manifest["catalog.fixture"] == "MALICIOUS"
    assert manifest["metadata.control.decision"] == "OBSERVE"
    assert manifest["metadata.control.reason"] == "metadata_is_data"
    assert manifest["metadata.trust"] == "untrusted_data"
    assert manifest["mcp.handler.lookup_policy.count"] == 1
    assert manifest["mcp.handler.lookup_customer_tier.count"] == 0
    assert manifest["follow_on.decision"] == "DENY"
    assert manifest["follow_on.reason"] == "tool_not_granted"
    assert manifest["server_owned.allowed_tools"] == "lookup_policy"
    assert manifest["splunk.validated"] is False
    assert manifest["splunk.verified"] is False
    export = json.loads((root / "export.json").read_text(encoding="utf-8"))
    assert export["splunk.verified"] is False
    events = (root / "events.jsonl").read_text(encoding="utf-8")
    assert "CTRL-MCP-METADATA-001" in events
    assert events.count('"event.name":"agentsec.mcp.started"') == 1
    assert "mcp_result_trust" not in events
    preview_events = [
        json.loads(line)
        for line in events.splitlines()
        if line.strip() and json.loads(line).get("agentsec.control.id") == "CTRL-MCP-METADATA-001"
    ]
    assert preview_events
    assert len(preview_events[0]["agentsec.content.preview"]) <= 200
    assert MCP_CATALOG_DESCRIPTION_MALICIOUS.startswith(preview_events[0]["agentsec.content.preview"][:20])
    limitations = json.loads((root / "limitations.json").read_text(encoding="utf-8"))
    assert any("splunk.verified=false" in item for item in limitations["items"])
    assert any("Scanners are not wired" in item for item in limitations["items"])
