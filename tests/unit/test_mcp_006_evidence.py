import json
from pathlib import Path

from agentsec.mcp.delegation_pipeline import run_mcp_006_invoke
from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.registry import default_registry

REQUIRED = (
    "manifest.json",
    "events.jsonl",
    "request.json",
    "result.json",
    "export.json",
    "limitations.json",
)


def test_mcp006_baseline_evidence_bundle_is_honest(settings, memory):
    result = run_mcp_006_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        registry=default_registry(),
    )
    root = Path(result.evidence_dir)
    for name in REQUIRED:
        assert (root / name).exists(), name
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema.version"] == "1.6.0"
    assert manifest["attack.id"] == "MCP-006"
    assert manifest["mcp.lab.id"] == "LAB-MCP-006"
    assert manifest["mcp.handler.lookup_policy.count"] == 1
    assert manifest["mcp.handler.lookup_customer_tier.count"] == 0
    assert manifest["delegation.caller.id"] == "acme-agent-credit-002"
    assert manifest["delegation.deputy.id"] == "acme-agent-compliance-004"
    assert manifest["delegation.decision"] == "ALLOW"
    assert manifest["delegation.authority.source"] == "delegated"
    assert manifest["downstream.mcp.decision"] == "ALLOW"
    assert manifest["splunk.validated"] is False
    export = json.loads((root / "export.json").read_text(encoding="utf-8"))
    assert export["splunk.verified"] is False
    limitations = json.loads((root / "limitations.json").read_text(encoding="utf-8"))
    assert any("splunk.verified=false" in item for item in limitations["items"])
    assert any("DET-MCP-006" in item for item in limitations["items"])
