import json
from pathlib import Path

from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_RESTRICTED_ARGS, MCP_POLICY_SCOPE
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


def test_mcp004_retest_evidence_bundle_is_honest(settings, memory):
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-004",
        registry=default_registry(),
    )
    root = Path(result.evidence_dir)
    for name in REQUIRED:
        assert (root / name).exists(), name
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema.version"] == "1.7.0"
    assert manifest["mcp.handler.invoked.count"] == 0
    assert manifest["mcp.resource.id"] == "executive-restricted"
    assert manifest["mcp.allowed_resource.ids"] == "lending-basics"
    assert manifest["splunk.validated"] is False
    export = json.loads((root / "export.json").read_text(encoding="utf-8"))
    assert export["splunk.verified"] is False
    events = (root / "events.jsonl").read_text(encoding="utf-8")
    assert "executive-restricted" in events
    assert "resource_not_granted" in events
    assert "agentsec.mcp.started" not in events
    result_doc = json.loads((root / "result.json").read_text(encoding="utf-8"))
    assert result_doc["mcp.resource.id"] == "executive-restricted"
    assert result_doc["mcp.allowed_resource.ids"] == "lending-basics"
