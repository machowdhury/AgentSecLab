import json
from pathlib import Path

from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_RESTRICTED_SCOPE
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


def test_mcp003_retest_evidence_bundle_is_honest(settings, memory):
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-003",
        registry=default_registry(),
    )
    root = Path(result.evidence_dir)
    for name in REQUIRED:
        assert (root / name).exists(), name
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema.version"] == "1.7.0"
    assert manifest["mcp.handler.invoked.count"] == 0
    assert manifest["splunk.validated"] is False
    export = json.loads((root / "export.json").read_text(encoding="utf-8"))
    assert export["splunk.verified"] is False
    events = (root / "events.jsonl").read_text(encoding="utf-8")
    assert "policy:restricted:read" in events
    assert '"agentsec.mcp.allowed_scope":"policy:read"' in events or "policy:read" in events
    assert "agentsec.mcp.started" not in events
