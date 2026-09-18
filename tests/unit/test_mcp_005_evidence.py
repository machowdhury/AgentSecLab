import json
from pathlib import Path

from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.mcp.result_trust import MALICIOUS_POLICY_SUMMARY

REQUIRED = (
    "manifest.json",
    "events.jsonl",
    "request.json",
    "result.json",
    "export.json",
    "limitations.json",
)


def test_mcp005_retest_evidence_bundle_is_honest(settings, memory):
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-005",
        registry=default_registry(),
    )
    root = Path(result.evidence_dir)
    for name in REQUIRED:
        assert (root / name).exists(), name
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema.version"] == "1.7.0"
    assert manifest["attack.id"] == "MCP-005"
    assert manifest["mcp.handler.lookup_policy.count"] == 1
    assert manifest["mcp.handler.lookup_customer_tier.count"] == 0
    assert manifest["result.fixture"] == "MALICIOUS"
    assert manifest["result.derived_authority"] is False
    assert manifest["result.control.decision"] == "OBSERVE"
    assert manifest["follow_on.decision"] == "DENY"
    assert manifest["follow_on.reason"] == "tool_not_granted"
    assert manifest["server_owned.allowed_tools"] == "lookup_policy"
    assert manifest["splunk.validated"] is False
    export = json.loads((root / "export.json").read_text(encoding="utf-8"))
    assert export["splunk.verified"] is False
    result_doc = json.loads((root / "result.json").read_text(encoding="utf-8"))
    assert result_doc["tool.result"]["summary"] == MALICIOUS_POLICY_SUMMARY
    limitations = json.loads((root / "limitations.json").read_text(encoding="utf-8"))
    assert any("splunk.verified=false" in item for item in limitations["items"])
    events = (root / "events.jsonl").read_text(encoding="utf-8")
    assert "SECURITY_OVERRIDE" in events
    assert '"agentsec.mcp.started"' in events
    assert events.count('"gen_ai.tool.name":"lookup_customer_tier"') >= 1
    assert '"event.name":"agentsec.mcp.started"' in events
    started_lines = [line for line in events.splitlines() if "agentsec.mcp.started" in line]
    assert all("lookup_customer_tier" not in line or "lookup_policy" in line for line in started_lines)
    assert not any(
        json.loads(line).get("gen_ai.tool.name") == "lookup_customer_tier"
        and json.loads(line).get("event.name") == "agentsec.mcp.started"
        for line in events.splitlines()
        if line.strip()
    )
