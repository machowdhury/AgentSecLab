"""Generate local MCP-006 evidence packs. Not Splunk validation.

Usage:
  .venv/bin/python scripts/run_lab_mcp_006_local_specimens.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from agentsec.mcp.delegation import DelegationRequest
from agentsec.mcp.delegation_pipeline import run_mcp_006_invoke
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_RESTRICTED_SCOPE,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import MemorySink


def _settings(*, profile: str) -> object:
    os.environ["AGENTSEC_OTEL_ENABLED"] = "false"
    os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, mode: str, profile: str, tool: str, arguments: dict, requested_scope: str, **kwargs):
    settings = _settings(profile=profile)
    memory = MemorySink()
    return run_mcp_006_invoke(
        tool=tool,
        arguments=arguments,
        requested_scope=requested_scope,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=kwargs.pop("registry", default_registry()),
        write_evidence=True,
        **kwargs,
    )


def summarize(label: str, result) -> dict:
    return {
        "label": label,
        "run.id": result.run_id,
        "profile": result.profile,
        "mode": result.testbed_mode,
        "caller": result.caller_agent_id,
        "deputy": result.deputy_agent_id,
        "tool": result.hops[0].tool_name if result.hops else None,
        "delegation.decision": result.delegation_decision,
        "delegation.reason": result.delegation_reason,
        "authority.source": result.authority_source,
        "downstream.mcp.decision": result.downstream_mcp_decision,
        "attempted": result.operation_attempted,
        "executed": result.operation_executed,
        "outcome": result.operation_outcome,
        "handler": result.handler_invoke_count,
        "lookup_policy": result.lookup_policy_handler_count,
        "lookup_customer_tier": result.lookup_customer_tier_handler_count,
        "event_count": len(result.events),
        "schema": "1.4.0",
        "evidence_dir": result.evidence_dir,
        "splunk.verified": False,
    }


def main() -> None:
    rows = []
    a = _run(
        mode="BASELINE",
        profile="defended",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
    )
    rows.append(summarize("A-BASELINE", a))
    b = _run(
        mode="ATTACK",
        profile="vulnerable",
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
    )
    rows.append(summarize("B-ATTACK", b))
    c = _run(
        mode="RETEST",
        profile="defended",
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
    )
    rows.append(summarize("C-RETEST", c))
    d = _run(
        mode="ATTACK",
        profile="defended",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        request=DelegationRequest(
            principal_id="applicant-web",
            caller_agent_id="acme-agent-unknown-999",
            deputy_agent_id="acme-agent-compliance-004",
            tool="lookup_policy",
            requested_scope=MCP_POLICY_SCOPE,
            arguments=MCP_LOOKUP_POLICY_ARGS,
        ),
    )
    rows.append(summarize("D-unknown-caller", d))
    e = _run(
        mode="ATTACK",
        profile="defended",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        request=DelegationRequest(
            principal_id="applicant-web",
            caller_agent_id="acme-agent-credit-002",
            deputy_agent_id="acme-agent-risk-003",
            tool="lookup_policy",
            requested_scope=MCP_POLICY_SCOPE,
            arguments=MCP_LOOKUP_POLICY_ARGS,
        ),
    )
    rows.append(summarize("E-unknown-deputy", e))
    k = _run(
        mode="BASELINE",
        profile="defended",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
    )
    rows.append(summarize("K-mcp-deny", k))
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected deputy handler failure")

    registry.replace_handler("lookup_policy", boom)
    el = _run(
        mode="BASELINE",
        profile="defended",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        registry=registry,
    )
    rows.append(summarize("L-handler-fail", el))
    out = Path("artifacts/lab-mcp-006-local-summary.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
