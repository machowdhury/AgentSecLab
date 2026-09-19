"""Generate LIVE OTEL MCP-006 specimens inside AcmeBank (OTLP on).

Not Splunk validation by itself. Do not set AGENTSEC_OTEL_ENABLED=false.
Run in the acmebank container so collector/HEC path is used.

Usage (container):
  python /tmp/run_lab_mcp_006_live_specimens.py A
  python /tmp/run_lab_mcp_006_live_specimens.py B
  python /tmp/run_lab_mcp_006_live_specimens.py C
"""

from __future__ import annotations

import json
import os
import sys

from agentsec.mcp.delegation_pipeline import run_mcp_006_invoke
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink, OtlpSink


def _settings(*, profile: str | None = None):
    if profile:
        os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, mode: str, profile: str, tool: str, arguments: dict, requested_scope: str):
    settings = _settings(profile=profile)
    memory = MemorySink()
    sink = FanoutSink([memory, OtlpSink(settings)])
    return run_mcp_006_invoke(
        tool=tool,
        arguments=arguments,
        requested_scope=requested_scope,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=default_registry(),
        write_evidence=True,
    )


def specimen_a():
    return _run(
        mode="BASELINE",
        profile="defended",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
    )


def specimen_b():
    return _run(
        mode="ATTACK",
        profile="vulnerable",
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
    )


def specimen_c():
    return _run(
        mode="RETEST",
        profile="defended",
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
    )


SPECIMENS = {
    "A": specimen_a,
    "B": specimen_b,
    "C": specimen_c,
}


def main() -> None:
    if os.environ.get("AGENTSEC_OTEL_ENABLED", "").lower() in {"0", "false", "no", "off"}:
        raise SystemExit("Refuse: AGENTSEC_OTEL_ENABLED is false. Phase 7C specimens must use OTLP.")
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in SPECIMENS:
        raise SystemExit(f"usage: {sys.argv[0]} {'|'.join(SPECIMENS)}")
    result = SPECIMENS[key]()
    events = result.events
    names = [event.get("event.name") for event in events]
    print(
        json.dumps(
            {
                "specimen": key,
                "run_id": result.run_id,
                "trace_id": events[0].get("trace_id") if events else None,
                "profile": result.profile,
                "testbed_mode": result.testbed_mode,
                "attack_id": result.attack_id,
                "schema_version": events[0].get("agentsec.schema.version") if events else None,
                "caller": result.caller_agent_id,
                "deputy": result.deputy_agent_id,
                "tool": result.hops[0].tool_name if result.hops else None,
                "delegation_decision": result.delegation_decision,
                "delegation_reason": result.delegation_reason,
                "authority_source": result.authority_source,
                "downstream_mcp_decision": result.downstream_mcp_decision,
                "attempted": result.operation_attempted,
                "executed": result.operation_executed,
                "outcome": result.operation_outcome,
                "handler": result.handler_invoke_count,
                "lookup_policy_handler": result.lookup_policy_handler_count,
                "lookup_customer_tier_handler": result.lookup_customer_tier_handler_count,
                "terminal": result.terminal,
                "event_count": len(events),
                "event_names": names,
                "evidence_dir": result.evidence_dir,
                "otel_enabled": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
