"""Generate LIVE OTEL MCP-004 specimens inside AcmeBank (OTLP on).

Not Splunk validation by itself. Do not set AGENTSEC_OTEL_ENABLED=false.
Run in the acmebank container so collector/HEC path is used.

Usage (container):
  python scripts/run_lab_mcp_004_live_specimens.py A
  python scripts/run_lab_mcp_004_live_specimens.py B
  ...
"""

from __future__ import annotations

import json
import os
import sys

from agentsec.mcp.fixtures import (
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
    MCP_POLICY_SCOPE,
    MCP_POLICY_UNKNOWN_ID,
)
from agentsec.mcp.pipeline import run_mcp_invoke, run_mcp_schema_failure
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink, OtlpSink


def _settings(*, profile: str | None = None):
    if profile:
        os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, tool: str, arguments: dict, scope: str, mode: str, attack_id: str, profile: str, registry=None):
    settings = _settings(profile=profile)
    memory = MemorySink()
    sink = FanoutSink([memory, OtlpSink(settings)])
    return run_mcp_invoke(
        tool=tool,
        arguments=arguments,
        requested_scope=scope,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        attack_id=attack_id,
        registry=registry or default_registry(),
        write_evidence=True,
    )


def specimen_a():
    return _run(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        scope=MCP_POLICY_SCOPE,
        mode="BASELINE",
        attack_id="MCP-004",
        profile="defended",
    )


def specimen_b():
    return _run(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        scope=MCP_POLICY_SCOPE,
        mode="ATTACK",
        attack_id="MCP-004",
        profile="vulnerable",
    )


def specimen_c():
    return _run(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        scope=MCP_POLICY_SCOPE,
        mode="RETEST",
        attack_id="MCP-004",
        profile="defended",
    )


def specimen_d():
    return _run(
        tool="lookup_policy",
        arguments={"policy_id": MCP_POLICY_UNKNOWN_ID},
        scope=MCP_POLICY_SCOPE,
        mode="ATTACK",
        attack_id="MCP-004",
        profile="defended",
    )


def specimen_e():
    return _run(
        tool="lookup_policy",
        arguments={},
        scope=MCP_POLICY_SCOPE,
        mode="ATTACK",
        attack_id="MCP-004",
        profile="defended",
    )


def specimen_f():
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected handler failure")

    registry.replace_handler("lookup_policy", boom)
    return _run(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        scope=MCP_POLICY_SCOPE,
        mode="BASELINE",
        attack_id="MCP-004",
        profile="defended",
        registry=registry,
    )


def specimen_g_duplicate_keys():
    """HTTP-boundary duplicate-key failure. Not a CTRL-MCP-001 event."""
    settings = _settings(profile="defended")
    memory = MemorySink()
    sink = FanoutSink([memory, OtlpSink(settings)])
    return run_mcp_schema_failure(
        sink=sink,
        memory=memory,
        settings=settings,
        user_id="unknown",
        testbed_mode="ATTACK",
        attack_id="MCP-004",
        error_reason="duplicate_json_keys",
        write_evidence=True,
    )


SPECIMENS = {
    "A": specimen_a,
    "B": specimen_b,
    "C": specimen_c,
    "D": specimen_d,
    "E": specimen_e,
    "F": specimen_f,
    "G": specimen_g_duplicate_keys,
}


def main() -> None:
    if os.environ.get("AGENTSEC_OTEL_ENABLED", "").lower() in {"0", "false", "no", "off"}:
        raise SystemExit("Refuse: AGENTSEC_OTEL_ENABLED is false. Phase 5C specimens must use OTLP.")
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in SPECIMENS:
        raise SystemExit(f"usage: {sys.argv[0]} {'|'.join(SPECIMENS)}")
    result = SPECIMENS[key]()
    hop = result.hops[0] if result.hops else None
    control = next(
        (event for event in result.events if event.get("event.name") == "agentsec.control.decision"),
        {},
    )
    print(
        json.dumps(
            {
                "specimen": key,
                "run_id": result.run_id,
                "profile": result.profile,
                "testbed_mode": result.testbed_mode,
                "attack_id": result.attack_id,
                "decision": hop.control_decision if hop else None,
                "reason": hop.control_reason if hop else result.block_reason,
                "handler": result.handler_invoke_count,
                "mcp_started": hop.mcp_started if hop else False,
                "mcp_completed": hop.mcp_completed if hop else False,
                "mcp_failed": hop.mcp_failed if hop else False,
                "resource_id": control.get("agentsec.mcp.resource.id"),
                "allowed_resource_ids": control.get("agentsec.mcp.allowed_resource.ids"),
                "event_count": len(result.events),
                "evidence_dir": result.evidence_dir,
                "otel_enabled": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
