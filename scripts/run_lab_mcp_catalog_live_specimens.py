"""Generate LIVE OTEL LAB-MCP-CATALOG specimens inside AcmeBank (OTLP on).

Not Splunk validation by itself. Do not set AGENTSEC_OTEL_ENABLED=false.
Run in the acmebank container so collector/HEC path is used.

Usage (container):
  python /tmp/run_lab_mcp_catalog_live_specimens.py A
  python /tmp/run_lab_mcp_catalog_live_specimens.py B
  python /tmp/run_lab_mcp_catalog_live_specimens.py C
"""

from __future__ import annotations

import json
import os
import sys

from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink, OtlpSink


def _settings(*, profile: str | None = None):
    if profile:
        os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, mode: str, profile: str):
    settings = _settings(profile=profile)
    memory = MemorySink()
    sink = FanoutSink([memory, OtlpSink(settings)])
    return run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        attack_id="MCP-CATALOG-001",
        registry=default_registry(),
        write_evidence=True,
    )


def specimen_a():
    return _run(mode="BASELINE", profile="defended")


def specimen_b():
    return _run(mode="ATTACK", profile="vulnerable")


def specimen_c():
    return _run(mode="RETEST", profile="defended")


SPECIMENS = {
    "A": specimen_a,
    "B": specimen_b,
    "C": specimen_c,
}


def main() -> None:
    if os.environ.get("AGENTSEC_OTEL_ENABLED", "").lower() in {"0", "false", "no", "off"}:
        raise SystemExit("Refuse: AGENTSEC_OTEL_ENABLED is false. Phase 8D specimens must use OTLP.")
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in SPECIMENS:
        raise SystemExit(f"usage: {sys.argv[0]} {'|'.join(SPECIMENS)}")
    result = SPECIMENS[key]()
    first = result.hops[0] if result.hops else None
    follow = result.hops[1] if result.hops and len(result.hops) > 1 else None
    names = [event.get("event.name") for event in result.events]
    print(
        json.dumps(
            {
                "specimen": key,
                "run_id": result.run_id,
                "profile": result.profile,
                "testbed_mode": result.testbed_mode,
                "attack_id": result.attack_id,
                "schema_version": result.events[0].get("agentsec.schema.version") if result.events else None,
                "trace_id": result.events[0].get("trace_id") if result.events else None,
                "catalog_fixture": result.catalog_fixture,
                "catalog_description_hash": result.catalog_description_hash,
                "catalog_description_preview": result.catalog_description_preview,
                "metadata_trust": result.metadata_trust,
                "metadata_control_decision": result.metadata_control_decision,
                "metadata_control_reason": result.metadata_control_reason,
                "metadata_derived_authority": result.metadata_derived_authority,
                "initial_decision": first.control_decision if first else None,
                "initial_reason": first.control_reason if first else None,
                "lookup_policy_handler": result.lookup_policy_handler_count,
                "lookup_customer_tier_handler": result.lookup_customer_tier_handler_count,
                "follow_on_decision": result.follow_on_decision,
                "follow_on_reason": result.follow_on_reason,
                "follow_on_mcp_started": follow.mcp_started if follow else False,
                "follow_on_attempted": follow.operation_attempted if follow else None,
                "follow_on_executed": follow.operation_executed if follow else None,
                "follow_on_outcome": follow.operation_outcome if follow else None,
                "server_owned_allowed_tools": result.server_owned_allowed_tools,
                "terminal": result.terminal,
                "event_count": len(result.events),
                "event_names": names,
                "evidence_dir": result.evidence_dir,
                "otel_enabled": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
