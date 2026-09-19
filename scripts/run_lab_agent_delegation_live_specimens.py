"""Generate LIVE OTEL LAB-AGENT-DELEGATION-001 specimens inside AcmeBank (OTLP on).

Not Splunk validation by itself. Do not set AGENTSEC_OTEL_ENABLED=false.
Run in the acmebank container so collector/HEC path is used.

Usage (container):
  python /tmp/run_lab_agent_delegation_live_specimens.py A
  python /tmp/run_lab_agent_delegation_live_specimens.py B
  python /tmp/run_lab_agent_delegation_live_specimens.py C
"""

from __future__ import annotations

import json
import os
import sys

from agentsec.identity.fixtures import adversarial_a2a_payload, baseline_a2a_payload
from agentsec.identity.pipeline import run_identity_delegation, write_identity_specimen_pack
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink, OtlpSink


def _settings(*, profile: str | None = None):
    if profile:
        os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, mode: str, profile: str, payload: dict):
    settings = _settings(profile=profile)
    memory = MemorySink()
    sink = FanoutSink([memory, OtlpSink(settings)])
    result = run_identity_delegation(
        payload=payload,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=default_registry(),
        write_evidence=True,
    )
    pack = write_identity_specimen_pack(label=mode, result=result, settings=settings)
    return result, pack


def specimen_a():
    return _run(mode="BASELINE", profile="defended", payload=baseline_a2a_payload())


def specimen_b():
    return _run(mode="ATTACK", profile="vulnerable", payload=adversarial_a2a_payload())


def specimen_c():
    return _run(mode="RETEST", profile="defended", payload=adversarial_a2a_payload())


SPECIMENS = {
    "A": specimen_a,
    "B": specimen_b,
    "C": specimen_c,
}


def main() -> None:
    if os.environ.get("AGENTSEC_OTEL_ENABLED", "").lower() in {"0", "false", "no", "off"}:
        raise SystemExit("Refuse: AGENTSEC_OTEL_ENABLED is false. Phase 12C specimens must use OTLP.")
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in SPECIMENS:
        raise SystemExit(f"usage: {sys.argv[0]} {'|'.join(SPECIMENS)}")
    result, pack = SPECIMENS[key]()
    follow = result.hops[1] if result.hops and len(result.hops) > 1 else None
    req = result.frozen_request
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
                "principal_id": result.principal_id,
                "caller_agent_id": result.caller_agent_id,
                "callee_agent_id": result.callee_agent_id,
                "requested_tool": req.requested_tool if req is not None else None,
                "requested_scope": req.requested_scope if req is not None else None,
                "resource": req.resource if req is not None else None,
                "claimed_scope": req.claimed_scope if req is not None else None,
                "request_fingerprint": result.request_fingerprint,
                "claim_trust": result.claim_trust,
                "identity_control_decision": result.identity_control_decision,
                "identity_control_reason": result.identity_control_reason,
                "follow_on_decision": result.follow_on_decision,
                "follow_on_reason": result.follow_on_reason,
                "follow_on_mcp_started": follow.mcp_started if follow else False,
                "follow_on_mcp_completed": follow.mcp_completed if follow else False,
                "follow_on_mcp_failed": follow.mcp_failed if follow else False,
                "lookup_policy_handler": result.lookup_policy_handler_count,
                "lookup_customer_tier_handler": result.lookup_customer_tier_handler_count,
                "overlay_applied": result.overlay_applied,
                "server_owned_allowed_tools": result.server_owned_allowed_tools,
                "terminal": result.terminal,
                "event_count": len(result.events),
                "event_names": [event.get("event.name") for event in result.events],
                "evidence_dir": result.evidence_dir,
                "specimen_dir": str(pack),
                "otel_enabled": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
