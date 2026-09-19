"""Generate LIVE OTEL LAB-AGENT-GOAL-INTEGRITY-001 specimens (OTLP on).

Not Splunk validation by itself. Do not set AGENTSEC_OTEL_ENABLED=false.

Usage (host, collector on 127.0.0.1:4318):
  AGENTSEC_OTEL_ENABLED=true OTEL_SERVICE_NAME=acmebank \\
    uv run python scripts/run_lab_agent_goal_integrity_live_specimens.py A
  ... B
  ... C
"""

from __future__ import annotations

import json
import os
import sys

from agentsec.goal.fixtures import adversarial_goal_payload, baseline_goal_payload
from agentsec.goal.pipeline import run_goal_integrity, write_goal_specimen_pack
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
    result = run_goal_integrity(
        payload=payload,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=default_registry(),
        write_evidence=True,
    )
    pack = write_goal_specimen_pack(label=mode, result=result, settings=settings)
    return result, pack


def specimen_a():
    return _run(mode="BASELINE", profile="defended", payload=baseline_goal_payload())


def specimen_b():
    return _run(mode="ATTACK", profile="vulnerable", payload=adversarial_goal_payload())


def specimen_c():
    return _run(mode="RETEST", profile="defended", payload=adversarial_goal_payload())


SPECIMENS = {
    "A": specimen_a,
    "B": specimen_b,
    "C": specimen_c,
}


def main() -> None:
    if os.environ.get("AGENTSEC_OTEL_ENABLED", "").lower() in {"0", "false", "no", "off"}:
        raise SystemExit("Refuse: AGENTSEC_OTEL_ENABLED is false. Phase 13C specimens must use OTLP.")
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in SPECIMENS:
        raise SystemExit(f"usage: {sys.argv[0]} {'|'.join(SPECIMENS)}")
    result, pack = SPECIMENS[key]()
    follow = result.hops[1] if result.hops and len(result.hops) > 1 else None
    print(
        json.dumps(
            {
                "specimen": key,
                "run_id": result.run_id,
                "profile": result.profile,
                "testbed_mode": result.testbed_mode,
                "attack_id": result.attack_id,
                "schema_version": result.events[0].get("agentsec.schema.version") if result.events else None,
                "task_id": result.frozen_task.task_id,
                "task_hash": result.task_fingerprint,
                "instruction_hash": result.instruction_hash,
                "proposed_fingerprint": result.proposed_fingerprint,
                "proposed_action": result.proposed_action,
                "effective_action": result.effective_action,
                "goal_control_decision": result.goal_control_decision,
                "goal_control_reason": result.goal_control_reason,
                "follow_on_decision": result.follow_on_decision,
                "follow_on_reason": result.follow_on_reason,
                "follow_on_mcp_started": follow.mcp_started if follow else False,
                "follow_on_mcp_completed": follow.mcp_completed if follow else False,
                "in_task_handler": result.in_task_lookup_policy_count,
                "wrong_goal_handler": result.wrong_goal_lookup_policy_count,
                "lookup_policy_handler": result.lookup_policy_handler_count,
                "overlay_applied": result.overlay_applied,
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
