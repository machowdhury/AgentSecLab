"""Generate local LAB-AGENT-GOAL-INTEGRITY-001 evidence packs. Not Splunk validation.

Usage:
  uv run python scripts/run_lab_agent_goal_integrity_local_specimens.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from agentsec.goal.fixtures import adversarial_goal_payload, baseline_goal_payload
from agentsec.goal.pipeline import run_goal_integrity, write_goal_specimen_pack
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import MemorySink


def _settings(*, profile: str):
    os.environ["AGENTSEC_OTEL_ENABLED"] = "false"
    os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, mode: str, profile: str, payload: dict):
    settings = _settings(profile=profile)
    memory = MemorySink()
    result = run_goal_integrity(
        payload=payload,
        sink=memory,
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


def summarize(label: str, result, pack: Path) -> dict:
    return {
        "label": label,
        "run.id": result.run_id,
        "profile": result.profile,
        "mode": result.testbed_mode,
        "task.hash": result.task_fingerprint,
        "instruction.hash": result.instruction_hash,
        "goal.proposed": result.proposed_action,
        "goal.proposed.fingerprint": result.proposed_fingerprint,
        "goal.decision": result.goal_control_decision,
        "goal.reason": result.goal_control_reason,
        "effective.action": result.effective_action,
        "follow_on.decision": result.follow_on_decision,
        "follow_on.reason": result.follow_on_reason,
        "lookup_policy": result.lookup_policy_handler_count,
        "in_task": result.in_task_lookup_policy_count,
        "wrong_goal": result.wrong_goal_lookup_policy_count,
        "schema": "1.9.0",
        "specimen_dir": str(pack),
        "evidence_dir": result.evidence_dir,
        "splunk.verified": False,
    }


def main() -> None:
    rows = []
    for label, fn in (("A", specimen_a), ("B", specimen_b), ("C", specimen_c)):
        result, pack = fn()
        rows.append(summarize(label, result, pack))
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
