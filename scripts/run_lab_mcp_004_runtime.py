"""Generate LAB-MCP-004 A/B/C local evidence bundles.

Not Splunk validation. Not a workshop. Runtime is authoritative.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("AGENTSEC_OTEL_ENABLED", "false")
os.environ.setdefault("AGENTSEC_ARTIFACTS_DIR", str(Path("artifacts").resolve()))

from agentsec.mcp.fixtures import (
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import MemorySink


def _run(*, profile: str, mode: str, arguments: dict, attack_id: str = "MCP-004"):
    reset_settings_cache()
    os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    settings = get_settings()
    memory = MemorySink()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=arguments,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        attack_id=attack_id,
        registry=default_registry(),
        write_evidence=True,
    )
    return result


def main() -> None:
    baseline = _run(profile="defended", mode="BASELINE", arguments=MCP_LOOKUP_POLICY_ARGS)
    attack = _run(profile="vulnerable", mode="ATTACK", arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS)
    retest = _run(profile="defended", mode="RETEST", arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS)
    summary = {
        "A_BASELINE": {
            "run_id": baseline.run_id,
            "decision": baseline.hops[0].control_decision,
            "reason": baseline.hops[0].control_reason,
            "handler": baseline.handler_invoke_count,
            "resource_id": "lending-basics",
            "evidence_dir": baseline.evidence_dir,
        },
        "B_ATTACK": {
            "run_id": attack.run_id,
            "decision": attack.hops[0].control_decision,
            "reason": attack.hops[0].control_reason,
            "handler": attack.handler_invoke_count,
            "resource_id": "executive-restricted",
            "evidence_dir": attack.evidence_dir,
        },
        "C_RETEST": {
            "run_id": retest.run_id,
            "decision": retest.hops[0].control_decision,
            "reason": retest.hops[0].control_reason,
            "handler": retest.handler_invoke_count,
            "resource_id": "executive-restricted",
            "evidence_dir": retest.evidence_dir,
        },
    }
    print(json.dumps(summary, indent=2))
    reset_settings_cache()


if __name__ == "__main__":
    main()
