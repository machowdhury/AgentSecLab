"""Generate local LAB-MCP-CATALOG evidence packs. Not Splunk validation.

Usage:
  .venv/bin/python scripts/run_lab_mcp_catalog_local_specimens.py
"""

from __future__ import annotations

import json
import os

from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import MemorySink


def _settings(*, profile: str):
    os.environ["AGENTSEC_OTEL_ENABLED"] = "false"
    os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, mode: str, profile: str):
    settings = _settings(profile=profile)
    memory = MemorySink()
    return run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        attack_id="MCP-CATALOG-001",
        registry=default_registry(),
        write_evidence=True,
    )


def summarize(label: str, result) -> dict:
    return {
        "label": label,
        "run.id": result.run_id,
        "profile": result.profile,
        "mode": result.testbed_mode,
        "catalog.fixture": result.catalog_fixture,
        "description.hash": result.catalog_description_hash,
        "metadata.decision": result.metadata_control_decision,
        "metadata.reason": result.metadata_control_reason,
        "first.decision": result.hops[0].control_decision if result.hops else None,
        "follow_on.decision": result.follow_on_decision,
        "follow_on.reason": result.follow_on_reason,
        "lookup_policy": result.lookup_policy_handler_count,
        "lookup_customer_tier": result.lookup_customer_tier_handler_count,
        "schema": "1.5.0",
        "evidence_dir": result.evidence_dir,
        "splunk.verified": False,
    }


def main() -> None:
    rows = []
    a = _run(mode="BASELINE", profile="defended")
    rows.append(summarize("A BASELINE", a))
    b = _run(mode="ATTACK", profile="vulnerable")
    rows.append(summarize("B ATTACK", b))
    c = _run(mode="RETEST", profile="defended")
    rows.append(summarize("C RETEST", c))
    print(json.dumps(rows, indent=2))
    from pathlib import Path

    artifacts = Path(a.evidence_dir).parent
    (artifacts / "lab-mcp-catalog-local-summary.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    reset_settings_cache()


if __name__ == "__main__":
    main()
