"""Generate LIVE OTEL LAB-RAG-001 specimens inside AcmeBank (OTLP on).

Not Splunk validation by itself. Do not set AGENTSEC_OTEL_ENABLED=false.
Run in the acmebank container so collector/HEC path is used.

Usage (container):
  python /tmp/run_lab_rag_live_specimens.py A
  python /tmp/run_lab_rag_live_specimens.py B
  python /tmp/run_lab_rag_live_specimens.py C
"""

from __future__ import annotations

import json
import os
import sys

from agentsec.mcp.registry import default_registry
from agentsec.rag.fixtures import DOCUMENT_ID_MALICIOUS, DOCUMENT_ID_NORMAL
from agentsec.rag.pipeline import run_rag_retrieve
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink, OtlpSink


def _settings(*, profile: str | None = None):
    if profile:
        os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _run(*, mode: str, profile: str, document_id: str):
    settings = _settings(profile=profile)
    memory = MemorySink()
    sink = FanoutSink([memory, OtlpSink(settings)])
    return run_rag_retrieve(
        document_id=document_id,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=default_registry(),
        write_evidence=True,
    )


def specimen_a():
    return _run(mode="BASELINE", profile="defended", document_id=DOCUMENT_ID_NORMAL)


def specimen_b():
    return _run(mode="ATTACK", profile="vulnerable", document_id=DOCUMENT_ID_MALICIOUS)


def specimen_c():
    return _run(mode="RETEST", profile="defended", document_id=DOCUMENT_ID_MALICIOUS)


SPECIMENS = {
    "A": specimen_a,
    "B": specimen_b,
    "C": specimen_c,
}


def main() -> None:
    if os.environ.get("AGENTSEC_OTEL_ENABLED", "").lower() in {"0", "false", "no", "off"}:
        raise SystemExit("Refuse: AGENTSEC_OTEL_ENABLED is false. Phase 10C specimens must use OTLP.")
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in SPECIMENS:
        raise SystemExit(f"usage: {sys.argv[0]} {'|'.join(SPECIMENS)}")
    result = SPECIMENS[key]()
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
                "document_id": result.document_id,
                "content_hash": result.content_hash,
                "content_preview": result.content_preview,
                "context_trust": result.context_trust,
                "context_provenance": result.context_provenance,
                "context_control_decision": result.context_control_decision,
                "context_control_reason": result.context_control_reason,
                "context_derived_authority": result.context_derived_authority,
                "follow_on_request": result.follow_on_request,
                "follow_on_decision": result.follow_on_decision,
                "follow_on_reason": result.follow_on_reason,
                "follow_on_mcp_started": follow.mcp_started if follow else False,
                "follow_on_attempted": follow.operation_attempted if follow else None,
                "follow_on_executed": follow.operation_executed if follow else None,
                "follow_on_outcome": follow.operation_outcome if follow else None,
                "lookup_customer_tier_handler": result.lookup_customer_tier_handler_count,
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
