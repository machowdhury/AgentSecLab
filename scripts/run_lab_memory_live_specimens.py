"""Generate LIVE OTEL LAB-MEMORY-001 specimens inside AcmeBank (OTLP on).

Not Splunk validation by itself. Do not set AGENTSEC_OTEL_ENABLED=false.
Run in the acmebank container so collector/HEC path is used.

Each specimen is TWO runs (write then recall) sharing one InProcessMemoryStore.

Usage (container):
  python /tmp/run_lab_memory_live_specimens.py A
  python /tmp/run_lab_memory_live_specimens.py B
  python /tmp/run_lab_memory_live_specimens.py C
"""

from __future__ import annotations

import json
import os
import sys

from agentsec.mcp.registry import default_registry
from agentsec.memory.fixtures import MEMORY_ID_MALICIOUS, MEMORY_ID_NORMAL
from agentsec.memory.pipeline import run_memory_recall, run_memory_write, write_memory_specimen_pack
from agentsec.memory.store import InProcessMemoryStore
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink, OtlpSink


def _settings(*, profile: str | None = None):
    if profile:
        os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _sink():
    settings = get_settings()
    memory = MemorySink()
    sink = FanoutSink([memory, OtlpSink(settings)])
    return settings, memory, sink


def _specimen(*, mode: str, write_profile: str, recall_profile: str, memory_id: str):
    store = InProcessMemoryStore()
    write_settings = _settings(profile=write_profile)
    write_mem = MemorySink()
    write_sink = FanoutSink([write_mem, OtlpSink(write_settings)])
    write = run_memory_write(
        memory_id=memory_id,
        store=store,
        sink=write_sink,
        memory=write_mem,
        settings=write_settings,
        testbed_mode=mode,
    )
    recall_settings = _settings(profile=recall_profile)
    recall_mem = MemorySink()
    recall_sink = FanoutSink([recall_mem, OtlpSink(recall_settings)])
    recall = run_memory_recall(
        memory_id=memory_id,
        store=store,
        sink=recall_sink,
        memory=recall_mem,
        settings=recall_settings,
        testbed_mode=mode,
        registry=default_registry(),
    )
    pack = write_memory_specimen_pack(
        label=mode, write=write, recall=recall, settings=recall_settings
    )
    return write, recall, pack


def specimen_a():
    return _specimen(
        mode="BASELINE",
        write_profile="defended",
        recall_profile="defended",
        memory_id=MEMORY_ID_NORMAL,
    )


def specimen_b():
    return _specimen(
        mode="ATTACK",
        write_profile="defended",
        recall_profile="vulnerable",
        memory_id=MEMORY_ID_MALICIOUS,
    )


def specimen_c():
    return _specimen(
        mode="RETEST",
        write_profile="defended",
        recall_profile="defended",
        memory_id=MEMORY_ID_MALICIOUS,
    )


SPECIMENS = {
    "A": specimen_a,
    "B": specimen_b,
    "C": specimen_c,
}


def _names(events):
    return [event.get("event.name") for event in events]


def main() -> None:
    if os.environ.get("AGENTSEC_OTEL_ENABLED", "").lower() in {"0", "false", "no", "off"}:
        raise SystemExit("Refuse: AGENTSEC_OTEL_ENABLED is false. Phase 11C specimens must use OTLP.")
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in SPECIMENS:
        raise SystemExit(f"usage: {sys.argv[0]} {'|'.join(SPECIMENS)}")
    write, recall, pack = SPECIMENS[key]()
    follow = recall.hops[1] if recall.hops and len(recall.hops) > 1 else None
    print(
        json.dumps(
            {
                "specimen": key,
                "write.run_id": write.run_id,
                "recall.run_id": recall.run_id,
                "write.profile": write.profile,
                "recall.profile": recall.profile,
                "testbed_mode": recall.testbed_mode,
                "attack_id": recall.attack_id,
                "schema_version": recall.events[0].get("agentsec.schema.version") if recall.events else None,
                "write.trace_id": write.events[0].get("trace_id") if write.events else None,
                "recall.trace_id": recall.events[0].get("trace_id") if recall.events else None,
                "memory_id": recall.memory_id,
                "write.content_hash": write.content_hash,
                "recall.content_hash": recall.content_hash,
                "hashes_equal": write.content_hash == recall.content_hash,
                "memory_trust": recall.memory_trust,
                "memory_provenance": recall.memory_provenance,
                "source_run_id": recall.source_run_id,
                "memory_control_decision": recall.memory_control_decision,
                "memory_control_reason": recall.memory_control_reason,
                "memory_derived_authority": recall.memory_derived_authority,
                "follow_on_request": recall.follow_on_request,
                "follow_on_decision": recall.follow_on_decision,
                "follow_on_reason": recall.follow_on_reason,
                "follow_on_mcp_started": follow.mcp_started if follow else False,
                "follow_on_attempted": follow.operation_attempted if follow else None,
                "follow_on_executed": follow.operation_executed if follow else None,
                "follow_on_outcome": follow.operation_outcome if follow else None,
                "lookup_customer_tier_handler": recall.lookup_customer_tier_handler_count,
                "server_owned_allowed_tools": recall.server_owned_allowed_tools,
                "write.terminal": write.terminal,
                "recall.terminal": recall.terminal,
                "write.event_count": len(write.events),
                "recall.event_count": len(recall.events),
                "write.event_names": _names(write.events),
                "recall.event_names": _names(recall.events),
                "write.evidence_dir": write.evidence_dir,
                "recall.evidence_dir": recall.evidence_dir,
                "specimen_dir": str(pack),
                "otel_enabled": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
