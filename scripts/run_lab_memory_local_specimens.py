"""Generate local LAB-MEMORY-001 evidence packs. Not Splunk validation.

Usage:
  uv run python scripts/run_lab_memory_local_specimens.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from agentsec.mcp.registry import default_registry
from agentsec.memory.fixtures import MEMORY_ID_MALICIOUS, MEMORY_ID_NORMAL
from agentsec.memory.pipeline import run_memory_recall, run_memory_write, write_memory_specimen_pack
from agentsec.memory.store import InProcessMemoryStore
from agentsec.settings import get_settings, reset_settings_cache
from agentsec.telemetry import MemorySink


def _settings(*, profile: str):
    os.environ["AGENTSEC_OTEL_ENABLED"] = "false"
    os.environ["AGENTSEC_SECURITY_PROFILE"] = profile
    reset_settings_cache()
    return get_settings()


def _specimen(*, label: str, mode: str, profile_write: str, profile_recall: str, memory_id: str):
    store = InProcessMemoryStore()
    write_settings = _settings(profile=profile_write)
    write_sink = MemorySink()
    write = run_memory_write(
        memory_id=memory_id,
        store=store,
        sink=write_sink,
        memory=write_sink,
        settings=write_settings,
        testbed_mode=mode,
    )
    recall_settings = _settings(profile=profile_recall)
    recall_sink = MemorySink()
    recall = run_memory_recall(
        memory_id=memory_id,
        store=store,
        sink=recall_sink,
        memory=recall_sink,
        settings=recall_settings,
        testbed_mode=mode,
        registry=default_registry(),
    )
    pack = write_memory_specimen_pack(
        label=label, write=write, recall=recall, settings=recall_settings
    )
    return write, recall, pack


def summarize(label: str, write, recall, pack: Path) -> dict:
    return {
        "label": label,
        "write.run.id": write.run_id,
        "recall.run.id": recall.run_id,
        "write.profile": write.profile,
        "recall.profile": recall.profile,
        "mode": recall.testbed_mode,
        "memory.id": recall.memory_id,
        "content.hash": recall.content_hash,
        "memory.decision": recall.memory_control_decision,
        "memory.reason": recall.memory_control_reason,
        "follow_on.decision": recall.follow_on_decision,
        "follow_on.reason": recall.follow_on_reason,
        "lookup_customer_tier": recall.lookup_customer_tier_handler_count,
        "schema": "1.7.0",
        "specimen_dir": str(pack),
        "write.evidence_dir": write.evidence_dir,
        "recall.evidence_dir": recall.evidence_dir,
        "splunk.verified": False,
    }


def main() -> None:
    rows = []
    a_write, a_recall, a_pack = _specimen(
        label="A",
        mode="BASELINE",
        profile_write="defended",
        profile_recall="defended",
        memory_id=MEMORY_ID_NORMAL,
    )
    rows.append(summarize("A BASELINE", a_write, a_recall, a_pack))
    b_write, b_recall, b_pack = _specimen(
        label="B",
        mode="ATTACK",
        profile_write="defended",
        profile_recall="vulnerable",
        memory_id=MEMORY_ID_MALICIOUS,
    )
    rows.append(summarize("B ATTACK", b_write, b_recall, b_pack))
    c_write, c_recall, c_pack = _specimen(
        label="C",
        mode="RETEST",
        profile_write="defended",
        profile_recall="defended",
        memory_id=MEMORY_ID_MALICIOUS,
    )
    rows.append(summarize("C RETEST", c_write, c_recall, c_pack))
    print(json.dumps(rows, indent=2))
    artifacts = Path(a_recall.evidence_dir).parent
    (artifacts / "lab-memory-001-local-summary.json").write_text(
        json.dumps(rows, indent=2) + "\n", encoding="utf-8"
    )
    reset_settings_cache()


if __name__ == "__main__":
    main()
