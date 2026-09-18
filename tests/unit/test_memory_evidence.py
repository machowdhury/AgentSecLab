"""LAB-MEMORY-001 local evidence packs include both run ids."""

import json
from pathlib import Path

from agentsec.memory.fixtures import MEMORY_ID_NORMAL
from agentsec.memory.pipeline import run_memory_recall, run_memory_write, write_memory_specimen_pack
from agentsec.memory.store import InProcessMemoryStore


def test_write_and_recall_evidence_bundles(settings, memory):
    store = InProcessMemoryStore()
    write = run_memory_write(
        memory_id=MEMORY_ID_NORMAL,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
    )
    recall = run_memory_recall(
        memory_id=MEMORY_ID_NORMAL,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
    )
    write_dir = Path(write.evidence_dir)
    recall_dir = Path(recall.evidence_dir)
    write_manifest = json.loads((write_dir / "manifest.json").read_text(encoding="utf-8"))
    recall_manifest = json.loads((recall_dir / "manifest.json").read_text(encoding="utf-8"))
    assert write_manifest["schema.version"] == "1.7.0"
    assert recall_manifest["schema.version"] == "1.7.0"
    assert write_manifest["memory.write.run.id"] == write.run_id
    assert recall_manifest["memory.write.run.id"] == write.run_id
    assert recall_manifest["memory.recall.run.id"] == recall.run_id
    assert recall_manifest["splunk.verified"] is False
    pack = write_memory_specimen_pack(label="A", write=write, recall=recall, settings=settings)
    specimen = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    assert specimen["memory.write.run.id"] == write.run_id
    assert specimen["memory.recall.run.id"] == recall.run_id
    for name in ("manifest.json", "events.jsonl", "export.json", "limitations.json", "request.json", "result.json"):
        assert (pack / name).is_file()
        assert (write_dir / name).is_file()
        assert (recall_dir / name).is_file()
