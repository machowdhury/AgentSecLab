"""LAB-AGENT-GOAL-INTEGRITY-001 local evidence packs keep splunk.verified false."""

import json
from pathlib import Path

from agentsec.goal.fixtures import baseline_goal_payload
from agentsec.goal.pipeline import run_goal_integrity, write_goal_specimen_pack
from agentsec.mcp.registry import default_registry


def test_goal_evidence_bundles(settings, memory):
    result = run_goal_integrity(
        payload=baseline_goal_payload(),
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        registry=default_registry(),
    )
    evidence = Path(result.evidence_dir)
    manifest = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema.version"] == "1.9.0"
    assert manifest["splunk.verified"] is False
    pack = write_goal_specimen_pack(label="A", result=result, settings=settings)
    specimen = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    assert specimen["run.id"] == result.run_id
    assert specimen["splunk.verified"] is False
    for name in ("manifest.json", "events.jsonl", "export.json", "limitations.json", "request.json", "result.json"):
        assert (pack / name).is_file()
        assert (evidence / name).is_file()
