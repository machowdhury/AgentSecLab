import json
from pathlib import Path

from agentsec.attacks import BENIGN_LOAN
from agentsec.pipeline import run_loan_pipeline


def test_evidence_bundle_has_required_experiment_fields(settings, stub_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=stub_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="LIVE",
        attack_id="ATK-001",
    )
    root = Path(result.evidence_dir)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for key in (
        "run.id",
        "lab.id",
        "AgentSec version",
        "model",
        "security profile",
        "attack",
        "expected behavior",
        "actual behavior",
        "telemetry",
        "control result",
        "detection result",
        "limitations",
    ):
        assert key in manifest
    assert manifest["detection result"]["splunk_validated"] is False
    assert manifest["detection result"]["scope"] == "local_event_list_not_splunk"
    assert (root / "events.jsonl").exists()
    assert manifest["run.id"] == result.run_id
