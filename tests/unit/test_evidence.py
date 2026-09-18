import json
from pathlib import Path

from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.events import content_hash
from agentsec.pipeline import run_loan_pipeline


REQUIRED_EVIDENCE_FILES = (
    "manifest.json",
    "events.jsonl",
    "request.json",
    "result.json",
    "export.json",
    "limitations.json",
)


def test_evidence_bundle_has_required_files_and_honest_export(settings, counting_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    root = Path(result.evidence_dir)
    for name in REQUIRED_EVIDENCE_FILES:
        assert (root / name).exists(), name

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema.name"] == "agentsec.security_event"
    assert manifest["schema.version"] == "1.7.0"
    assert manifest["run.id"] == result.run_id
    assert manifest["incident.id"] == result.run_id
    assert manifest["testbed.mode"] == "BASELINE"
    assert manifest["execution.mode"] == "LIVE"
    assert manifest["telemetry.fidelity"] == "OBSERVED"
    assert manifest["splunk.validated"] is False
    assert manifest["runtime.authoritative"] is True
    assert manifest["llm.invoked.count"] == 4
    assert manifest["llm.completed.count"] == 4

    export = json.loads((root / "export.json").read_text(encoding="utf-8"))
    assert export["otlp.attempted"] is False
    assert export["otlp.ok"] is False
    assert export["splunk.attempted"] is False
    assert export["splunk.verified"] is False
    assert export["hec.ok"] is False
    assert export["collector.observed"] is False
    assert "NOT VERIFIED" in export["note"]
    assert "does NOT mean" in export["note"]

    request_doc = json.loads((root / "request.json").read_text(encoding="utf-8"))
    assert set(request_doc) == {"input.length", "input.hash", "input.preview"}
    assert request_doc["input.hash"] == content_hash(BENIGN_LOAN)
    assert "input" not in request_doc
    assert "prompt" not in request_doc

    result_doc = json.loads((root / "result.json").read_text(encoding="utf-8"))
    assert result_doc["hops"][0]["operation.executed"] is True
    assert result_doc["hops"][0]["operation.outcome"] == "success"
    assert "delegator.agent.id" not in result_doc["hops"][0]
    assert result_doc["hops"][1]["delegator.agent.id"] == result.hops[0].agent_id


def test_evidence_does_not_store_full_prompt_by_default(settings, counting_llm, memory):
    long_input = ("Please consider this home loan application. " * 20) + "Amount 250000."
    assert len(long_input) > 200
    result = run_loan_pipeline(
        long_input,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    root = Path(result.evidence_dir)
    bundle_text = (root / "request.json").read_text(encoding="utf-8")
    events_text = (root / "events.jsonl").read_text(encoding="utf-8")
    assert long_input not in bundle_text
    assert long_input not in events_text
    request_doc = json.loads((root / "request.json").read_text(encoding="utf-8"))
    assert len(request_doc["input.preview"]) <= 200
    assert request_doc["input.hash"] == content_hash(long_input)
    for event in result.events:
        assert "gen_ai.input.messages" not in event
        preview = event.get("agentsec.content.preview")
        if preview is not None:
            assert len(preview) <= 200


def test_denied_evidence_agrees_with_runtime(settings, counting_llm, memory):
    result = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="ATK-002",
    )
    root = Path(result.evidence_dir)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    result_doc = json.loads((root / "result.json").read_text(encoding="utf-8"))
    assert manifest["llm.invoked.count"] == 0
    assert manifest["blocked"] is True
    hop = result_doc["hops"][0]
    assert hop["control.decision"] == "DENY"
    assert hop["operation.attempted"] is False
    assert hop["operation.executed"] is False
    assert hop["operation.outcome"] == "prevented"
    assert hop["llm.started"] is False
    assert counting_llm.call_count == 0
    events = (root / "events.jsonl").read_text(encoding="utf-8")
    assert "agentsec.llm.started" not in events
