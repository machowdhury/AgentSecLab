"""LAB-RAG-001 local evidence packs. Splunk not verified."""

from pathlib import Path

import json

from agentsec.mcp.registry import default_registry
from agentsec.rag.fixtures import DOCUMENT_ID_MALICIOUS, DOCUMENT_ID_NORMAL
from agentsec.rag.pipeline import run_rag_retrieve


def _run(settings, memory, *, mode: str, document_id: str):
    return run_rag_retrieve(
        document_id=document_id,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=default_registry(),
        write_evidence=True,
    )


def test_baseline_evidence_bundle(settings, memory):
    result = _run(settings, memory, mode="BASELINE", document_id=DOCUMENT_ID_NORMAL)
    assert result.evidence_dir
    bundle = Path(result.evidence_dir)
    for name in ("manifest.json", "events.jsonl", "request.json", "result.json", "export.json", "limitations.json"):
        assert (bundle / name).is_file(), name
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema.version"] == "1.7.0"
    assert manifest["attack.id"] == "RAG-001"
    assert manifest["splunk.verified"] is False
    assert manifest["rag.document.id"] == DOCUMENT_ID_NORMAL
    assert manifest["rag.control.decision"] == "OBSERVE"
    export = json.loads((bundle / "export.json").read_text(encoding="utf-8"))
    assert export.get("splunk.verified") is False or manifest["splunk.verified"] is False
    events = (bundle / "events.jsonl").read_text(encoding="utf-8")
    assert "full_document" not in events
    assert manifest["rag.content.preview"]
    assert len(manifest["rag.content.preview"]) <= 200


def test_retest_evidence_marks_deny(settings, memory):
    result = _run(settings, memory, mode="RETEST", document_id=DOCUMENT_ID_MALICIOUS)
    manifest = json.loads(Path(result.evidence_dir, "manifest.json").read_text(encoding="utf-8"))
    assert manifest["follow_on.decision"] == "DENY"
    assert manifest["mcp.handler.lookup_customer_tier.count"] == 0
    assert manifest["splunk.verified"] is False
