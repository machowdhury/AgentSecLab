"""Workshop logic contracts for LAB-RAG-CONTEXT.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT"
DOCS = ROOT / "docs"
REQUIRED_FILES = (
    LAB_DIR / "README.md",
    LAB_DIR / "workshop.md",
    LAB_DIR / "evidence.md",
    LAB_DIR / "knowledge-check.md",
    LAB_DIR / "dashboard.definition.json",
)
WORKSHOP_STEPS = (
    "LEARN",
    "BASELINE",
    "ATTACK",
    "OBSERVE",
    "HUNT",
    "DETECT",
    "DEFEND",
    "RETEST",
    "COMPARE",
    "PROVE",
)
MALICIOUS_HASH = "sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef"
NORMAL_HASH = "sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e"
BASELINE_ID = "51f70fb9-994e-4dd4-9b36-cac6fb1e8232"
ATTACK_ID = "3a43d24f-9281-42f6-8375-1fb2efaa80ac"
RETEST_ID = "bea97bae-491b-4b36-b52f-1417d2bad01b"


def _lab_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in REQUIRED_FILES if path.suffix == ".md")


def _docs_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            DOCS / "PHASE10E_RAG_CONTEXT_WORKSHOP.md",
            DOCS / "learning-notes" / "rag-context-soc-investigation.md",
        )
    )


def test_required_workshop_files_exist():
    for path in REQUIRED_FILES:
        assert path.is_file(), path
    assert (LAB_DIR / "dashboard.md").is_file()
    assert (DOCS / "PHASE10E_RAG_CONTEXT_WORKSHOP.md").is_file()
    assert (DOCS / "learning-notes" / "rag-context-soc-investigation.md").is_file()
    notes = (DOCS / "learning-notes" / "rag-context-soc-investigation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    assert not (LAB_DIR / "searches" / "DET-RAG.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-RAG-INJECTION.spl").exists()


def test_ten_steps_and_evidence_ids():
    blob = _lab_text() + _docs_text()
    for step in WORKSHOP_STEPS:
        assert step in blob
    assert "ws_lab_rag_context" in blob
    assert MALICIOUS_HASH in blob
    assert NORMAL_HASH in blob
    assert BASELINE_ID in blob
    assert ATTACK_ID in blob
    assert RETEST_ID in blob
    assert blob.count(MALICIOUS_HASH) >= 4


def test_teaching_boundaries():
    blob = _lab_text() + _docs_text()
    assert "RETRIEVED CONTENT IS DATA" in blob
    assert "REQUEST != GRANT" in blob or "REQUEST ≠ GRANT" in blob
    assert "OBSERVE != ALLOW" in blob or "OBSERVE ≠ ALLOW" in blob
    assert "ALLOW != EXECUTION" in blob or "ALLOW ≠ EXECUTION" in blob
    assert "SPLUNK != ENFORCEMENT" in blob or "SPLUNK ≠ ENFORCEMENT" in blob
    assert "DETECTION ANALYZED — NO NEW RAG DETECTOR" in blob or "NO NEW DETECTOR" in blob
    assert "INTENTIONALLY VULNERABLE" in blob
    assert "handler count" in blob.lower()
    assert "INV-002" in blob
    assert "1.6.0" in blob
    assert "No DET-RAG" in blob or "no DET-RAG" in blob
    assert "Q-RAG-CONTEXT-AUTHORITY" in blob
    assert "FUTURE — NOT IMPLEMENTED" in blob or "FUTURE — NOT IMPLEMENTED" in blob.upper()
    lowered = blob.lower()
    assert "the retrieved text authorized" not in lowered
    assert "phase 11" in lowered
    teaching = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            LAB_DIR / "README.md",
            LAB_DIR / "workshop.md",
            LAB_DIR / "evidence.md",
        )
    ).lower()
    for claim in (
        "splunk blocked the action",
        "splunk prevented the attack",
        "the detector caught rag",
        "normal is safe",
        "untrusted_data means malicious",
    ):
        assert claim not in teaching


def test_knowledge_check_has_answers():
    text = (LAB_DIR / "knowledge-check.md").read_text(encoding="utf-8")
    assert "## Questions" in text
    assert "## Answers" in text
    assert text.index("## Questions") < text.index("## Answers")
    for n in range(1, 21):
        assert f"{n}." in text
    for needle in (
        "INV-002",
        "provenance",
        "OBSERVE",
        "ALLOW",
        "DENY",
        "DET-MCP-001",
        "handler",
        "hash",
        "tool_not_granted",
        "allowed_tools",
        "ML",
    ):
        assert needle in text
