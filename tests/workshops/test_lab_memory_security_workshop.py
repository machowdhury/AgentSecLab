"""Workshop logic contracts for LAB-MEMORY-001.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MEMORY-001"
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
MALICIOUS_HASH = "sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9"
NORMAL_HASH = "sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b"
BASELINE_WRITE = "a8407246-7992-4ad8-bd02-cb701e150f30"
BASELINE_RECALL = "914c41ce-5123-49eb-892c-c948295dbc46"
ATTACK_WRITE = "05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464"
ATTACK_RECALL = "b8737cd9-9b6b-48f2-acfa-178ae1446ddc"
RETEST_WRITE = "060a0a72-ceb5-4b99-8330-98de81d8ae5e"
RETEST_RECALL = "5d5b9d1b-092d-4ddb-8422-4092d289cd49"


def _lab_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in REQUIRED_FILES if path.suffix == ".md")


def _docs_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            DOCS / "PHASE11E_MEMORY_SECURITY_WORKSHOP.md",
            DOCS / "learning-notes" / "memory-soc-investigation.md",
        )
    )


def test_required_workshop_files_exist():
    for path in REQUIRED_FILES:
        assert path.is_file(), path
    assert (LAB_DIR / "dashboard.md").is_file()
    assert (DOCS / "PHASE11E_MEMORY_SECURITY_WORKSHOP.md").is_file()
    assert (DOCS / "learning-notes" / "memory-soc-investigation.md").is_file()
    notes = (DOCS / "learning-notes" / "memory-soc-investigation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    assert not (LAB_DIR / "searches" / "DET-MEMORY.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-MEMORY-WRITE.spl").exists()


def test_ten_steps_and_evidence_ids():
    blob = _lab_text() + _docs_text()
    for step in WORKSHOP_STEPS:
        assert step in blob
    assert "ws_lab_memory_security" in blob
    assert MALICIOUS_HASH in blob
    assert NORMAL_HASH in blob
    assert BASELINE_WRITE in blob
    assert BASELINE_RECALL in blob
    assert ATTACK_WRITE in blob
    assert ATTACK_RECALL in blob
    assert RETEST_WRITE in blob
    assert RETEST_RECALL in blob
    assert blob.count(MALICIOUS_HASH) >= 4


def test_teaching_boundaries():
    blob = _lab_text() + _docs_text()
    assert "PERSISTED MEMORY != TRUSTED INSTRUCTION" in blob
    assert "MEMORY RECALL != AUTHORIZATION" in blob
    assert "REQUEST != GRANT" in blob or "REQUEST ≠ GRANT" in blob
    assert "OBSERVE != ALLOW" in blob or "OBSERVE ≠ ALLOW" in blob
    assert "ALLOW != EXECUTION" in blob or "ALLOW ≠ EXECUTION" in blob
    assert "SPLUNK != ENFORCEMENT" in blob or "SPLUNK ≠ ENFORCEMENT" in blob
    assert "DETECTION ANALYZED — NO NEW MEMORY DETECTOR" in blob or "NO NEW DETECTOR" in blob
    assert "INTENTIONALLY VULNERABLE" in blob
    assert "handler count" in blob.lower()
    assert "INV-003" in blob
    assert "1.7.0" in blob
    assert "No DET-MEMORY" in blob or "no DET-MEMORY" in blob
    assert "Q-MEMORY-CONTEXT-AUTHORITY" in blob
    assert "FUTURE — NOT IMPLEMENTED" in blob or "FUTURE — NOT IMPLEMENTED" in blob.upper()
    lowered = blob.lower()
    assert "the memory authorized the tool" not in lowered
    assert "phase 12" in lowered
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
        "the detector caught memory",
        "normal is safe",
        "untrusted_data means malicious",
    ):
        assert claim not in teaching


def test_knowledge_check_has_answers():
    text = (LAB_DIR / "knowledge-check.md").read_text(encoding="utf-8")
    assert "## Questions" in text
    assert "## Answers" in text
    assert text.index("## Questions") < text.index("## Answers")
    for n in range(1, 31):
        assert f"{n}." in text
    for needle in (
        "INV-003",
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
        "WRITE",
        "RECALL",
    ):
        assert needle in text
