"""Workshop logic contracts for LAB-AGENT-GOAL-INTEGRITY-001.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001"
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
TASK_HASH = "sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c"
INSTRUCTION_HASH = "sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2"
BASELINE = "0aced342-1295-4820-b807-9a8718d9e847"
ATTACK = "fd994587-7e1c-4a70-8013-54cb2c85254d"
RETEST = "605ba7c1-449b-4338-92df-7da3b704b08e"


def _lab_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in REQUIRED_FILES if path.suffix == ".md")


def _docs_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            DOCS / "PHASE13E_GOAL_INTEGRITY_WORKSHOP.md",
            DOCS / "learning-notes" / "goal-integrity-soc-investigation.md",
        )
    )


def test_required_workshop_files_exist():
    for path in REQUIRED_FILES:
        assert path.is_file(), path
    assert (LAB_DIR / "dashboard.md").is_file()
    assert (DOCS / "PHASE13E_GOAL_INTEGRITY_WORKSHOP.md").is_file()
    assert (DOCS / "learning-notes" / "goal-integrity-soc-investigation.md").is_file()
    notes = (DOCS / "learning-notes" / "goal-integrity-soc-investigation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    assert not (LAB_DIR / "searches" / "DET-GOAL.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-GOAL-TASK.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-GOAL-INSTRUCTION.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-GOAL-EXECUTED.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-GOAL-DENY.spl").exists()


def test_ten_steps_and_evidence_ids():
    blob = _lab_text() + _docs_text()
    for step in WORKSHOP_STEPS:
        assert step in blob
    assert "ws_lab_agent_goal_integrity" in blob
    assert TASK_HASH in blob
    assert INSTRUCTION_HASH in blob
    assert BASELINE in blob
    assert ATTACK in blob
    assert RETEST in blob
    assert blob.count(TASK_HASH) >= 3


def test_teaching_boundaries():
    blob = _lab_text() + _docs_text()
    assert "AUTHORIZED TOOL != AUTHORIZED GOAL" in blob
    assert "AUTHORIZED TOOL != AUTHORIZED USE OF TOOL" in blob
    assert "REQUEST != GRANT" in blob or "REQUEST ≠ GRANT" in blob
    assert "OBSERVE != ALLOW" in blob or "OBSERVE ≠ ALLOW" in blob
    assert "ALLOW != EXECUTION" in blob or "ALLOW ≠ EXECUTION" in blob
    assert "SPLUNK != ENFORCEMENT" in blob or "SPLUNK ≠ ENFORCEMENT" in blob
    assert "DETECTION ANALYZED — NO NEW GOAL DETECTOR" in blob or "NO NEW DETECTOR" in blob
    assert "INTENTIONALLY VULNERABLE" in blob
    assert "handler" in blob.lower()
    assert "INV-002" in blob
    assert "INV-006" in blob
    assert "1.9.0" in blob
    assert "No DET-GOAL" in blob or "no DET-GOAL" in blob
    assert "Q-GOAL-INTEGRITY-AUTHORITY" in blob
    assert "FUTURE — NOT IMPLEMENTED" in blob
    assert "Do not say MCP blocked the attack" in blob
    lowered = blob.lower()
    assert "the instruction authorized the tool" not in lowered
    assert "phase 14" in lowered
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
        "the detector caught goal",
        "baseline is safe",
        "untrusted_instruction means malicious",
        "mcp blocked retest",
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
        "INV-006",
        "OBSERVE",
        "ALLOW",
        "DENY",
        "DET-MCP-001",
        "handler",
        "hash",
        "lookup_policy",
        "extract_full_policy",
        "summarize_lending_policy",
        "ML",
        "untrusted_instruction",
        "CTRL-GOAL-INTEGRITY-001",
        "CTRL-MCP-001",
    ):
        assert needle in text
