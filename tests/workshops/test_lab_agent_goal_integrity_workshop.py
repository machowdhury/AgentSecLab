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
