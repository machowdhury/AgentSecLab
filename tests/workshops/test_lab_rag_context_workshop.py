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
