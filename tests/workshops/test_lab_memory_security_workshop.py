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
