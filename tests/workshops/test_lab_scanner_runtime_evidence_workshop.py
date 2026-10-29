"""Workshop logic contracts for LAB-SCANNER-RUNTIME-EVIDENCE.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-SCANNER-RUNTIME-EVIDENCE"
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
MALICIOUS_HASH = "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"
NORMAL_HASH = "sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3"
ATTACK_ID = "a0937bff-31a5-453a-99bf-47d7b5148ce4"
RETEST_ID = "23c222ea-6a87-40b7-a3e9-f12a5b572fa1"
NORMAL_SCAN = "b3061c4e-7a81-445c-8fd8-3108dd14c419"
MALICIOUS_SCAN = "7ae3ea64-4e7a-40fe-943f-3e582bce5ee8"


def _lab_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in REQUIRED_FILES if path.suffix == ".md")


def _docs_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            DOCS / "PHASE9E_SCANNER_RUNTIME_WORKSHOP.md",
            DOCS / "learning-notes" / "scanner-runtime-soc-investigation.md",
        )
    )








def test_knowledge_check_has_answers():
    text = (LAB_DIR / "knowledge-check.md").read_text(encoding="utf-8")
    assert "description_sha256" in text or "description SHA-256" in text
    assert "artifact.sha256" in text
    assert "DET-MCP-001" in text
    assert "INV-002" in text
    assert "## Answers" in text
    for n in range(1, 16):
        assert f"{n}." in text
