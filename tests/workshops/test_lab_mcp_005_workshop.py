"""Workshop logic contracts for LAB-MCP-005.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

REQUIRED_IDS = (
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-RESULT-AUTHORITY",
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

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-005"
REQUIRED_FILES = (
    LAB_DIR / "README.md",
    LAB_DIR / "workshop.md",
    LAB_DIR / "evidence.md",
    LAB_DIR / "knowledge-check.md",
    LAB_DIR / "dashboard.md",
)


def _lab_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in REQUIRED_FILES)


def _teaching_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            LAB_DIR / "README.md",
            LAB_DIR / "workshop.md",
            LAB_DIR / "evidence.md",
            LAB_DIR / "dashboard.md",
        )
    )


def test_workshop_files_exist():
    for path in REQUIRED_FILES:
        assert path.is_file(), path
    assert (LAB_DIR / "dashboard.definition.json").is_file()
    assert (LAB_DIR / "searches" / "Q-MCP-RESULT-AUTHORITY.spl").is_file()
    assert not (LAB_DIR / "searches" / "DET-MCP-005.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-MCP-RESULT-FOLLOWON.spl").exists()


def test_workshop_flow_headings_in_order():
    text = (LAB_DIR / "workshop.md").read_text(encoding="utf-8")
    positions = [text.index(f"## {step}") for step in WORKSHOP_STEPS]
    assert positions == sorted(positions)


def test_validated_searches_named_per_step():
    workshop = (LAB_DIR / "workshop.md").read_text(encoding="utf-8")
    for query_id in REQUIRED_IDS:
        assert query_id in workshop
    detect = workshop.split("## DETECT", 1)[1].split("## DEFEND", 1)[0]
    assert "DET-MCP-001" in detect
    assert "NO NEW DETECTOR" in detect
    assert "Q-MCP-AFTER-DENY" in detect
    assert "DET-MCP-001-POSITIVE-CONTROL" in detect
    assert "SIMULATED" in detect
    assert "DET-MCP-005" in detect
    observe = workshop.split("## OBSERVE", 1)[1].split("## HUNT", 1)[0]
    assert "sequence" in observe.lower()
    assert "Q-MCP-RESULT-AUTHORITY" in observe


def test_validated_run_ids_and_lessons():
    blob = _lab_text()
    assert "3013aa39-fe08-4b58-9898-f3abb092ac06" in blob
    assert "f3f48182-df57-4b38-b069-17a199dc4939" in blob
    assert "0ab10594-a7fc-48b6-81bf-4cbca54a64c6" in blob
    assert "lookup_policy" in blob
    assert "lookup_customer_tier" in blob
    assert "lending-basics" in blob
    assert "ws_lab_mcp_005" in blob
    assert "INV-002" in blob
    lowered = blob.lower()
    assert "handler count" in lowered
    assert "runtime handler count is authoritative" in lowered
    assert "data cannot grant authority" in lowered or "data ≠ authority" in lowered
    assert "no det-mcp-005" in lowered
    assert "q-mcp-result-followon" in lowered
    assert "not published" in lowered
    assert "bounded" in lowered
    assert "lookup_customer_tie" in blob
    assert "sha256:f7d67b151741ef7c7efb60242b96f8325996709128293da424f53a547230c358" in blob
    assert not (LAB_DIR / "searches" / "Q-MCP-004.spl").exists()
    forbidden = (
        "splunk blocked the action",
        "splunk prevented the attack",
        "the detector caught mcp-005",
        "the hash proves the result is safe",
        "allow proves execution",
        "the server granted lookup_customer_tier",
        "the ai ignored the malicious instruction",
    )
    teaching = _teaching_text().lower()
    for claim in forbidden:
        assert claim not in teaching


def test_knowledge_check_separates_answers():
    checks = (LAB_DIR / "knowledge-check.md").read_text(encoding="utf-8")
    assert "## Questions" in checks
    assert "## Answers" in checks
    assert checks.index("## Questions") < checks.index("## Answers")
    for needle in (
        "INV-002",
        "provenance",
        "ALLOW",
        "DENY",
        "DET-MCP-001",
        "handler",
        "hash",
        "prompt-injection",
        "gen_ai.tool.call.id",
        "tool_not_granted",
    ):
        assert needle in checks


def test_evidence_hierarchy():
    evidence = (LAB_DIR / "evidence.md").read_text(encoding="utf-8")
    for layer in ("Runtime", "Local", "Export", "Splunk", "Search", "Detection"):
        assert layer in evidence
    assert "handler" in evidence.lower()
    assert "splunk.verified" in evidence
    assert "DET-MCP-001" in evidence
    assert "Q-MCP-RESULT-AUTHORITY" in evidence
    assert "NO NEW DETECTOR" in evidence
    assert "no indexed follow-on execution event" in evidence.lower()


def test_simulated_not_observed_runtime():
    detect = (LAB_DIR / "workshop.md").read_text(encoding="utf-8").split("## DETECT", 1)[1].split("## DEFEND", 1)[0]
    assert "**SIMULATED**" in detect
    assert "makeresults" in detect
    assert "not OBSERVED" in detect or "Not OBSERVED" in detect
    assert "NOT INDEXED" in detect
