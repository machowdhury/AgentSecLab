"""Workshop logic contracts for LAB-MCP-001.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

REQUIRED_IDS = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-SCOPE",
    "Q-MCP-PARAMS",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-RESULT",
    "Q-MCP-RESULT-TRUST",
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
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001"
REQUIRED_FILES = (
    LAB_DIR / "README.md",
    LAB_DIR / "workshop.md",
    LAB_DIR / "evidence.md",
    LAB_DIR / "knowledge-check.md",
    LAB_DIR / "dashboard.md",
)


def _lab_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in REQUIRED_FILES)


def test_workshop_files_exist():
    for path in REQUIRED_FILES:
        assert path.is_file(), path
    assert (LAB_DIR / "searches" / "catalog.json").is_file()
    assert (LAB_DIR / "dashboard.definition.json").is_file()


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
    assert "HUNT" in detect
    assert "DETECTION" in detect
    assert "Q-MCP-AFTER-DENY" in detect
    assert "Q-MCP-AFTER-DENY-POSITIVE-CONTROL" in detect
    assert "DET-MCP-001-POSITIVE-CONTROL" in detect
    assert "SIMULATED" in detect
    observe = workshop.split("## OBSERVE", 1)[1].split("## HUNT", 1)[0]
    assert "sequence" in observe.lower()


def test_validated_run_ids_and_lessons():
    blob = _lab_text()
    assert "163d11e2-e751-4282-9406-19b490542ed4" in blob
    assert "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49" in blob
    assert "7a1d37b5-d589-4dfd-8322-25ebd0152dbc" in blob
    assert "lookup_customer_tier" in blob
    assert "unauthorized invocation" in blob.lower()
    assert "ws_lab_mcp_001" in blob
    lowered = blob.lower()
    assert "allow is not execution" in lowered or "allow ≠ execution" in lowered
    assert "handler count" in lowered
    assert "untrusted_data" in blob
    assert "runtime handler count is authoritative" in lowered


def test_knowledge_check_separates_answers():
    checks = (LAB_DIR / "knowledge-check.md").read_text(encoding="utf-8")
    assert "## Questions" in checks
    assert "## Answers" in checks
    assert checks.index("## Questions") < checks.index("## Answers")
    for needle in (
        "lookup_customer_tier",
        "ERROR",
        "ALLOW",
        "mcp.started",
        "mcp.failed",
        "untrusted_data",
        "zero Splunk",
    ):
        assert needle in checks


def test_evidence_hierarchy():
    evidence = (LAB_DIR / "evidence.md").read_text(encoding="utf-8")
    for layer in ("Runtime", "Local", "OTLP", "Splunk", "SPL"):
        assert layer in evidence
    assert "handler" in evidence.lower()
    assert "splunk.verified" in evidence


def test_simulated_not_observed_runtime():
    detect = (LAB_DIR / "workshop.md").read_text(encoding="utf-8").split("## DETECT", 1)[1].split("## DEFEND", 1)[0]
    assert "**SIMULATED**" in detect
    assert "makeresults" in detect
    assert "not OBSERVED" in detect or "Not OBSERVED" in detect
