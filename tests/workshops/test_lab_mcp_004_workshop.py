"""Workshop logic contracts for LAB-MCP-004.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

REQUIRED_IDS = (
    "Q-MCP-AUTHZ",
    "Q-MCP-SCOPE",
    "Q-MCP-RESOURCE-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
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
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-004"
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
    assert (LAB_DIR / "dashboard.definition.json").is_file()
    assert (LAB_DIR / "searches" / "Q-MCP-RESOURCE-AUTHZ.spl").is_file()
    assert not (LAB_DIR / "searches" / "DET-MCP-004.spl").exists()


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
    assert "DET-MCP-001-RESOURCE-POSITIVE-CONTROL" in detect
    assert "SIMULATED" in detect
    assert "DET-MCP-004" in detect
    observe = workshop.split("## OBSERVE", 1)[1].split("## HUNT", 1)[0]
    assert "sequence" in observe.lower()
    assert "resource.id" in observe


def test_validated_run_ids_and_lessons():
    blob = _lab_text()
    assert "fb50dcaf-8e84-4a3f-a55b-997c72edbd04" in blob
    assert "5ab59fc7-303e-4eea-84e7-ae0b2f405146" in blob
    assert "0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd" in blob
    assert "0e4e0051-528d-4bf3-8773-d1fb55a5864f" in blob
    assert "lookup_policy" in blob
    assert "lending-basics" in blob
    assert "executive-restricted" in blob
    assert "does-not-exist" in blob
    assert "ws_lab_mcp_004" in blob
    lowered = blob.lower()
    assert "allow is not execution" in lowered or "allow ≠ execution" in lowered
    assert "handler count" in lowered
    assert "runtime handler count is authoritative" in lowered
    assert "may the agent call this tool" in lowered
    assert "this resource" in lowered
    assert "allowticket" in lowered
    assert not (LAB_DIR / "searches" / "Q-MCP-004.spl").exists()


def test_knowledge_check_separates_answers():
    checks = (LAB_DIR / "knowledge-check.md").read_text(encoding="utf-8")
    assert "## Questions" in checks
    assert "## Answers" in checks
    assert checks.index("## Questions") < checks.index("## Answers")
    for needle in (
        "executive-restricted",
        "does-not-exist",
        "ERROR",
        "ALLOW",
        "mcp.started",
        "allowed_resource.ids",
        "DET-MCP-001",
        "handler",
        "AllowTicket",
        "malformed",
    ):
        assert needle in checks


def test_evidence_hierarchy():
    evidence = (LAB_DIR / "evidence.md").read_text(encoding="utf-8")
    for layer in ("Runtime", "Local", "Export", "Splunk", "Search", "Detection"):
        assert layer in evidence
    assert "handler" in evidence.lower()
    assert "splunk.verified" in evidence
    assert "DET-MCP-001" in evidence
    assert "Q-MCP-RESOURCE-AUTHZ" in evidence
    assert "duplicate_json_keys" in evidence


def test_simulated_not_observed_runtime():
    detect = (LAB_DIR / "workshop.md").read_text(encoding="utf-8").split("## DETECT", 1)[1].split("## DEFEND", 1)[0]
    assert "**SIMULATED**" in detect
    assert "makeresults" in detect
    assert "not OBSERVED" in detect or "Not OBSERVED" in detect
