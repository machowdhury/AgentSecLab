"""Workshop logic contracts for LAB-MCP-CATALOG.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

REQUIRED_IDS = (
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-CATALOG-AUTHORITY",
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
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-CATALOG"
REQUIRED_FILES = (
    LAB_DIR / "README.md",
    LAB_DIR / "workshop.md",
    LAB_DIR / "evidence.md",
    LAB_DIR / "knowledge-check.md",
    LAB_DIR / "dashboard.md",
)
MALICIOUS_HASH = "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"


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
    assert (LAB_DIR / "searches" / "Q-MCP-CATALOG-AUTHORITY.spl").is_file()
    assert not (LAB_DIR / "searches" / "DET-MCP-CATALOG.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-MCP-CATALOG-METADATA.spl").exists()


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
    assert "DETECTION GAP" in detect
    assert "Q-MCP-AFTER-DENY" in detect
    assert "DET-MCP-001-POSITIVE-CONTROL" in detect
    assert "SIMULATED" in detect
    assert "DET-MCP-CATALOG" in detect
    observe = workshop.split("## OBSERVE", 1)[1].split("## HUNT", 1)[0]
    assert "sequence" in observe.lower()
    assert "Q-MCP-CATALOG-AUTHORITY" in observe
    hunt = workshop.split("## HUNT", 1)[1].split("## DETECT", 1)[0]
    assert "Q-MCP-EXECUTED" in hunt
    assert "metadata executed" not in hunt.lower() or "Do not teach" in hunt


def test_validated_run_ids_and_lessons():
    blob = _lab_text()
    assert "d95717ed-ffd2-46c0-a130-9a5d7d539a5d" in blob
    assert "a0937bff-31a5-453a-99bf-47d7b5148ce4" in blob
    assert "23c222ea-6a87-40b7-a3e9-f12a5b572fa1" in blob
    assert "lookup_policy" in blob
    assert "lookup_customer_tier" in blob
    assert "ws_lab_mcp_catalog" in blob
    assert "INV-002" in blob
    assert "CTRL-MCP-METADATA-001" in blob
    assert "CTRL-MCP-001" in blob
    assert "metadata_is_data" in blob
    assert "vulnerable_profile_fail_open:metadata_derived_authority" in blob
    assert "tool_not_granted" in blob
    assert MALICIOUS_HASH in blob
    lowered = blob.lower()
    assert "handler count" in lowered
    assert "runtime handler count is authoritative" in lowered
    assert "no det-mcp-catalog" in lowered
    assert "q-mcp-catalog-metadata" in lowered
    assert "not published" in lowered
    assert "request ≠ grant" in lowered or "REQUEST ≠ GRANT" in blob
    assert "observe ≠ allow" in lowered or "OBSERVE ≠ ALLOW" in blob
    forbidden = (
        "splunk blocked the action",
        "splunk prevented the attack",
        "the detector caught mcp-catalog",
        "allow proves execution",
        "empty splunk table proves prevention",
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
        "METADATA",
        "ALLOW",
        "DENY",
        "DET-MCP-001",
        "handler",
        "CTRL-MCP-METADATA-001",
        "CTRL-MCP-001",
        "scanner",
        MALICIOUS_HASH,
    ):
        assert needle in checks


def test_evidence_hierarchy():
    evidence = (LAB_DIR / "evidence.md").read_text(encoding="utf-8")
    for layer in ("Runtime", "Local", "Export", "Splunk", "Search", "Detection"):
        assert layer in evidence
    assert "handler" in evidence.lower()
    assert "splunk.verified" in evidence
    assert "DET-MCP-001" in evidence
    assert "Q-MCP-CATALOG-AUTHORITY" in evidence
    assert "DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN" in evidence
    assert "no indexed follow-on mcp execution event" in evidence.lower()


def test_simulated_not_observed_runtime():
    detect = (
        (LAB_DIR / "workshop.md")
        .read_text(encoding="utf-8")
        .split("## DETECT", 1)[1]
        .split("## DEFEND", 1)[0]
    )
    assert "**SIMULATED**" in detect
    assert "makeresults" in detect
    assert "not OBSERVED" in detect or "Not OBSERVED" in detect
    assert "NOT INDEXED" in detect
    assert "DETECTION ANALYZED" in detect or "DETECTION GAP" in detect
