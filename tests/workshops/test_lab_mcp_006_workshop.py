"""Workshop logic contracts for LAB-MCP-006.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

REQUIRED_IDS = (
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-DELEGATION",
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
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-006"
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
    assert (LAB_DIR / "searches" / "Q-MCP-DELEGATION.spl").is_file()
    assert not (LAB_DIR / "searches" / "DET-MCP-006.spl").exists()
    assert not (LAB_DIR / "searches" / "Q-MCP-AMBIENT-USE.spl").exists()


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
    assert "DET-MCP-006" in detect
    observe = workshop.split("## OBSERVE", 1)[1].split("## HUNT", 1)[0]
    assert "sequence" in observe.lower()
    assert "Q-MCP-DELEGATION" in observe


def test_validated_run_ids_and_lessons():
    blob = _lab_text()
    assert "1cf98c4d-1bd8-4df5-be70-b82419e2c2b2" in blob
    assert "d7524a4e-8da6-4171-8867-d2a2168128ac" in blob
    assert "50f7ec04-7524-41c0-95a8-3b1ef4d91dc4" in blob
    assert "lookup_policy" in blob
    assert "lookup_customer_tier" in blob
    assert "acme-agent-credit-002" in blob
    assert "acme-agent-compliance-004" in blob
    assert "ws_lab_mcp_006" in blob
    assert "INV-001" in blob
    assert "CTRL-DELEGATION-001" in blob
    assert "CTRL-MCP-001" in blob
    assert "ambient_deputy" in blob
    assert "delegated_authority_not_granted" in blob
    assert "vulnerable_profile_fail_open:ambient_deputy_authority" in blob
    assert "sha256:ea33191fceeb105e47270f6839bb98addfb7245a32534138192b23e1fab9a419" in blob
    lowered = blob.lower()
    assert "handler count" in lowered
    assert "runtime handler count is authoritative" in lowered
    assert "deputy authority" in lowered
    assert "no det-mcp-006" in lowered
    assert "q-mcp-ambient-use" in lowered
    assert "not published" in lowered
    assert "deputy_not_on_indexed_hop1" in blob
    forbidden = (
        "splunk blocked the action",
        "splunk prevented the attack",
        "the detector caught mcp-006",
        "allow proves execution",
        "the caller was granted lookup_customer_tier",
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
        "INV-001",
        "caller",
        "deputy",
        "ambient",
        "delegated",
        "ALLOW",
        "DENY",
        "DET-MCP-001",
        "handler",
        "CTRL-DELEGATION-001",
        "CTRL-MCP-001",
        "gen_ai.tool.call.id",
    ):
        assert needle in checks


def test_evidence_hierarchy():
    evidence = (LAB_DIR / "evidence.md").read_text(encoding="utf-8")
    for layer in ("Runtime", "Local", "Export", "Splunk", "Search", "Detection"):
        assert layer in evidence
    assert "handler" in evidence.lower()
    assert "splunk.verified" in evidence
    assert "DET-MCP-001" in evidence
    assert "Q-MCP-DELEGATION" in evidence
    assert "NO NEW DETECTOR" in evidence
    assert "no indexed mcp execution event" in evidence.lower()


def test_simulated_not_observed_runtime():
    detect = (LAB_DIR / "workshop.md").read_text(encoding="utf-8").split("## DETECT", 1)[1].split("## DEFEND", 1)[0]
    assert "**SIMULATED**" in detect
    assert "makeresults" in detect
    assert "not OBSERVED" in detect or "Not OBSERVED" in detect
    assert "NOT INDEXED" in detect
