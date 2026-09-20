"""Phase 13D is detection analysis + workshop design only."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
HUNT = (
    ROOT
    / "learning"
    / "level_1"
    / "LAB-AGENT-GOAL-INTEGRITY-001"
    / "searches"
    / "Q-GOAL-INTEGRITY-AUTHORITY.spl"
)
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DOCS = ROOT / "docs"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
LAB = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001"


def test_phase13d_no_new_detector_or_studio():
    assert not list((ROOT / "learning").rglob("DET-GOAL*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-GOAL*"))
    if VIEWS.is_dir():
        names = {path.name for path in VIEWS.glob("*goal*")}
        assert names <= {"ws_lab_agent_goal_integrity.xml"}
        assert "ws_lab_goal.xml" not in names
    saved = (ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf").read_text(
        encoding="utf-8"
    )
    assert "DET-GOAL" not in saved
    assert "Q-GOAL" not in saved
    extra = ("Q-GOAL-TASK", "Q-GOAL-INSTRUCTION", "Q-GOAL-EXECUTED", "Q-GOAL-DENY")
    for name in extra:
        assert not list(LAB.rglob(f"{name}.*"))


def test_phase13d_runtime_schema_and_existing_spl_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "sequence>deny_sequence" in det
    assert "CTRL-GOAL" not in det
    assert "GOAL-001" not in det
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
    )
    hunt = HUNT.read_text(encoding="utf-8")
    assert "CTRL-GOAL-INTEGRITY-001" in hunt
    assert "CTRL-MCP-001" in hunt
    assert "__RUN_ID__" in hunt
    assert "| join " not in hunt
    assert "| rex " not in hunt
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")


def test_phase13d_docs_choose_no_new_detector_and_design_workshop():
    required = (
        DOCS / "PHASE13D_GOAL_INTEGRITY_DETECTION_ANALYSIS.md",
        DOCS / "GOAL_INTEGRITY_SOC_EVIDENCE_PLANES.md",
        DOCS / "GOAL_INTEGRITY_WORKSHOP_DESIGN.md",
        DOCS / "learning-notes" / "goal-integrity-detection-engineering.md",
        DOCS / "reviews" / "splunk-ko-review-goal-integrity-phase13d-2026-09-18.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE13D_GOAL_INTEGRITY_DETECTION_ANALYSIS.md").read_text(
        encoding="utf-8"
    )
    for needle in (
        "DETECTION ANALYZED — NO NEW DETECTOR",
        "DESIGNED — NOT IMPLEMENTED",
        "Phase 13E not started",
        "0 rows is CORRECT BEHAVIOR",
        "DET-MCP-001 silence != SAFE",
        "MCP ALLOW DOES NOT MEAN",
        "No INV-009",
        "sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c",
        "0aced342-1295-4820-b807-9a8718d9e847",
        "fd994587-7e1c-4a70-8013-54cb2c85254d",
        "605ba7c1-449b-4338-92df-7da3b704b08e",
        "Q-GOAL-INTEGRITY-AUTHORITY",
        "REUSE",
        "CIM NOT APPLICABLE",
        "UNMAPPED / REQUIRES REVALIDATION",
        "ANOMALY != INCIDENT",
        "No rug-pull",
        "No A2A",
        "INTENTIONALLY VULNERABLE LAB PROFILE",
    ):
        assert needle in phase, needle
    assert "DETECTION CANDIDATE JUSTIFIED FOR PHASE 13E IMPLEMENTATION" not in phase
    planes = (DOCS / "GOAL_INTEGRITY_SOC_EVIDENCE_PLANES.md").read_text(encoding="utf-8")
    assert "Plane 1" in planes
    assert "Plane 5" in planes
    assert "TOOL AUTHORIZATION != TASK AUTHORIZATION" in planes
    assert "AUTHORIZED TOOL != AUTHORIZED USE OF TOOL" in planes
    workshop = (DOCS / "GOAL_INTEGRITY_WORKSHOP_DESIGN.md").read_text(encoding="utf-8")
    for needle in (
        "ws_lab_agent_goal_integrity",
        "AUTHORIZED TOOL != AUTHORIZED GOAL",
        "OBSERVE != ALLOW",
        "SPLUNK != ENFORCEMENT",
        "INTENTIONALLY VULNERABLE LAB PROFILE",
        "DETECTION ANALYZED — NO NEW GOAL DETECTOR",
        "DEFENSE DOES NOT MEAN",
        "Do not say MCP blocked",
        "INV-006",
    ):
        assert needle in workshop, needle
    notes = (DOCS / "learning-notes" / "goal-integrity-detection-engineering.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "13D" in status
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in status
    assert "13E NOT STARTED" in status or "Phase 13E" in status
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    assert "Do not start Phase 13E" in roadmap
    assert "No rug-pull" in roadmap
    assert "No A2A" in roadmap
