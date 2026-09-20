"""Phase 14A is design/research/contract only.

Does not implement Attack Simulator, Studio, SPL, detectors, or schema.
Does not prove launch, HEC, Splunk rendering, or detection effectiveness.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
ATTACK_APP = ROOT / "src" / "agentsec" / "attack_app.py"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
NOTE = DOCS / "learning-notes" / "attack-investigate-prove.md"

PHASE14A_DOCS = (
    DOCS / "AGENTSEC_LEARNING_EXPERIENCE_ARCHITECTURE.md",
    DOCS / "AGENTSEC_ATTACK_SIMULATOR_ARCHITECTURE.md",
    DOCS / "AGENTSEC_GUIDED_INVESTIGATION_STANDARD.md",
    DOCS / "AGENTSEC_LAB_EXECUTION_MODES.md",
    DOCS / "AGENTSEC_ATTACK_LAUNCH_CONTRACT.md",
    DOCS / "AGENTSEC_SPLUNK_LEARNING_INTERACTION_MATRIX.md",
    DOCS / "AGENTSEC_CROSS_WORKSHOP_READINESS_MATRIX.md",
    DOCS / "PHASE14A_LEARNING_EXPERIENCE_DESIGN.md",
    NOTE,
)


def test_phase14a_design_docs_exist():
    for path in PHASE14A_DOCS:
        assert path.is_file(), path


def test_phase14a_is_design_only_and_forbids_14b():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in PHASE14A_DOCS)
    for needle in (
        "DESIGN",
        "Not implemented",
        "Do not start Phase 14B",
        "Splunk is not enforcement",
        "Studio is not an authorization engine",
        "allowlisted",
        "WAITING_FOR_EVIDENCE",
        "HEC HTTP 200",
        "LIVE",
        "REPLAY",
        "GUIDED",
        "BEGINNER",
        "INTERMEDIATE",
        "ADVANCED",
        "CHALLENGE",
        "Path A",
        "Path B",
        "OPEN SPLUNK SEARCH",
        "WHAT IT DOES NOT PROVE",
        "CONNECT",
        "LAB-PI-001",
        "DETECTION ANALYZED — NO NEW DETECTOR",
        "NOT SUPPORTED / DO NOT BUILD",
        "REQUIRES CUSTOM APP/JS",
        "INTENTIONALLY VULNERABLE",
        "FUTURE PRODUCTION",
        "no GFM",
    ):
        assert needle in blob, needle
    phase = (DOCS / "PHASE14A_LEARNING_EXPERIENCE_DESIGN.md").read_text(encoding="utf-8")
    assert "Choose LAB-PI-001" in phase
    assert "MCP-001 is the **designated second**" in phase
    assert "No Studio implementation in 14A" in phase
    assert "1.9.0" in phase
    matrix = (DOCS / "AGENTSEC_CROSS_WORKSHOP_READINESS_MATRIX.md").read_text(
        encoding="utf-8"
    )
    assert "LIVE READY" in matrix
    assert "No published workshop is **LIVE READY**" in matrix
    assert "GUIDED READY" in matrix
    assert "ws_lab_identity" not in matrix.lower() or "no Studio view" in matrix
    notes = NOTE.read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in notes


def test_phase14a_did_not_implement_simulator_studio_spl_or_schema():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "sequence>deny_sequence" in det
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-GOAL" not in saved
    assert "DET-PI-002" not in saved
    attack = ATTACK_APP.read_text(encoding="utf-8")
    assert "ATK-002" in attack
    assert "/api/attacks/ATK-002" in attack
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")
    names = {path.name for path in VIEWS.glob("ws_*.xml")}
    assert "ws_agentsec_home.xml" in names
    assert "ws_lab_pi_001.xml" in names
    assert "ws_attack_simulator.xml" not in names
    assert "ws_guided_investigation.xml" not in names
    assert not list((ROOT / "learning").rglob("DET-GOAL*"))
    assert not list((ROOT / "learning").rglob("Q-ATTACK-SIM*"))


def test_phase14a_status_and_roadmap_do_not_start_14b():
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "14A" in status
    assert "DESIGN" in status
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    assert "Do not start Phase 14B" in roadmap
    assert "Phase 14A" in roadmap
    learning = (DOCS / "AGENTSEC_LEARNING_ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "LEARN → BASELINE → ATTACK" in learning
    ui = (DOCS / "AGENTSEC_UI_DESIGN_SYSTEM.md").read_text(encoding="utf-8")
    assert "14A" in ui or "Phase 14A" in ui
    workshop = (DOCS / "AGENTSEC_WORKSHOP_UI_STANDARD.md").read_text(encoding="utf-8")
    assert "CONNECT" in workshop
    assert "Not implemented" in workshop or "DESIGN" in workshop
