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


