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


