"""Phase 11D is detection analysis only: no new detector, Studio, or runtime change."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
HUNT = ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "searches" / "Q-MEMORY-CONTEXT-AUTHORITY.spl"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DOCS = ROOT / "docs"


def test_phase11d_no_new_detector_or_studio():
    assert not list((ROOT / "learning").rglob("DET-MEMORY*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-MEMORY*"))
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    memory_views = {path.name for path in views.glob("*memory*")} if views.is_dir() else set()
    assert memory_views <= {"ws_lab_memory_security.xml"}
    saved = (ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf").read_text(
        encoding="utf-8"
    )
    assert "DET-MEMORY" not in saved
    assert "Q-MEMORY" not in saved


def test_phase11d_runtime_schema_and_existing_spl_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "sequence>deny_sequence" in det
    assert "CTRL-MEMORY" not in det
    assert "MEMORY-001" not in det
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
    )
    hunt = HUNT.read_text(encoding="utf-8")
    assert 'hop="1"' in hunt
    assert "CTRL-MEMORY-CONTEXT-001" in hunt
    assert "__WRITE_RUN_ID__" in hunt
    assert "__RECALL_RUN_ID__" in hunt
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")


