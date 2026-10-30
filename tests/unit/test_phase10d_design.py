"""Phase 10D is detection analysis only: no new detector, Studio, or runtime change."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
HUNT = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "searches" / "Q-RAG-CONTEXT-AUTHORITY.spl"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DOCS = ROOT / "docs"


def test_phase10d_no_new_detector_or_studio():
    assert not list((ROOT / "learning").rglob("DET-RAG*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-RAG*"))
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    rag_views = {path.name for path in views.glob("*rag*")} if views.is_dir() else set()
    assert rag_views <= {"ws_lab_rag_context.xml"}
    saved = (ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf").read_text(
        encoding="utf-8"
    )
    assert "DET-RAG" not in saved
    assert "Q-RAG" not in saved


def test_phase10d_runtime_schema_and_existing_spl_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "sequence>deny_sequence" in det
    assert "CTRL-RAG" not in det
    assert "RAG-001" not in det
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
    )
    hunt = HUNT.read_text(encoding="utf-8")
    assert 'hop="1"' in hunt
    assert "CTRL-RAG-CONTEXT-001" in hunt
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")


