"""Phase 11B must not rewrite prior SPL, detectors, or Studio."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"


def test_no_det_memory_and_det_mcp_001_unchanged():
    assert DET.is_file()
    text = DET.read_text(encoding="utf-8")
    assert "sequence>deny_sequence" in text
    assert "CTRL-MEMORY" not in text
    assert "MEMORY-001" not in text
    assert list((ROOT / "learning").rglob("DET-MEMORY*")) == []
    assert "memory.trust" not in text


def test_q_mcp_not_rewritten_for_memory():
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0")
    assert "agentsec.memory" not in authz
    rag = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT"
    if rag.is_dir():
        for path in rag.rglob("*.spl"):
            assert "agentsec.memory" not in path.read_text(encoding="utf-8")


def test_no_memory_studio_from_phase_11b():
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    if views.is_dir():
        assert {path.name for path in views.glob("*memory*")} <= {"ws_lab_memory_security.xml"}


def test_schema_17_has_memory_and_keeps_rag():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "memory_context_trust" in schema
    assert "CTRL-MEMORY-CONTEXT-001" in schema
    assert "MEMORY-001" in schema
    assert "agent.memory.store" in schema
    assert "rag_context_trust" in schema
    assert "trusted_memory" not in schema
    assert "memory_allowed_tools" not in schema
    assert '"agentsec.session.id"' not in schema
