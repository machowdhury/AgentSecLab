"""Phase 10B must not rewrite prior SPL, detectors, or Studio."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"


def test_no_det_rag_and_det_mcp_001_unchanged():
    assert DET.is_file()
    text = DET.read_text(encoding="utf-8")
    assert "sequence>deny_sequence" in text
    assert "CTRL-RAG" not in text
    assert "RAG-001" not in text
    assert list((ROOT / "learning").rglob("DET-RAG*")) == []
    assert "rag.context" not in DET.read_text(encoding="utf-8")


def test_q_mcp_and_q_scanner_not_rewritten_for_rag():
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0")
    assert "rag.context" not in authz
    scanner = ROOT / "learning" / "level_1" / "LAB-SCANNER-RUNTIME-EVIDENCE"
    if scanner.is_dir():
        for path in scanner.rglob("*.spl"):
            assert "rag.context" not in path.read_text(encoding="utf-8")


def test_no_rag_studio_from_phase_10b():
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    if views.is_dir():
        assert {path.name for path in views.glob("*rag*")} <= {"ws_lab_rag_context.xml"}


def test_schema_16_has_rag_and_not_trusted_document():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.6.0"' in schema
    assert "rag_context_trust" in schema
    assert "trusted_document" not in schema
    assert "rag_allowed_tools" not in schema
