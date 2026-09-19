"""Phase 9B must not add SPL, Studio, detectors, schema fields, or rug-pull."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"


def test_phase9b_docs_exist():
    docs = ROOT / "docs"
    for path in (
        docs / "CISCO_MCP_SCANNER_INTEGRATION.md",
        docs / "SCANNER_EVIDENCE_RUNTIME_CONTRACT.md",
        docs / "PHASE9B_CISCO_MCP_SCANNER_VALIDATION.md",
        docs / "learning-notes" / "scanner-vs-runtime-evidence.md",
    ):
        assert path.is_file(), path
    assert "SCANNER FINDING != AUTHORIZATION DECISION" in (
        docs / "CISCO_MCP_SCANNER_INTEGRATION.md"
    ).read_text(encoding="utf-8")

    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "agentsec.scanner" not in schema
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
    )
    det = DET.read_text(encoding="utf-8")
    assert "scanner" not in det.lower()
    protocol = PROTOCOL.read_text(encoding="utf-8")
    assert "list_changed" not in protocol
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    scanner_views = {path.name for path in views.glob("*scanner*")}
    assert scanner_views <= {"ws_lab_scanner_runtime_evidence.xml"}
    assert not list((ROOT / "learning").rglob("DET-SCANNER*"))
