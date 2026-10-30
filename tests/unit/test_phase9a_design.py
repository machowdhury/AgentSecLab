"""Phase 9A design documents exist and remain research-only.

Does not execute scanners, SPL, or runtime. Does not prove integrations.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
NOTE = DOCS / "learning-notes" / "external-agent-security-tools-101.md"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
METADATA = ROOT / "src" / "agentsec" / "mcp" / "metadata_trust.py"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
STATUS = DOCS / "IMPLEMENTATION_STATUS.md"

PHASE9A_DOCS = (
    DOCS / "EXTERNAL_AGENT_SECURITY_TOOL_LANDSCAPE.md",
    DOCS / "SCANNER_INTEGRATION_ARCHITECTURE.md",
    DOCS / "SCANNER_EVIDENCE_MODEL.md",
    DOCS / "SCANNER_THREAT_MODEL.md",
    DOCS / "SCANNER_SPLUNK_INTEGRATION_DESIGN.md",
    DOCS / "SCANNER_SANDBOXING_MODEL.md",
    DOCS / "PHASE9A_SCANNER_RESEARCH.md",
    NOTE,
)








def test_phase9a_did_not_change_schema_runtime_or_validated_spl():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "agentsec.scanner" not in schema
    assert "agentsec:scanner:finding" not in schema
    protocol = PROTOCOL.read_text(encoding="utf-8")
    assert "list_changed" not in protocol
    metadata = METADATA.read_text(encoding="utf-8")
    assert "CTRL-MCP-METADATA-001" in metadata
    assert "scanner" not in metadata.lower()
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
    )
    det = DET.read_text(encoding="utf-8")
    assert "CTRL-MCP-METADATA" not in det
    assert "scanner" not in det.lower()


