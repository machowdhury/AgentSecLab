"""Phase 8B catalog-poisoning design documents. No runtime."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
TOOLS = ROOT / "src" / "agentsec" / "mcp" / "tools.py"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"

PHASE8B_DOCS = (
    DOCS / "MCP_CATALOG_POISONING_PREDECESSOR_ANALYSIS.md",
    DOCS / "MCP_CATALOG_POISONING_SECURITY_MODEL.md",
    DOCS / "MCP_CATALOG_POISONING_THREAT_MODEL.md",
    DOCS / "MCP_CATALOG_POISONING_LAB_SPECIFICATION.md",
    DOCS / "MCP_CATALOG_POISONING_EVENT_MODEL_REVIEW.md",
    DOCS / "MCP_CATALOG_POISONING_SCANNER_INTEGRATION.md",
    DOCS / "MCP_CATALOG_POISONING_DETECTION_MODEL.md",
    DOCS / "learning-notes" / "mcp-tool-description-security-101.md",
)






def test_phase8b_did_not_add_spl_studio_or_detector():
    det = DET.read_text(encoding="utf-8")
    assert "sequence>deny_sequence" in det
    assert "CTRL-MCP-METADATA" not in det
    protocol = PROTOCOL.read_text(encoding="utf-8")
    assert "tools/list" not in protocol
    assert "list_changed" not in protocol
