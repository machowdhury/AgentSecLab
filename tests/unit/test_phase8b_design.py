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


def test_phase8b_design_docs_exist():
    for path in PHASE8B_DOCS:
        assert path.is_file(), path


def test_phase8b_is_design_only():
    blob = "\n".join(p.read_text(encoding="utf-8") for p in PHASE8B_DOCS)
    assert "DESIGN" in blob
    assert "LAB-MCP-CATALOG" in blob
    assert "INV-002" in blob
    assert "vulnerable_profile_fail_open:metadata_derived_authority" in blob
    assert "CTRL-MCP-METADATA-001" in blob
    spec = (DOCS / "MCP_CATALOG_POISONING_LAB_SPECIFICATION.md").read_text(encoding="utf-8")
    assert "also invoke lookup_customer_tier" in spec
    assert "Do **not** reuse MCP-005" in spec
    assert "same MALICIOUS" in spec
    assert "grant_tool" in spec
    scan = (DOCS / "MCP_CATALOG_POISONING_SCANNER_INTEGRATION.md").read_text(encoding="utf-8")
    assert "cisco-ai-defense/mcp-scanner" in scan
    assert "snyk/agent-scan" in scan
    assert "Evidence. **Not** runtime DENY" in scan
    det = (DOCS / "MCP_CATALOG_POISONING_DETECTION_MODEL.md").read_text(encoding="utf-8")
    assert "DET-MCP-001" in det
    assert "NO DETECTOR JUSTIFIED" in det
    events = (DOCS / "MCP_CATALOG_POISONING_EVENT_MODEL_REVIEW.md").read_text(encoding="utf-8")
    assert "BLOCKED BY TELEMETRY" in events
    assert "mcp_metadata_trust" in events


def test_phase8b_did_not_add_spl_studio_or_detector():
    det = DET.read_text(encoding="utf-8")
    assert "sequence>deny_sequence" in det
    assert "CTRL-MCP-METADATA" not in det
    protocol = PROTOCOL.read_text(encoding="utf-8")
    assert "tools/list" not in protocol
    assert "list_changed" not in protocol
