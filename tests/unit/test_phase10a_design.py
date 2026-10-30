"""Phase 10A RAG / retrieved-context design documents. No runtime."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
NOTE = DOCS / "learning-notes" / "rag-context-security-101.md"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
AUTHZ = ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
RESULT = ROOT / "src" / "agentsec" / "mcp" / "result_trust.py"
METADATA = ROOT / "src" / "agentsec" / "mcp" / "metadata_trust.py"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
STATUS = DOCS / "IMPLEMENTATION_STATUS.md"
ROADMAP = DOCS / "AGENTSEC_ROADMAP_2026.md"

PHASE10A_DOCS = (
    DOCS / "RAG_PREDECESSOR_ANALYSIS.md",
    DOCS / "RAG_CONTEXT_SECURITY_MODEL.md",
    DOCS / "RAG_CONTEXT_THREAT_MODEL.md",
    DOCS / "RAG_LAB_SPECIFICATION.md",
    DOCS / "RAG_EVENT_MODEL_REVIEW.md",
    DOCS / "RAG_DETECTION_MODEL.md",
    DOCS / "RAG_EXTERNAL_TOOL_RESEARCH.md",
    NOTE,
)










def test_phase10a_design_docs_remain_and_detector_was_not_created():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "rag_context_trust" in schema
    protocol = PROTOCOL.read_text(encoding="utf-8")
    assert "rag" not in protocol.lower()
    result = RESULT.read_text(encoding="utf-8")
    assert "CTRL-MCP-RESULT-001" in result
    metadata = METADATA.read_text(encoding="utf-8")
    assert "CTRL-MCP-METADATA-001" in metadata
    det = DET.read_text(encoding="utf-8")
    assert "sequence>deny_sequence" in det
    assert "CTRL-RAG" not in det
    assert "RAG-001" not in det


def test_phase10a_did_not_add_spl_studio_or_rag_detector():
    learning = ROOT / "learning"
    assert list(learning.rglob("DET-RAG*")) == []
    catalog_xml = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    studio = {path.name for path in catalog_xml.glob("*rag*")} if catalog_xml.is_dir() else set()
    assert studio <= {"ws_lab_rag_context.xml"}
