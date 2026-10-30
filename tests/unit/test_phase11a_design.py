"""Phase 11A agent memory security design documents. No runtime."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
NOTE = DOCS / "learning-notes" / "agent-memory-security-101.md"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
STATUS = DOCS / "IMPLEMENTATION_STATUS.md"
ROADMAP = DOCS / "AGENTSEC_ROADMAP_2026.md"

PHASE11A_DOCS = (
    DOCS / "MEMORY_PREDECESSOR_ANALYSIS.md",
    DOCS / "MEMORY_SECURITY_MODEL.md",
    DOCS / "MEMORY_THREAT_MODEL.md",
    DOCS / "MEMORY_LAB_SPECIFICATION.md",
    DOCS / "MEMORY_EVENT_MODEL_REVIEW.md",
    DOCS / "MEMORY_DETECTION_MODEL.md",
    DOCS / "MEMORY_EXTERNAL_TOOL_RESEARCH.md",
    NOTE,
)










def test_phase11a_did_not_create_spl_detector_or_studio():
    protocol = PROTOCOL.read_text(encoding="utf-8")
    assert "memory" not in protocol.lower()
    det = DET.read_text(encoding="utf-8")
    assert "sequence>deny_sequence" in det
    assert "CTRL-MEMORY" not in det
    assert "MEMORY-001" not in det
    learning = ROOT / "learning"
    assert list(learning.rglob("DET-MEMORY*")) == []
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    studio = {path.name for path in views.glob("*memory*")} if views.is_dir() else set()
    assert studio <= {"ws_lab_memory_security.xml"}
