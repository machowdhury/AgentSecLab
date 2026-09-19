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


def test_phase9a_design_docs_exist():
    for path in PHASE9A_DOCS:
        assert path.is_file(), path
    assert STATUS.is_file()
    assert (DOCS / "AGENTSEC_ROADMAP_2026.md").is_file()


def test_phase9a_is_design_only():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in PHASE9A_DOCS)
    assert "DESIGN" in blob
    assert "SCANNER FINDING ≠ AUTHORIZATION DECISION" in blob
    assert "Scanner PASS ≠ trusted" in blob
    assert "Do not start Phase 9B" in blob
    research = (DOCS / "PHASE9A_SCANNER_RESEARCH.md").read_text(encoding="utf-8")
    assert "cisco-ai-defense/mcp-scanner" in research or "mcp-scanner" in research
    assert "snyk/agent-scan" in research
    assert "INTEGRATE FIRST" in research
    assert "YARA" in research
    assert "DefenseClaw" in research
    assert "OBSERVED_SCANNER" in (DOCS / "SCANNER_EVIDENCE_MODEL.md").read_text(
        encoding="utf-8"
    )
    assert "agentsec:scanner:finding" in (
        DOCS / "SCANNER_SPLUNK_INTEGRATION_DESIGN.md"
    ).read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")


def test_phase9a_first_target_is_mcp_scanner_static_not_merely_cisco():
    research = (DOCS / "PHASE9A_SCANNER_RESEARCH.md").read_text(encoding="utf-8")
    assert "Not selected merely because it is Cisco" in research
    assert "static" in research.lower()
    arch = (DOCS / "SCANNER_INTEGRATION_ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "CTRL-MCP-001" in arch
    assert "CTRL-MCP-METADATA-001" in arch
    assert "must not become" in arch.lower() or "must not" in arch


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


def test_phase9a_did_not_add_spl_studio_or_detector():
    learning = ROOT / "learning"
    assert list(learning.rglob("DET-SCANNER*")) == []
    catalog_xml = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    studio = {path.name for path in catalog_xml.glob("*scanner*")} if catalog_xml.is_dir() else set()
    assert studio <= {"ws_lab_scanner_runtime_evidence.xml"}
    status = STATUS.read_text(encoding="utf-8")
    assert "9A DESIGN / RESEARCH ONLY" in status
    assert "NOT STARTED" in status
    splunk_design = (DOCS / "SCANNER_SPLUNK_INTEGRATION_DESIGN.md").read_text(
        encoding="utf-8"
    )
    assert "No SPL" in splunk_design or "No SPL." in splunk_design
    assert "Do not publish" in splunk_design
    assert "DET-MCP-SCANNER" in splunk_design
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    assert "Do not start Phase 9B" in roadmap
    assert "No rug-pull" in roadmap
    assert "No A2A" in roadmap
