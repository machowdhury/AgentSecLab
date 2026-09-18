"""Phase 9D is detection analysis only: no new detector, Studio, or runtime feed."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DOCS = ROOT / "docs"


def test_phase9d_no_new_detector_or_studio():
    assert not list((ROOT / "learning").rglob("DET-SCANNER*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-SCANNER*"))
    assert not list((ROOT / "learning").rglob("DET-MCP-CATALOG*"))
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    scanner_views = {path.name for path in views.glob("*scanner*")}
    assert scanner_views <= {"ws_lab_scanner_runtime_evidence.xml"}
    saved = (ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf").read_text(
        encoding="utf-8"
    )
    assert "DET-SCANNER" not in saved
    assert "Q-SCANNER" not in saved


def test_phase9d_runtime_and_schema_unchanged_contracts():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.7.0"' in schema
    assert "agentsec.scanner" not in schema
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "scanner" not in det.lower()
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
    )
    assert "agentsec:scanner:finding" not in authz
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")


def test_phase9d_docs_choose_no_new_detector():
    required = (
        DOCS / "PHASE9D_SCANNER_DETECTION_ANALYSIS.md",
        DOCS / "SCANNER_DETECTION_MODEL.md",
        DOCS / "SCANNER_RUNTIME_EVIDENCE_PLANES.md",
        DOCS / "learning-notes" / "scanner-vs-runtime-detection.md",
        DOCS / "reviews" / "splunk-ko-review-scanner-detection-2026-09-16.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE9D_SCANNER_DETECTION_ANALYSIS.md").read_text(encoding="utf-8")
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in phase
    assert "DETECTION CANDIDATE JUSTIFIED FOR LATER IMPLEMENTATION" not in phase
    assert "No Snyk Agent Scan" in phase or "No Agent Scan" in phase
    assert "No rug-pull" in phase
    assert "No A2A" in phase
    assert "Phase 9E not started" in phase
    model = (DOCS / "SCANNER_DETECTION_MODEL.md").read_text(encoding="utf-8")
    assert "vulnerable_profile_fail_open:metadata_derived_authority" in model
    assert "REJECT" in model
    notes = (DOCS / "learning-notes" / "scanner-vs-runtime-detection.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "9D" in status
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in status
