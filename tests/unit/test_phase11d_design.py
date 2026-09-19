"""Phase 11D is detection analysis only: no new detector, Studio, or runtime change."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
HUNT = ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "searches" / "Q-MEMORY-CONTEXT-AUTHORITY.spl"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DOCS = ROOT / "docs"


def test_phase11d_no_new_detector_or_studio():
    assert not list((ROOT / "learning").rglob("DET-MEMORY*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-MEMORY*"))
    views = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    memory_views = {path.name for path in views.glob("*memory*")} if views.is_dir() else set()
    assert memory_views <= {"ws_lab_memory_security.xml"}
    saved = (ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf").read_text(
        encoding="utf-8"
    )
    assert "DET-MEMORY" not in saved
    assert "Q-MEMORY" not in saved


def test_phase11d_runtime_schema_and_existing_spl_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "sequence>deny_sequence" in det
    assert "CTRL-MEMORY" not in det
    assert "MEMORY-001" not in det
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
    )
    hunt = HUNT.read_text(encoding="utf-8")
    assert 'hop="1"' in hunt
    assert "CTRL-MEMORY-CONTEXT-001" in hunt
    assert "__WRITE_RUN_ID__" in hunt
    assert "__RECALL_RUN_ID__" in hunt
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")


def test_phase11d_docs_choose_no_new_detector():
    required = (
        DOCS / "PHASE11D_MEMORY_DETECTION_ANALYSIS.md",
        DOCS / "MEMORY_DETECTION_ENGINEERING_MODEL.md",
        DOCS / "MEMORY_RUNTIME_EVIDENCE_PLANES.md",
        DOCS / "learning-notes" / "memory-detection-vs-hunting.md",
        DOCS / "reviews" / "splunk-ko-review-memory-detection-2026-09-18.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE11D_MEMORY_DETECTION_ANALYSIS.md").read_text(encoding="utf-8")
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in phase
    assert "DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN" not in phase
    assert "NEW DETECTOR JUSTIFIED" not in phase
    assert "No Agent Scan" in phase or "No Snyk Agent Scan" in phase
    assert "No rug-pull" in phase
    assert "No A2A" in phase
    assert "Phase 11E not started" in phase
    assert "0 rows is CORRECT BEHAVIOR" in phase
    assert "sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9" in phase
    assert "b8737cd9-9b6b-48f2-acfa-178ae1446ddc" in phase
    assert "5d5b9d1b-092d-4ddb-8422-4092d289cd49" in phase
    model = (DOCS / "MEMORY_DETECTION_ENGINEERING_MODEL.md").read_text(encoding="utf-8")
    assert "vulnerable_profile_fail_open:memory_derived_authority" in model
    assert "REJECT" in model
    assert "TELEMETRY GAP" in model
    notes = (DOCS / "learning-notes" / "memory-detection-vs-hunting.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "11D" in status
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in status
    assert "11E NOT STARTED" in status or "Phase 11E" in status
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    assert "Do not start Phase 11E" in roadmap
    assert "No rug-pull" in roadmap
    assert "No A2A" in roadmap
    planes = (DOCS / "MEMORY_RUNTIME_EVIDENCE_PLANES.md").read_text(encoding="utf-8")
    assert "Plane 1" in planes
    assert "Plane 5" in planes
    assert "CONTROL EVIDENCE" in planes
    assert "EXECUTION EVIDENCE" in planes
