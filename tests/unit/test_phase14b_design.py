"""Phase 14B docs and non-goals: no schema bump, no detector, no Studio launcher."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
NOTE = DOCS / "learning-notes" / "launch-investigate-live-run.md"

PHASE14B_DOCS = (
    DOCS / "PHASE14B_ATTACK_SERVICE_IMPLEMENTATION.md",
    DOCS / "AGENTSEC_ATTACK_SERVICE_RUNTIME_CONTRACT.md",
    DOCS / "AGENTSEC_ATTACK_SERVICE_SECURITY_BOUNDARY.md",
    DOCS / "AGENTSEC_LIVE_LAUNCH_EVIDENCE_CONTRACT.md",
    NOTE,
)


def test_phase14b_docs_exist():
    for path in PHASE14B_DOCS:
        assert path.is_file(), path


def test_phase14b_did_not_bump_schema_or_add_detectors_or_studio():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-ATTACK-SIMULATOR" not in saved
    assert "DET-LAUNCH" not in saved
    assert "DET-PROMPT-ATTACK" not in saved
    assert "DET-GOAL" not in saved
    names = {path.name for path in VIEWS.glob("ws_*.xml")}
    assert "ws_lab_pi_001.xml" in names
    assert "ws_attack_simulator.xml" not in names
    assert "ws_guided_investigation.xml" not in names
    assert not list((ROOT / "learning").rglob("DET-LAUNCH*"))
    assert not list((ROOT / "learning").rglob("Q-ATTACK-SIM*"))


def test_phase14b_status_forbids_14c_and_keeps_pi_reference():
    impl = (DOCS / "PHASE14B_ATTACK_SERVICE_IMPLEMENTATION.md").read_text(encoding="utf-8")
    assert "LAB-PI-001" in impl
    assert "Do not start Phase 14C" in impl
    assert "BLOCKED BY PROCESS-ENV ARCHITECTURE" in impl
    assert "WAITING_FOR_EVIDENCE" in impl
    assert "NOT PRODUCTION AUTHENTICATION" in impl
    notes = NOTE.read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in notes
