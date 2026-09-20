"""Phase 14C: guided investigation on LAB-PI-001 only.

Does not start 14D, bump schema, add detectors, or change authorization.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
NOTE = DOCS / "learning-notes" / "guided-investigation-pi.md"
IMPL = DOCS / "PHASE14C_GUIDED_INVESTIGATION.md"
INV = ROOT / "learning" / "level_1" / "LAB-PI-001" / "investigations.json"


def test_phase14c_docs_exist():
    assert IMPL.is_file()
    assert NOTE.is_file()
    assert INV.is_file()
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")


def test_phase14c_did_not_bump_schema_or_add_detectors_or_new_nav():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-ATTACK-SIMULATOR" not in saved
    assert "DET-LAUNCH" not in saved
    assert "DET-PROMPT-ATTACK" not in saved
    names = {path.name for path in VIEWS.glob("ws_*.xml")}
    assert "ws_lab_pi_001.xml" in names
    assert "ws_guided_investigation.xml" not in names
    assert "ws_attack_simulator.xml" not in names
    assert not list((ROOT / "learning").rglob("DET-LAUNCH*"))
    hunt_files = {
        path.name
        for path in (ROOT / "learning" / "level_1" / "LAB-PI-001" / "searches").glob("Q-*.spl")
    }
    assert hunt_files == {
        "Q-RUN-EVENTS.spl",
        "Q-CONTROL-DECISION.spl",
        "Q-LLM-EXECUTED.spl",
        "Q-LLM-AFTER-DENY.spl",
        "Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl",
    }


def test_phase14c_forbids_14d_and_keeps_pi_reference():
    impl = IMPL.read_text(encoding="utf-8")
    assert "LAB-PI-001" in impl
    assert "Do not start Phase 14D" in impl
    assert "1.9.0" in impl
    builder = (ROOT / "scripts" / "build_lab_pi_001_dashboard.py").read_text(encoding="utf-8")
    assert "No custom JavaScript" in builder
    assert "fit-to-width" in builder
    assert "stacked notebook" in builder.lower() or "stacked notebook" in impl.lower()
