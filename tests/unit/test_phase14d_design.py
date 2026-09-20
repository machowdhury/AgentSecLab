"""Phase 14D: LIVE RETEST on LAB-PI-001 only. Does not start 14E or MCP-001."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
NOTE = ROOT / "docs" / "learning-notes" / "live-defend-retest-compare.md"
IMPL = ROOT / "docs" / "PHASE14D_LIVE_DEFEND_RETEST_COMPARE.md"
ATTACK_APP = ROOT / "src" / "agentsec" / "attack_app.py"
CTX = ROOT / "src" / "agentsec" / "experiment_context.py"


def test_phase14d_docs_exist():
    assert IMPL.is_file()
    assert NOTE.is_file()
    assert CTX.is_file()
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")


def test_phase14d_did_not_bump_schema_or_add_detectors_or_mcp001():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-ATTACK-SIMULATOR" not in saved
    assert "DET-LAUNCH" not in saved
    names = {path.name for path in VIEWS.glob("ws_*.xml")}
    assert "ws_lab_pi_001.xml" in names
    assert "ws_lab_mcp_001_live.xml" not in names
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


def test_phase14d_forbids_14e():
    impl = IMPL.read_text(encoding="utf-8")
    assert "LAB-PI-001" in impl
    assert "Do not start Phase 14E" in impl
    assert "1.9.0" in impl
    ctx = CTX.read_text(encoding="utf-8")
    assert "ExperimentContext" in ctx
    assert "from_definition" in ctx
