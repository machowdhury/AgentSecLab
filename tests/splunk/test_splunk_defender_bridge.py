"""Offline contracts for the Splunk Defender Bridge.

These tests do not execute SPL against Splunk and do not prove browser
rendering, event completeness, or control effectiveness.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.authorize import CONTROL_ID

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-SPLUNK-DEFENDER-BRIDGE"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_splunk_defender_bridge.xml"
)
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
SEARCHES = LAB / "searches"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def _tab_markdown(layout_id: str) -> str:
    definition = _definition()
    parts = []
    for row in definition["layout"]["layoutDefinitions"][layout_id]["structure"]:
        viz = definition["visualizations"][row["item"]]
        if viz.get("type") == "splunk.markdown":
            parts.append(viz["options"]["markdown"])
    return "\n".join(parts)


def test_checkpoint_sits_between_l5_and_l6_and_is_not_live():
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    ids = [row["id"] for row in curriculum["levels"]]
    assert ids == ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10"]
    checkpoint = curriculum["checkpoints"][0]
    assert checkpoint["id"] == "SPLUNK-DEFENDER-BRIDGE"
    assert checkpoint["placement"] == "L5 → Splunk Defender Bridge → L6"
    assert checkpoint["mode"] == "REPLAY"
    assert checkpoint["live_launcher"] is False
    assert checkpoint["lab_id"] not in known_lab_ids()
    labels = [row["label"] for row in curriculum["nav_collections"]]
    assert labels.index("Capstone") < labels.index("Splunk Defender Bridge") < labels.index(
        "Blue Team"
    )
    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_lab_agentsec_capstone") < nav.index("ws_lab_splunk_defender_bridge")
    assert nav.index("ws_lab_splunk_defender_bridge") < nav.index("ws_lab_blue_team_incident")
    l6 = next(row for row in curriculum["levels"] if row["id"] == "L6")
    assert "Splunk Defender Bridge" in l6["prerequisites"]
    assert (ROOT / "scripts" / "build_lab_splunk_defender_bridge_dashboard.py").is_file()
    assert DEFINITION.is_file()
    assert VIEW.is_file()


def test_mission_does_not_supply_a_run_id_or_the_comparison_answer():
    mission = _tab_markdown("layout_mission")
    assert "security question" in mission.lower()
    assert "hypothesis" in mission.lower()
    assert UUID.search(mission) is None
    assert "agentsec.run.id=" not in mission
    for banned in ("was denied", "did not execute", "NO ATTACK"):
        assert banned.lower() not in mission.lower()
    definition = _definition()
    assert definition["inputs"] == {}
    assert [row["label"] for row in definition["layout"]["tabs"]["items"]][0] == "MISSION"


def test_progressive_hints_and_answer_separation():
    discover = _tab_markdown("layout_discover")
    investigate = _tab_markdown("layout_investigate")
    path_b = _tab_markdown("layout_path_b")
    assert "Hint 1" in discover
    assert "Hint 2" in discover
    assert "Hint 3" in discover
    assert "Hint 4" in investigate
    assert "stats _____" in discover
    assert "dc(agentsec.run.id) as distinct_runs by agentsec.testbed.mode" in path_b
    assert "dc(agentsec.run.id) as distinct_runs by agentsec.testbed.mode" not in discover
    assert "Path B" in path_b
    assert "not policy" in path_b.lower()
    assert "Beginner" in _tab_markdown("layout_mission")
    assert "Practitioner" in _tab_markdown("layout_mission")
    assert "Advanced" in _tab_markdown("layout_mission")


def test_comparison_duplicates_gaps_and_false_lead():
    investigate = _tab_markdown("layout_investigate")
    challenge = _tab_markdown("layout_challenge")
    path_b = _tab_markdown("layout_path_b")
    assert "ATTACK" in investigate and "RETEST" in investigate and "BASELINE" in investigate
    assert "NOT PROVEN" in challenge
    assert "NOT MODELED" in challenge
    assert "NOT PROVEN" in path_b
    assert "NOT MODELED" in path_b
    assert "dc(_raw)" in challenge
    assert "indexed rows" in challenge.lower()
    assert "NO EVIDENCE FOUND" in challenge
    assert "INSUFFICIENT EVIDENCE" in challenge
    assert "CORRELATION NOT ESTABLISHED" in challenge
    assert "mcp-scanner" in challenge
    assert "garak" in challenge
    assert "HIGH" in challenge
    assert "description hash" in challenge
    for banned in ("SAFE", "SECURE", "NO ATTACK"):
        assert not re.search(rf"\b{banned}\b", challenge)


def test_searches_are_bounded_and_do_not_embed_a_run_id():
    names = sorted(path.name for path in SEARCHES.glob("Q-BRIDGE-*.spl"))
    assert names == [
        "Q-BRIDGE-COMPARE.spl",
        "Q-BRIDGE-DISCOVER.spl",
        "Q-BRIDGE-DUPLICATES.spl",
        "Q-BRIDGE-EXTERNAL.spl",
        "Q-BRIDGE-FIELDS.spl",
        "Q-BRIDGE-NARROW.spl",
        "Q-BRIDGE-SEQUENCE.spl",
        "Q-BRIDGE-STATS.spl",
    ]
    discover = (SEARCHES / "Q-BRIDGE-DISCOVER.spl").read_text(encoding="utf-8")
    assert discover.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "agentsec.run.id=" not in discover
    narrow = (SEARCHES / "Q-BRIDGE-NARROW.spl").read_text(encoding="utf-8")
    assert "by agentsec.run.id" in narrow
    assert "CTRL-MCP-001" in narrow
    for path in SEARCHES.glob("*.spl"):
        text = path.read_text(encoding="utf-8")
        assert text.startswith("index=agentsec_telemetry"), path.name
        assert "index=*" not in text
        assert UUID.search(text) is None
        assert "DET-" not in text
        assert "enableSched" not in text


def test_security_semantics_schema_and_detector_boundary():
    challenge = _tab_markdown("layout_challenge")
    assert "CTRL-MCP-001" in challenge
    assert "does not enable DET-MCP-001" in challenge
    assert "candidate detection" in challenge
    assert "enabled detector" in challenge
    assert CONTROL_ID == "CTRL-MCP-001"
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert saved.count("[AgentSec -") == 1
    assert "enableSched = 0" in saved or "enableSched=0" in saved
    contract = (
        ROOT / "src" / "agentsec" / "external_evidence" / "contract.py"
    ).read_text(encoding="utf-8")
    assert 'EXTERNAL_CONTRACT_VERSION = "1.0.0"' in contract
    note = (ROOT / "docs" / "learning-notes" / "splunk-defender-bridge.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in note
