"""Offline contracts for the Detection Engineering workshop.

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
LAB = ROOT / "learning" / "level_1" / "LAB-DETECTION-ENGINEERING"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_detection_engineering.xml"
)
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
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


def test_checkpoint_follows_l6_and_levels_stay_put():
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    ids = [row["id"] for row in curriculum["levels"]]
    assert ids == ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10"]
    checkpoint = curriculum["checkpoints"][1]
    assert checkpoint["id"] == "DETECTION-ENGINEERING"
    assert checkpoint["placement"] == "L6 → Detection Engineering Workshop → L7"
    assert checkpoint["mode"] == "REPLAY"
    assert checkpoint["live_launcher"] is False
    assert checkpoint["lab_id"] not in known_lab_ids()
    blue = next(row for row in curriculum["nav_collections"] if row["label"] == "Blue Team and Threat Modeling")
    views = blue["views"]
    assert views.index("ws_lab_blue_team_incident") < views.index("ws_lab_detection_engineering")
    assert views.index("ws_lab_detection_engineering") < views.index("ws_lab_threat_modeling")
    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_lab_blue_team_incident") < nav.index("ws_lab_detection_engineering")
    assert nav.index("ws_lab_detection_engineering") < nav.index("ws_lab_threat_modeling")
    l7 = next(row for row in curriculum["levels"] if row["id"] == "L7")
    assert "Detection Engineering workshop" in l7["prerequisites"]


def test_path_a_does_not_hand_over_the_correlation_or_the_runs():
    definition = _definition()
    assert definition["inputs"] == {}
    assert [row["label"] for row in definition["layout"]["tabs"]["items"]][0] == "MISSION"
    path_a = "\n".join(
        _tab_markdown(layout_id)
        for layout_id in (
            "layout_mission",
            "layout_hypothesis",
            "layout_correlate",
            "layout_compare",
            "layout_coverage",
        )
    )
    assert "security question" in path_a.lower()
    assert "earliest=0" in path_a
    assert UUID.search(path_a) is None
    assert "eventstats" not in path_a
    assert "Beginner" in _tab_markdown("layout_mission")
    assert "Practitioner" in _tab_markdown("layout_mission")
    assert "Expert" in _tab_markdown("layout_mission")
    assert "NOT IMPLEMENTED" in path_a
    assert "NO EVIDENCE FOUND" in path_a
    assert "NO MATCH" in path_a
    assert "Find CTRL-MCP-001" in path_a
    assert "Write the coverage statement" in path_a
    det_md = (
        ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.md"
    ).read_text(encoding="utf-8")
    assert "operational detection" not in det_md.lower()
    assert "LOGIC_VALIDATED" in det_md
    assert "disabled" in det_md.lower()


def test_path_b_records_order_and_the_shipped_gap():
    path_b = _tab_markdown("layout_path_b")
    assert "0ab10594-a7fc-48b6-81bf-4cbca54a64c6" in path_b
    assert "23c222ea-6a87-40b7-a3e9-f12a5b572fa1" in path_b
    assert "not after" in path_b.lower()
    assert "SIMULATED" in path_b
    assert "not policy" in path_b.lower()
    assert "control_id" in path_b
    tuned = _definition()["dataSources"]["ds_tuned"]["options"]["query"]
    broad = _definition()["dataSources"]["ds_broad"]["options"]["query"]
    assert 'control_id="CTRL-MCP-001"' in tuned
    assert "sequence>deny_sequence" in tuned
    assert "by run_id tool" in tuned
    assert "sequence>" not in broad
    assert "by run_id tool" not in broad
    assert "earliest=0" in tuned and "earliest=0" in broad


def test_detector_schema_and_contract_stay_put():
    saved = SAVED.read_text(encoding="utf-8")
    assert saved.count("disabled = 1") == 3
    assert "disabled = 0" not in saved
    assert "enableSched = 0" in saved
    det = DET.read_text(encoding="utf-8")
    assert 'control_id="CTRL-MCP-001"' not in det
    assert 'decision="DENY"' in det
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    assert CONTROL_ID == "CTRL-MCP-001"
    assert VIEW.is_file()
    assert "LAB-DETECTION-ENGINEERING" in VIEW.read_text(encoding="utf-8")
