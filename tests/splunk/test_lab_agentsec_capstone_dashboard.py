"""Dashboard Studio contracts for LAB-AGENTSEC-CAPSTONE-001.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-AGENTSEC-CAPSTONE-001"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_agentsec_capstone.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_agentsec_capstone_dashboard.py"

WORKSHOP_TABS = (
    "MISSION",
    "INVESTIGATE",
    "EVIDENCE",
    "PATH B · ANSWERS",
)
REQUIRED_TOKENS = ("retrieve_run_id", "write_run_id", "run_id")


def _definition() -> dict:
    return json.loads(DEFINITION_PATH.read_text(encoding="utf-8"))


def test_builder_and_view_exist():
    assert BUILDER.is_file()
    assert DEFINITION_PATH.is_file()
    assert VIEW_XML.is_file()
    xml = VIEW_XML.read_text(encoding="utf-8")
    assert "<label>Lending Assistant Investigation</label>" in xml
    assert "Splunk does not ALLOW or DENY" in xml
    assert "RAG Memory MCP Authorization Failure" not in xml


def test_nav_includes_capstone_human_label():
    nav = NAV_XML.read_text(encoding="utf-8")
    assert "ws_lab_agentsec_capstone" in nav
    assert "Lending Assistant Investigation" in nav
    assert "LAB-AGENTSEC-CAPSTONE-001" not in nav


def test_tabs_and_tokens():
    definition = _definition()
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    assert labels == list(WORKSHOP_TABS)
    tokens = {
        inp["options"]["token"]
        for inp in definition["inputs"].values()
        if inp["type"] == "input.dropdown"
    }
    assert set(REQUIRED_TOKENS) <= tokens
    for inp in definition["inputs"].values():
        assert "Investigate" in inp["title"]
        assert inp["type"] == "input.dropdown"


def test_datasources_used_and_no_new_detector():
    definition = _definition()
    used = set()
    for viz in definition["visualizations"].values():
        ds = viz.get("dataSources") or {}
        used.update(ds.values())
    unused = set(definition["dataSources"]) - used
    assert not unused, unused
    queries = " ".join(
        str(ds.get("options", {}).get("query", "")) for ds in definition["dataSources"].values()
    )
    assert "DET-CAPSTONE" not in queries


def test_teaching_claims():
    definition = _definition()
    md = "\n".join(
        viz["options"]["markdown"]
        for viz in definition["visualizations"].values()
        if viz.get("type") == "splunk.markdown"
    )
    lowered = md.lower()
    assert "splunk authorized" not in lowered
    assert "splunk blocked" not in lowered
    assert "SAME ADVERSARIAL INFLUENCE" in md
    assert "DIFFERENT AUTHORIZATION" in md
    assert "CTRL-MCP-001" in md
    assert "Path A" in md
    assert "Path B" in md
    assert "Question 1 — Influence" in md
    assert "Question 6 — Control effectiveness" in md
    assert "Write a hypothesis before opening" in md
    assert "SUPPORTED" in md
    assert "INCORRECT" in md
    assert "enforcement" in lowered
    assert "fixture-equivalent" in lowered
    assert "ToolRegistry count proves invocation began" in md
    assert "event-local control.decision fields" in md
    assert "published BASELINE specimen triple" in md
    assert "official LIVE triple" not in md


def test_mission_does_not_leak_capstone_answers():
    definition = _definition()
    blocks = definition["layout"]["layoutDefinitions"]["layout_mission"]["structure"]
    mission_ids = {block["item"] for block in blocks}
    mission = "\n".join(
        definition["visualizations"][viz_id]["options"]["markdown"]
        for viz_id in mission_ids
        if definition["visualizations"][viz_id].get("type") == "splunk.markdown"
    )
    assert "vulnerable_profile_fail_open" not in mission
    assert "tool_not_granted" not in mission
    assert "Privileged handler 1" not in mission
    assert "ToolRegistry invocation count 1" not in mission
    assert "CTRL-MCP-001 **ALLOW**" not in mission
    assert "CTRL-MCP-001 **DENY**" not in mission
