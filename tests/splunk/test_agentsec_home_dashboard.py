"""Contracts for the AgentSec Home landing view.

No hunts. No detectors. Orientation only.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFINITION = ROOT / "learning" / "home" / "dashboard.definition.json"
VIEW_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_agentsec_home.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_agentsec_home_dashboard.py"


def _definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def _xml_definition() -> dict:
    xml = VIEW_XML.read_text(encoding="utf-8")
    start = xml.index("<![CDATA[") + len("<![CDATA[")
    end = xml.index("]]>")
    return json.loads(xml[start:end].strip())


def test_home_files_and_nav_default():
    assert DEFINITION.is_file()
    assert VIEW_XML.is_file()
    assert BUILDER.is_file()
    nav = NAV_XML.read_text(encoding="utf-8")
    assert 'name="ws_agentsec_home" default="true"' in nav
    assert "<collection label=" in nav
    assert "LAB-PI-001" not in nav
    file_def = _definition()
    assert file_def == _xml_definition()
    xml = VIEW_XML.read_text(encoding="utf-8")
    assert "<label>Home</label>" in xml
    assert "dataSources" not in file_def
    assert file_def["layout"]["options"]["submitButton"] is False


def test_home_is_orientation_not_a_directory():
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "LEARN" in markdown
    assert "BASELINE" in markdown
    assert "ATTACK" in markdown
    assert "OBSERVE" in markdown
    assert "HUNT" in markdown
    assert "DETECT" in markdown
    assert "DEFEND" in markdown
    assert "RETEST" in markdown
    assert "COMPARE" in markdown
    assert "PROVE" in markdown
    assert "Splunk does not grant" in markdown or "Splunk does not" in markdown
    assert "DET-MCP-001" in markdown
    lowered = markdown.lower()
    assert "safe" not in lowered or "not safe" in lowered
    assert "dataSources" not in json.dumps(_definition())
