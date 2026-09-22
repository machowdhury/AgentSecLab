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


def test_home_is_academy_landing_not_stale_directory():
    definition = _definition()
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in definition["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    assert labels == ["START", "ORIENT", "PATH", "SPLUNK"]
    assert "Start here" in markdown
    assert "Direct Prompt Injection" in markdown
    assert "Agent Identity / Delegation" in markdown
    assert "Lending Assistant Investigation" in markdown
    assert "LIVE" in markdown
    assert "REPLAY" in markdown
    assert "not published" not in markdown.lower()
    assert "Attack Labs" not in markdown
    assert "Foundations" in markdown
    assert "Path A" in markdown
    assert "Path B" in markdown
    assert "Mastery Check" in markdown
    assert "index=agentsec_telemetry" in markdown
    assert "SUPPORTED" in markdown
    assert "INCORRECT" in markdown
    assert "1.9.0" in markdown
