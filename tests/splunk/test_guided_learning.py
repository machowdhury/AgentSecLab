"""Structural contracts for the guided learning shell.

These tests do not execute SPL and do not prove a dashboard rendered.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION

ROOT = Path(__file__).resolve().parents[2]
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
CURRICULUM = ROOT / "learning" / "academy" / "curriculum.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"

LIVE_VIEWS = {
    "ws_lab_pi_001",
    "ws_lab_mcp_001",
    "ws_lab_rag_context",
    "ws_lab_memory_security",
    "ws_lab_agent_goal_integrity",
    "ws_lab_agent_delegation",
    "ws_lab_agentsec_capstone",
}


def _definition(name: str) -> dict:
    xml = (VIEWS / f"{name}.xml").read_text(encoding="utf-8")
    start = xml.index("<![CDATA[") + len("<![CDATA[")
    end = xml.index("]]>")
    return json.loads(xml[start:end])


def test_navigation_is_about_twelve_curriculum_groups():
    root = ET.parse(NAV).getroot()
    children = list(root)
    labels = [child.get("label") or (child.text or "").strip() for child in children]
    assert labels == [
        "Home",
        "Your path",
        "Foundations",
        "Context Security",
        "Agent Intent",
        "Capstone",
        "Blue Team and Threat Modeling",
        "Identity and Delegation",
        "Data and Memory Governance",
        "Operational Scenarios",
        "Mastery",
        "Arena",
        "Search",
    ]
    assert len(children) == 13
    assert len(children) < 20
    for child in children:
        if child.tag != "collection":
            continue
        assert len(list(child)) >= 1
        for view in child:
            assert (VIEWS / f"{view.get('name')}.xml").is_file()
    assert (VIEWS / "learner_path.xml").is_file()
    assert (VIEWS / "ws_agentsec_arena.xml").is_file()


def test_curriculum_order_has_a_next_step_and_guide_metadata():
    curriculum = json.loads(CURRICULUM.read_text(encoding="utf-8"))
    assert curriculum["schema_version"] == "1.9.0"
    views = [view for group in curriculum["nav_collections"] for view in group["views"]]
    assert views[0] == "ws_lab_pi_001"
    assert len(views) == len(set(views))
    for view in views:
        definition = _definition(view)
        shell = definition["visualizations"]["viz_guide_shell"]["options"]["markdown"]
        assert "Where you are" in shell
        assert "What you are learning" in shell
        assert "What this does not prove" in shell
        assert "not execution" in shell
        assert "not a security verdict" in shell
        assert "tool_not_granted" not in shell
        assert "fail_open" not in shell
        assert "http://127.0.0.1" not in shell
        assert "http://localhost" not in shell


#: LIVE workshops default the LIVE run.id box to empty so the bound search shows
#: no specimen answer before the learner has run anything. The one exception is
#: LAB-MCP-001, whose Investigation Notebook deliberately offers a specimen
#: fallback. Dashboard Studio treats an EMPTY token as unset and then never runs
#: any search that references it ("Set token value to render visualization"),
#: so that lab needs a real sentinel value. It is "none": not a run.id, matching
#: no event, so the guide search still shows nothing. Measured on the deployed
#: dashboard: empty default -> 55 unrendered notebook panels; adding the
#: documented defaults.tokens stanza with an empty value -> 60.
LIVE_DEFAULT_EXCEPTIONS = {"ws_lab_mcp_001": "none"}


def test_live_workshops_bind_an_empty_run_id_to_an_inline_search():
    for view in LIVE_VIEWS:
        definition = _definition(view)
        text = next(
            inp for inp in definition["inputs"].values() if inp["type"] == "input.text"
        )
        assert text["options"]["defaultValue"] == LIVE_DEFAULT_EXCEPTIONS.get(view, "")
        query = definition["dataSources"]["ds_guide_events"]["options"]["query"]
        assert '"agentsec.run.id"="$live_run_id$"' in query
        assert 'where "$live_run_id$"!=""' in query
        assert definition["visualizations"]["viz_guide_events"]["type"] == "splunk.table"
        shell = definition["visualizations"]["viz_guide_shell"]["options"]["markdown"]
        assert "index=agentsec_telemetry" in shell
        assert "LIVE run.id" in shell


def test_replay_workshops_do_not_gain_a_paste_box():
    curriculum = json.loads(CURRICULUM.read_text(encoding="utf-8"))
    for level in curriculum["levels"]:
        for lab in level["labs"]:
            if lab["mode"] == "LIVE":
                continue
            definition = _definition(lab["view"])
            assert all(inp["type"] != "input.text" for inp in definition["inputs"].values())


def test_arena_is_optional_and_after_mastery():
    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_agentsec_mastery") < nav.index("ws_agentsec_arena")
    assert nav.index("ws_agentsec_arena") < nav.index('name="search"')
    arena = _definition("ws_agentsec_arena")
    text = arena["visualizations"]["viz_arena"]["options"]["markdown"]
    assert "Optional" in text
    assert "not the start" in text
    assert "LAB-PI-001" in text
    assert "not execution" in text
    assert "http://127.0.0.1" not in text


def test_security_contracts_remain():
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    conf = SAVED.read_text(encoding="utf-8")
    stanza = conf.split("[AgentSec - MCP Execution After Authorization Deny]", 1)[1].split("\n[", 1)[0]
    assert "disabled = 1" in stanza
    assert "enableSched = 0" in stanza
