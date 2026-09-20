"""Dashboard Studio contracts for LAB-PI-001 WS-001.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-PI-001"
SEARCH_DIR = LAB_DIR / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_pi_001.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"

REQUIRED_IDS = (
    "Q-RUN-EVENTS",
    "Q-CONTROL-DECISION",
    "Q-LLM-EXECUTED",
    "Q-LLM-AFTER-DENY",
)
WORKSHOP_TABS = (
    "LEARN",
    "BASELINE",
    "ATTACK",
    "OBSERVE",
    "HUNT",
    "DETECT",
    "DEFEND",
    "RETEST",
    "COMPARE",
    "PROVE",
)
PROHIBITED_FIELDS = (
    "agentsec.event.name",
    "agentsec.profile",
    "agentsec.pipeline.outcome",
)
REQUIRED_TOKENS = ("run_id",)
HUNT_LOCAL_TOKENS = ()
SPECIMEN_IDS = {
    "baseline_run_id": "b3611d56-0d3f-4b2e-9a51-75ae36628155",
    "attack_run_id": "f39fed12-de89-45ba-b684-5b6077942580",
    "retest_run_id": "bbe75cb8-0190-47d6-86be-5feba58ad5c0",
}


def _definition() -> dict:
    return json.loads(DEFINITION_PATH.read_text(encoding="utf-8"))


def _xml_definition() -> dict:
    xml = VIEW_XML.read_text(encoding="utf-8")
    match = re.search(r"<definition><!\[CDATA\[\n(.*)\n  \]\]></definition>", xml, re.S)
    assert match, "Studio XML must wrap the definition in CDATA"
    return json.loads(match.group(1))


def test_definition_files_exist_and_match():
    assert DEFINITION_PATH.is_file()
    assert VIEW_XML.is_file()
    assert NAV_XML.is_file()
    assert "ws_lab_pi_001" in NAV_XML.read_text(encoding="utf-8")
    file_def = _definition()
    xml_def = _xml_definition()
    assert file_def == xml_def
    xml = VIEW_XML.read_text(encoding="utf-8")
    assert xml.startswith("<?xml")
    assert 'version="2"' in xml
    assert 'theme="light"' in xml


def test_grid_workshop_tabs_and_tokens():
    definition = _definition()
    assert definition["layout"]["layoutDefinitions"]
    for layout in definition["layout"]["layoutDefinitions"].values():
        assert layout["type"] == "grid"
        assert layout["options"]["backgroundColor"] == "#F6F8FB"
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    assert labels == list(WORKSHOP_TABS)
    tokens = {inp["options"]["token"] for inp in definition["inputs"].values()}
    assert tokens == set(REQUIRED_TOKENS) | set(HUNT_LOCAL_TOKENS)
    assert definition["layout"]["globalInputs"] == ["input_run_id"]
    hunt_inp = [inp for inp in definition["inputs"].values() if inp["options"]["token"] == "run_id"][0]
    assert hunt_inp["type"] == "input.dropdown"
    assert hunt_inp["options"]["defaultValue"] == SPECIMEN_IDS.get("run_id", SPECIMEN_IDS["baseline_run_id"])
    item_values = {item["value"] for item in hunt_inp["options"]["items"]}
    assert SPECIMEN_IDS["baseline_run_id"] in item_values
    assert SPECIMEN_IDS["attack_run_id"] in item_values
    assert SPECIMEN_IDS["retest_run_id"] in item_values
    hunt = [
        inp for inp in definition["inputs"].values() if inp["options"]["token"] == "run_id"
    ][0]
    assert hunt["options"]["defaultValue"] == SPECIMEN_IDS["baseline_run_id"]
    assert hunt["title"] == "Investigate specimen"
    global_titles = {
        definition["inputs"][input_id]["title"]
        for input_id in definition["layout"]["globalInputs"]
    }
    assert global_titles == {"Investigate specimen"}
    hunt_layout = definition["layout"]["layoutDefinitions"]["layout_hunt"]["structure"]
    hunt_input_ids = {item["item"] for item in hunt_layout if item["type"] == "input"}
    assert hunt_input_ids == set()
    assert definition["layout"]["layoutDefinitions"]["layout_hunt"]["options"]["display"] == "fit-to-width"
    assert "expressions" not in definition or not definition.get("expressions", {}).get("conditions")


def test_datasources_are_validated_spl_with_token_bind_only():
    definition = _definition()
    catalog = json.loads((SEARCH_DIR / "catalog.json").read_text(encoding="utf-8"))
    queries = {row["id"]: row for row in catalog["queries"]}
    expected = {
        "ds_q_run_events": (queries["Q-RUN-EVENTS"]["spl_file"], "run_id"),
        "ds_q_control": (queries["Q-CONTROL-DECISION"]["spl_file"], "run_id"),
        "ds_q_llm": (queries["Q-LLM-EXECUTED"]["spl_file"], "run_id"),
        "ds_q_after_deny": (queries["Q-LLM-AFTER-DENY"]["spl_file"], "run_id"),
        "ds_q_control_baseline": (queries["Q-CONTROL-DECISION"]["spl_file"], SPECIMEN_IDS["baseline_run_id"]),
        "ds_q_control_attack": (queries["Q-CONTROL-DECISION"]["spl_file"], SPECIMEN_IDS["attack_run_id"]),
        "ds_q_control_retest": (queries["Q-CONTROL-DECISION"]["spl_file"], SPECIMEN_IDS["retest_run_id"]),
        "ds_q_llm_baseline": (queries["Q-LLM-EXECUTED"]["spl_file"], SPECIMEN_IDS["baseline_run_id"]),
        "ds_q_llm_attack": (queries["Q-LLM-EXECUTED"]["spl_file"], SPECIMEN_IDS["attack_run_id"]),
        "ds_q_llm_retest": (queries["Q-LLM-EXECUTED"]["spl_file"], SPECIMEN_IDS["retest_run_id"]),
    }
    for ds_id, (spl_file, token) in expected.items():
        spl = (SEARCH_DIR / spl_file).read_text(encoding="utf-8").strip()
        bound = spl.replace("__RUN_ID__", f'"${token}$"' if token == "run_id" else f'"{token}"')
        assert definition["dataSources"][ds_id]["options"]["query"] == bound, ds_id
        assert definition["dataSources"][ds_id]["type"] == "ds.search"
    sim = catalog["positive_control"]
    sim_spl = (SEARCH_DIR / sim["spl_file"]).read_text(encoding="utf-8").strip()
    assert definition["dataSources"]["ds_q_after_deny_sim"]["options"]["query"] == sim_spl
    assert set(definition["dataSources"]) == set(expected) | {"ds_q_after_deny_sim"}


def test_visualizations_reference_existing_datasources_and_layouts():
    definition = _definition()
    ds_ids = set(definition["dataSources"])
    viz_ids = set(definition["visualizations"])
    layout_items: set[str] = set()
    layout_inputs: set[str] = set()
    for layout in definition["layout"]["layoutDefinitions"].values():
        for item in layout["structure"]:
            assert item["type"] in {"block", "input"}
            if item["type"] == "input":
                layout_inputs.add(item["item"])
            else:
                layout_items.add(item["item"])
    assert layout_items == viz_ids
    assert layout_inputs == set()
    assert layout_inputs.isdisjoint(viz_ids)
    for viz_id, viz in definition["visualizations"].items():
        assert viz["type"] in {"splunk.markdown", "splunk.table"}
        if viz["type"] == "splunk.table":
            primary = viz["dataSources"]["primary"]
            assert primary in ds_ids, viz_id
            assert viz.get("hideWhenNoData") is False
    used_ds = {
        viz["dataSources"]["primary"]
        for viz in definition["visualizations"].values()
        if viz["type"] == "splunk.table"
    }
    assert used_ds == ds_ids


def test_no_new_detections_attacks_or_out_of_scope_topics():
    blob = json.dumps(_definition()) + VIEW_XML.read_text(encoding="utf-8")
    lowered = blob.lower()
    for field in PROHIBITED_FIELDS:
        assert field not in blob
    assert "action.notable" not in lowered
    assert "no notable event" in lowered
    assert "cron_schedule" not in lowered
    assert "alert.track" not in lowered
    assert "ds.savedsearch" not in lowered
    assert "ds.mltk" not in lowered
    assert "no mcp / a2a / rag / mltk" in lowered
    for query_id in REQUIRED_IDS:
        assert query_id in blob
    assert "not a detection" in lowered
    assert "simulated" in lowered
    assert "makeresults" in lowered
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "does **not** ALLOW or DENY" in markdown
    assert "78f05d1b-728e-4e70-8993-f5e365871f87" in markdown
    assert "Do **not** call" in markdown
    assert "| Role | run.id |" not in markdown
    assert "**BASELINE** `b3611d56-0d3f-4b2e-9a51-75ae36628155`" in markdown
    assert "not in `index=agentsec_telemetry` here" in markdown
    assert "Path A" in markdown
    assert "Path B" in markdown
    assert "Try it yourself" in markdown
    assert "WHAT IT DOES NOT MEAN" in markdown
    assert "Connect the concepts" in markdown
    assert "Launch RETEST (LIVE)" in markdown
    assert "SAME ATTACK INPUT" in markdown
    assert "What changed?" in markdown
    assert "not automatically SAFE" in markdown
    assert "custom javascript" not in json.dumps(_definition()).lower()
    for viz in _definition()["visualizations"].values():
        if viz["type"] == "splunk.markdown":
            assert viz["options"]["fontSize"] == "large"
            assert not viz["options"]["markdown"].startswith("        #"), viz


def test_hunt_path_b_panels_are_sequential_and_investigations_overlay():
    hunt = _definition()["layout"]["layoutDefinitions"]["layout_hunt"]
    by_item = {row["item"]: row["position"] for row in hunt["structure"]}
    i1_q = by_item["viz_i1_q"]
    i1_h1 = by_item["viz_i1_h1"]
    i1_sol = by_item["viz_i1_sol"]
    i1_tbl = by_item["viz_i1_tbl"]
    i2_q = by_item["viz_i2_q"]
    assert i2_q["y"] >= i1_tbl["y"] + i1_tbl["h"]
    assert i1_h1["y"] >= i1_q["y"] + i1_q["h"]
    assert i1_sol["y"] >= i1_h1["y"] + i1_h1["h"]
    assert i1_tbl["y"] >= i1_sol["y"] + i1_sol["h"]
