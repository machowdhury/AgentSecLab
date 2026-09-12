"""Dashboard Studio contracts for LAB-MCP-001 WS-MCP-001.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001"
SEARCH_DIR = LAB_DIR / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_mcp_001.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_mcp_001_dashboard.py"

REQUIRED_IDS = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-SCOPE",
    "Q-MCP-PARAMS",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-RESULT",
    "Q-MCP-RESULT-TRUST",
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
    "session.id",
    "mcp.session.id",
    "gen_ai.tool.call.arguments",
)
REQUIRED_TOKENS = ("run_id", "baseline_run_id", "attack_run_id", "retest_run_id")
SPECIMEN_IDS = {
    "baseline_run_id": "163d11e2-e751-4282-9406-19b490542ed4",
    "attack_run_id": "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49",
    "retest_run_id": "7a1d37b5-d589-4dfd-8322-25ebd0152dbc",
}
FORBIDDEN_CLAIMS = (
    "allow = executed",
    "allow equals execution",
    "mcp.started = success",
    "mcp.failed = prevented",
    "mcp.failed is prevention",
    "no splunk row = deny",
    "unknown tool = deny",
    "known-ungranted tool = error",
    "splunk authorized",
)


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
    assert BUILDER.is_file()
    assert "ws_lab_mcp_001" in NAV_XML.read_text(encoding="utf-8")
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
        assert layout["options"]["width"] == 1440
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    assert labels == list(WORKSHOP_TABS)
    tokens = {inp["options"]["token"] for inp in definition["inputs"].values()}
    assert tokens == set(REQUIRED_TOKENS)
    for input_id in definition["inputs"]:
        assert input_id in definition["layout"]["globalInputs"]
    for token, run_id in SPECIMEN_IDS.items():
        match = [
            inp for inp in definition["inputs"].values() if inp["options"]["token"] == token
        ]
        assert match[0]["options"]["defaultValue"] == run_id
    hunt = [inp for inp in definition["inputs"].values() if inp["options"]["token"] == "run_id"][0]
    assert hunt["options"]["defaultValue"] == SPECIMEN_IDS["baseline_run_id"]
    assert hunt["title"] == "Hunt"
    assert {inp["title"] for inp in definition["inputs"].values()} == {
        "Hunt",
        "BASELINE",
        "ATTACK",
        "RETEST",
    }


def test_datasources_are_validated_spl_with_token_bind_only():
    definition = _definition()
    catalog = json.loads((SEARCH_DIR / "catalog.json").read_text(encoding="utf-8"))
    queries = {row["id"]: row for row in catalog["queries"]}
    expected = {
        "ds_q_who": (queries["Q-MCP-WHO"]["spl_file"], "run_id"),
        "ds_q_authz": (queries["Q-MCP-AUTHZ"]["spl_file"], "run_id"),
        "ds_q_tool": (queries["Q-MCP-TOOL"]["spl_file"], "run_id"),
        "ds_q_scope": (queries["Q-MCP-SCOPE"]["spl_file"], "run_id"),
        "ds_q_params": (queries["Q-MCP-PARAMS"]["spl_file"], "run_id"),
        "ds_q_executed": (queries["Q-MCP-EXECUTED"]["spl_file"], "run_id"),
        "ds_q_after_deny": (queries["Q-MCP-AFTER-DENY"]["spl_file"], "run_id"),
        "ds_q_result": (queries["Q-MCP-RESULT"]["spl_file"], "run_id"),
        "ds_q_result_trust": (queries["Q-MCP-RESULT-TRUST"]["spl_file"], "run_id"),
        "ds_q_authz_baseline": (queries["Q-MCP-AUTHZ"]["spl_file"], "baseline_run_id"),
        "ds_q_authz_attack": (queries["Q-MCP-AUTHZ"]["spl_file"], "attack_run_id"),
        "ds_q_authz_retest": (queries["Q-MCP-AUTHZ"]["spl_file"], "retest_run_id"),
        "ds_q_tool_baseline": (queries["Q-MCP-TOOL"]["spl_file"], "baseline_run_id"),
        "ds_q_tool_attack": (queries["Q-MCP-TOOL"]["spl_file"], "attack_run_id"),
        "ds_q_tool_retest": (queries["Q-MCP-TOOL"]["spl_file"], "retest_run_id"),
        "ds_q_executed_baseline": (queries["Q-MCP-EXECUTED"]["spl_file"], "baseline_run_id"),
        "ds_q_executed_attack": (queries["Q-MCP-EXECUTED"]["spl_file"], "attack_run_id"),
        "ds_q_executed_retest": (queries["Q-MCP-EXECUTED"]["spl_file"], "retest_run_id"),
    }
    for ds_id, (spl_file, token) in expected.items():
        spl = (SEARCH_DIR / spl_file).read_text(encoding="utf-8").strip()
        bound = spl.replace("__RUN_ID__", f'"${token}$"')
        assert definition["dataSources"][ds_id]["options"]["query"] == bound, ds_id
        assert definition["dataSources"][ds_id]["type"] == "ds.search"
    sim = catalog["positive_control"]
    sim_spl = (SEARCH_DIR / sim["spl_file"]).read_text(encoding="utf-8").strip()
    assert definition["dataSources"]["ds_q_after_deny_sim"]["options"]["query"] == sim_spl
    extra = {
        "ds_q_after_deny_sim",
        "ds_observe_seq",
        "ds_what_identity",
        "ds_what_decision",
        "ds_what_baseline_id",
        "ds_what_baseline_dec",
        "ds_what_attack_id",
        "ds_what_attack_dec",
        "ds_what_retest_id",
        "ds_what_retest_dec",
    }
    assert set(definition["dataSources"]) == set(expected) | extra


def test_display_searches_do_not_drift_from_validated_filter():
    definition = _definition()
    executed = (SEARCH_DIR / "Q-MCP-EXECUTED.spl").read_text(encoding="utf-8")
    assert '"event.name"=agentsec.control.decision' in executed
    assert '"event.name"=agentsec.mcp.started' in executed
    for ds_id in (
        "ds_observe_seq",
        "ds_what_identity",
        "ds_what_decision",
        "ds_what_baseline_id",
        "ds_what_baseline_dec",
        "ds_what_attack_id",
        "ds_what_attack_dec",
        "ds_what_retest_id",
        "ds_what_retest_dec",
    ):
        query = definition["dataSources"][ds_id]["options"]["query"]
        assert "index=agentsec_telemetry" in query
        assert "mvindex(mvdedup(" in query
        assert "| join " not in query
        assert "| transaction " not in query
        assert "event.name" in query
        assert "agentsec.event.name" not in query


def test_visualizations_reference_existing_datasources_and_layouts():
    definition = _definition()
    ds_ids = set(definition["dataSources"])
    viz_ids = set(definition["visualizations"])
    layout_items: set[str] = set()
    for layout in definition["layout"]["layoutDefinitions"].values():
        for item in layout["structure"]:
            layout_items.add(item["item"])
            assert item["type"] == "block"
    assert layout_items == viz_ids
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


def test_no_detections_and_security_semantics():
    blob = json.dumps(_definition()) + VIEW_XML.read_text(encoding="utf-8")
    lowered = blob.lower()
    queries = "\n".join(ds["options"]["query"] for ds in _definition()["dataSources"].values())
    for field in PROHIBITED_FIELDS:
        assert field not in queries
    assert "action.notable" not in lowered
    assert "no notable event" in lowered
    assert "cron_schedule" not in lowered
    assert "alert.track" not in lowered
    assert "ds.savedsearch" not in lowered
    assert "ds.mltk" not in lowered
    assert "not a detection" in lowered
    assert "simulated" in lowered
    assert "makeresults" in lowered
    for query_id in REQUIRED_IDS:
        assert query_id in blob
    assert "Q-MCP-AFTER-DENY-POSITIVE-CONTROL" in blob
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "does **not** ALLOW or DENY" in markdown
    assert "Runtime handler count is authoritative" in markdown
    assert "untrusted_data" in markdown
    assert "unauthorized invocation" in markdown.lower()
    assert "| Role | run.id |" not in markdown
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in lowered
    for viz in _definition()["visualizations"].values():
        if viz["type"] == "splunk.markdown":
            assert viz["options"]["fontSize"] == "large"
            assert not viz["options"]["markdown"].startswith("        #"), viz
    titles = [viz["title"] for viz in _definition()["visualizations"].values() if "title" in viz]
    assert any("SIMULATED" in title for title in titles)


def test_table_empty_copy_is_nodata_not_caption():
    """Always-visible description must not claim absence while rows can exist."""
    for viz_id, viz in _definition()["visualizations"].items():
        if viz["type"] != "splunk.table":
            continue
        desc = viz.get("description") or ""
        assert desc, viz_id
        assert not desc.startswith("No indexed"), viz_id
        no_data = viz["options"].get("noDataMessage") or ""
        assert no_data, viz_id
        assert viz.get("hideWhenNoData") is False
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "Validated specimen ids" in markdown
    learn = next(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz.get("title") == "LEARN"
    )
    assert learn.index("163d11e2-e751-4282-9406-19b490542ed4") < learn.index("Trust path")
    assert "Control `executed` stays false on ALLOW" in json.dumps(_definition())


def test_what_happened_is_split_identity_and_decision():
    definition = _definition()
    for prefix in ("baseline", "attack", "retest"):
        ident = definition["dataSources"][f"ds_what_{prefix}_id"]["options"]["query"]
        dec = definition["dataSources"][f"ds_what_{prefix}_dec"]["options"]["query"]
        assert ident.endswith("| table run_id, profile, mode, agent, tool")
        assert "execution_state" in dec
        assert "result_trust" in dec
        assert "decision" in dec
    hunt_dec = definition["dataSources"]["ds_what_decision"]["options"]["query"]
    assert "execution_state" in hunt_dec
    viz = definition["visualizations"]
    assert "viz_baseline_what_id" in viz and "viz_baseline_what_dec" in viz
    assert "viz_prove_what_id" in viz and "viz_prove_what_dec" in viz


def test_specimen_uuids_are_complete():
    blob = json.dumps(_definition())
    for run_id in SPECIMEN_IDS.values():
        assert run_id in blob
    hunt = [inp for inp in _definition()["inputs"].values() if inp["options"]["token"] == "run_id"][0]
    assert hunt["options"]["defaultValue"] == SPECIMEN_IDS["baseline_run_id"]
