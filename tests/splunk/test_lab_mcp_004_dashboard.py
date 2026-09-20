"""Dashboard Studio contracts for LAB-MCP-004 WS-MCP-004.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-004"
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RESOURCE_DIR = LAB_DIR / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_mcp_004.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_mcp_004_dashboard.py"

REQUIRED_IDS = (
    "Q-MCP-AUTHZ",
    "Q-MCP-SCOPE",
    "Q-MCP-RESOURCE-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
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
    "effective_resource",
    "resource.authorized",
)
REQUIRED_TOKENS = ("run_id",)
SPECIMEN_IDS = {
    "baseline_run_id": "fb50dcaf-8e84-4a3f-a55b-997c72edbd04",
    "attack_run_id": "5ab59fc7-303e-4eea-84e7-ae0b2f405146",
    "retest_run_id": "0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd",
    "unknown_run_id": "0e4e0051-528d-4bf3-8773-d1fb55a5864f",
}
FORBIDDEN_CLAIMS = (
    "allow = executed",
    "allow equals execution",
    "mcp.started = success",
    "mcp.failed = prevented",
    "mcp.failed is prevention",
    "no splunk row = deny",
    "unknown = deny",
    "unknown_resource is deny",
    "known-but-ungranted = unknown",
    "tool granted = resource granted",
    "scope granted = resource granted",
    "allowed_resource.ids changed",
    "splunk authorized",
    "resource attack blocked",
    "valid argument = authorized",
    "simulated = observed",
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
    assert "ws_lab_mcp_004" in NAV_XML.read_text(encoding="utf-8")
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
    hunt_inp = [inp for inp in definition["inputs"].values() if inp["options"]["token"] == "run_id"][0]
    assert hunt_inp["type"] == "input.dropdown"
    assert hunt_inp["options"]["defaultValue"] == SPECIMEN_IDS.get("run_id", SPECIMEN_IDS["baseline_run_id"])
    item_values = {item["value"] for item in hunt_inp["options"]["items"]}
    assert SPECIMEN_IDS["baseline_run_id"] in item_values
    assert SPECIMEN_IDS["attack_run_id"] in item_values
    assert SPECIMEN_IDS["retest_run_id"] in item_values
    hunt = [inp for inp in definition["inputs"].values() if inp["options"]["token"] == "run_id"][0]
    assert hunt["options"]["defaultValue"] == SPECIMEN_IDS["baseline_run_id"]
    assert hunt["title"] == "Investigate specimen"
    assert {inp["title"] for inp in definition["inputs"].values()} == {"Investigate specimen"}


def test_datasources_are_validated_spl_with_token_bind_only():
    definition = _definition()
    catalog = json.loads((SEARCH_DIR / "catalog.json").read_text(encoding="utf-8"))
    queries = {row["id"]: row for row in catalog["queries"]}
    resource_catalog = json.loads((RESOURCE_DIR / "catalog.json").read_text(encoding="utf-8"))
    resource_query = resource_catalog["queries"][0]
    assert resource_query["id"] == "Q-MCP-RESOURCE-AUTHZ"
    expected = {
        "ds_q_authz": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], "run_id"),
        "ds_q_scope": (SEARCH_DIR / queries["Q-MCP-SCOPE"]["spl_file"], "run_id"),
        "ds_q_tool": (SEARCH_DIR / queries["Q-MCP-TOOL"]["spl_file"], "run_id"),
        "ds_q_executed": (SEARCH_DIR / queries["Q-MCP-EXECUTED"]["spl_file"], "run_id"),
        "ds_q_after_deny": (SEARCH_DIR / queries["Q-MCP-AFTER-DENY"]["spl_file"], "run_id"),
        "ds_q_resource": (RESOURCE_DIR / resource_query["spl_file"], "run_id"),
        "ds_q_authz_baseline": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], SPECIMEN_IDS["baseline_run_id"]),
        "ds_q_authz_attack": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], SPECIMEN_IDS["attack_run_id"]),
        "ds_q_authz_retest": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], SPECIMEN_IDS["retest_run_id"]),
        "ds_q_authz_unknown": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], SPECIMEN_IDS["unknown_run_id"]),
        "ds_q_resource_baseline": (RESOURCE_DIR / resource_query["spl_file"], SPECIMEN_IDS["baseline_run_id"]),
        "ds_q_resource_attack": (RESOURCE_DIR / resource_query["spl_file"], SPECIMEN_IDS["attack_run_id"]),
        "ds_q_resource_retest": (RESOURCE_DIR / resource_query["spl_file"], SPECIMEN_IDS["retest_run_id"]),
        "ds_q_resource_unknown": (RESOURCE_DIR / resource_query["spl_file"], SPECIMEN_IDS["unknown_run_id"]),
        "ds_q_tool_baseline": (SEARCH_DIR / queries["Q-MCP-TOOL"]["spl_file"], SPECIMEN_IDS["baseline_run_id"]),
        "ds_q_tool_attack": (SEARCH_DIR / queries["Q-MCP-TOOL"]["spl_file"], SPECIMEN_IDS["attack_run_id"]),
        "ds_q_tool_retest": (SEARCH_DIR / queries["Q-MCP-TOOL"]["spl_file"], SPECIMEN_IDS["retest_run_id"]),
        "ds_q_executed_baseline": (SEARCH_DIR / queries["Q-MCP-EXECUTED"]["spl_file"], SPECIMEN_IDS["baseline_run_id"]),
        "ds_q_executed_attack": (SEARCH_DIR / queries["Q-MCP-EXECUTED"]["spl_file"], SPECIMEN_IDS["attack_run_id"]),
        "ds_q_executed_retest": (SEARCH_DIR / queries["Q-MCP-EXECUTED"]["spl_file"], SPECIMEN_IDS["retest_run_id"]),
    }
    for ds_id, (spl_path, token) in expected.items():
        spl = spl_path.read_text(encoding="utf-8").strip()
        bound = spl.replace("__RUN_ID__", f'"${token}$"' if token == "run_id" else f'"{token}"')
        assert definition["dataSources"][ds_id]["options"]["query"] == bound, ds_id
        assert definition["dataSources"][ds_id]["type"] == "ds.search"
    fixture = resource_catalog["detection"]["resource_teaching_fixture"]
    sim_spl = (RESOURCE_DIR / fixture["spl_file"]).read_text(encoding="utf-8").strip()
    assert definition["dataSources"]["ds_det_mcp_001_resource_sim"]["options"]["query"] == sim_spl
    extra = {
        "ds_det_mcp_001_resource_sim",
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
    seq = definition["dataSources"]["ds_observe_seq"]["options"]["query"]
    assert "agentsec.mcp.requested_scope" in seq
    assert "agentsec.mcp.allowed_scope" in seq
    assert "agentsec.mcp.resource.id" in seq
    assert "agentsec.mcp.allowed_resource.ids" in seq
    assert '"event.name"=agentsec.control.decision' in seq
    assert '"event.name"=agentsec.mcp.started' in seq
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
        assert "| map " not in query
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


def test_no_duplicate_searches_and_security_semantics():
    blob = json.dumps(_definition()) + VIEW_XML.read_text(encoding="utf-8")
    lowered = blob.lower()
    queries = "\n".join(ds["options"]["query"] for ds in _definition()["dataSources"].values())
    for field in PROHIBITED_FIELDS:
        assert field not in queries
    assert "DET-MCP-004.spl" not in blob
    assert "Q-MCP-004" not in blob
    assert "action.notable" not in lowered
    assert "no notable event" in lowered
    assert "ds.savedsearch" not in lowered
    assert "ds.mltk" not in lowered
    assert "does not enable" in lowered
    assert "det-mcp-001" in lowered
    assert "simulated" in lowered
    assert "makeresults" in lowered
    assert "DET-MCP-001-RESOURCE-POSITIVE-CONTROL" in blob
    assert "Q-MCP-RESOURCE-AUTHZ" in blob
    for query_id in REQUIRED_IDS:
        assert query_id in blob
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "does **not** ALLOW or DENY" in markdown
    assert "Runtime handler count is authoritative" in markdown
    assert "May the agent call this **tool**" in markdown
    assert "this resource" in markdown.lower()
    assert "executive-restricted" in markdown
    assert "does-not-exist" in markdown
    assert "unknown_resource" in markdown
    assert "AllowTicket" in markdown
    assert "malformed_arguments" in markdown
    assert "duplicate_json_keys" in markdown
    assert "| Role | run.id |" not in markdown
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in lowered
    for viz in _definition()["visualizations"].values():
        if viz["type"] == "splunk.markdown":
            assert viz["options"]["fontSize"] == "large"
            assert not viz["options"]["markdown"].startswith("        #"), viz
    titles = [viz["title"] for viz in _definition()["visualizations"].values() if "title" in viz]
    assert any("SIMULATED" in title for title in titles)
    assert "schema" in markdown and "1.2.0" in markdown


def test_table_empty_copy_is_nodata_not_caption():
    for viz_id, viz in _definition()["visualizations"].items():
        if viz["type"] != "splunk.table":
            continue
        desc = viz.get("description") or ""
        assert desc, viz_id
        assert not desc.startswith("No indexed"), viz_id
        no_data = viz["options"].get("noDataMessage") or ""
        assert no_data, viz_id
        assert viz.get("hideWhenNoData") is False
        assert "resource attack blocked" not in no_data.lower()
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "Evidence identity" in markdown
    learn = next(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz.get("title") == "LEARN"
    )
    assert learn.index("fb50dcaf-8e84-4a3f-a55b-997c72edbd04") < learn.index("**Path:**")
    assert "Control executed stays false on ALLOW" in json.dumps(_definition())


def test_what_happened_is_split_identity_and_decision():
    definition = _definition()
    for prefix in ("baseline", "attack", "retest"):
        ident = definition["dataSources"][f"ds_what_{prefix}_id"]["options"]["query"]
        dec = definition["dataSources"][f"ds_what_{prefix}_dec"]["options"]["query"]
        assert ident.endswith("| table run_id, profile, mode, agent, tool")
        assert "execution_state" in dec
        assert "requested_scope" in dec
        assert "allowed_scope" in dec
        assert "resource_id" in dec
        assert "allowed_resource_ids" in dec
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


def test_det_mcp_001_file_is_not_rewritten():
    det = (SEARCH_DIR / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    blob = json.dumps(_definition())
    assert det.strip() not in blob
    assert "DET-MCP-001-RESOURCE-POSITIVE-CONTROL" in blob
    assert "DET-MCP-004" in blob
    assert not list(LAB_DIR.glob("searches/DET-MCP-004.*"))


def test_q_mcp_source_files_unchanged_by_bind():
    original = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8")
    assert "__RUN_ID__" in original
    bound = _definition()["dataSources"]["ds_q_authz"]["options"]["query"]
    assert original.strip() != bound
    assert (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8") == original
    resource = (RESOURCE_DIR / "Q-MCP-RESOURCE-AUTHZ.spl").read_text(encoding="utf-8")
    assert "__RUN_ID__" in resource
    assert resource.strip() != _definition()["dataSources"]["ds_q_resource"]["options"]["query"]
