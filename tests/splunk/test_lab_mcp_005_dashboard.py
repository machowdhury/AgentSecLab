"""Dashboard Studio contracts for LAB-MCP-005 WS-MCP-005.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-005"
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RESULT_DIR = LAB_DIR / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_mcp_005.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_mcp_005_dashboard.py"

REQUIRED_IDS = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-RESULT",
    "Q-MCP-RESULT-TRUST",
    "Q-MCP-RESULT-AUTHORITY",
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
    "agentsec.mcp.allowed_tools",
    "gen_ai.tool.call.id",
    "result.authorized",
    "trusted_result",
)
REQUIRED_TOKENS = (
    "run_id",
    "baseline_run_id",
    "attack_run_id",
    "retest_run_id",
)
SPECIMEN_IDS = {
    "baseline_run_id": "3013aa39-fe08-4b58-9898-f3abb092ac06",
    "attack_run_id": "f3f48182-df57-4b38-b069-17a199dc4939",
    "retest_run_id": "0ab10594-a7fc-48b6-81bf-4cbca54a64c6",
}
FORBIDDEN_CLAIMS = (
    "allow = executed",
    "allow equals execution",
    "mcp.started = success",
    "mcp.failed = prevented",
    "mcp.failed is prevention",
    "no splunk row = deny",
    "splunk blocked",
    "splunk prevented",
    "the detector caught mcp-005",
    "the result was trusted",
    "hash proves the result is safe",
    "allow proves execution",
    "server granted lookup_customer_tier",
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
    assert "ws_lab_mcp_005" in NAV_XML.read_text(encoding="utf-8")
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
    result_catalog = json.loads((RESULT_DIR / "catalog.json").read_text(encoding="utf-8"))
    result_query = result_catalog["queries"][0]
    assert result_query["id"] == "Q-MCP-RESULT-AUTHORITY"
    expected = {
        "ds_q_who": (SEARCH_DIR / queries["Q-MCP-WHO"]["spl_file"], "run_id"),
        "ds_q_authz": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], "run_id"),
        "ds_q_tool": (SEARCH_DIR / queries["Q-MCP-TOOL"]["spl_file"], "run_id"),
        "ds_q_executed": (SEARCH_DIR / queries["Q-MCP-EXECUTED"]["spl_file"], "run_id"),
        "ds_q_after_deny": (SEARCH_DIR / queries["Q-MCP-AFTER-DENY"]["spl_file"], "run_id"),
        "ds_q_result": (SEARCH_DIR / queries["Q-MCP-RESULT"]["spl_file"], "run_id"),
        "ds_q_result_trust": (SEARCH_DIR / queries["Q-MCP-RESULT-TRUST"]["spl_file"], "run_id"),
        "ds_q_result_authority": (RESULT_DIR / result_query["spl_file"], "run_id"),
        "ds_q_authz_baseline": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], "baseline_run_id"),
        "ds_q_authz_attack": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], "attack_run_id"),
        "ds_q_authz_retest": (SEARCH_DIR / queries["Q-MCP-AUTHZ"]["spl_file"], "retest_run_id"),
        "ds_q_authority_baseline": (RESULT_DIR / result_query["spl_file"], "baseline_run_id"),
        "ds_q_authority_attack": (RESULT_DIR / result_query["spl_file"], "attack_run_id"),
        "ds_q_authority_retest": (RESULT_DIR / result_query["spl_file"], "retest_run_id"),
        "ds_q_tool_baseline": (SEARCH_DIR / queries["Q-MCP-TOOL"]["spl_file"], "baseline_run_id"),
        "ds_q_tool_attack": (SEARCH_DIR / queries["Q-MCP-TOOL"]["spl_file"], "attack_run_id"),
        "ds_q_tool_retest": (SEARCH_DIR / queries["Q-MCP-TOOL"]["spl_file"], "retest_run_id"),
        "ds_q_executed_baseline": (SEARCH_DIR / queries["Q-MCP-EXECUTED"]["spl_file"], "baseline_run_id"),
        "ds_q_executed_attack": (SEARCH_DIR / queries["Q-MCP-EXECUTED"]["spl_file"], "attack_run_id"),
        "ds_q_executed_retest": (SEARCH_DIR / queries["Q-MCP-EXECUTED"]["spl_file"], "retest_run_id"),
        "ds_what_baseline": (RESULT_DIR / result_query["spl_file"], "baseline_run_id"),
        "ds_what_attack": (RESULT_DIR / result_query["spl_file"], "attack_run_id"),
        "ds_what_retest": (RESULT_DIR / result_query["spl_file"], "retest_run_id"),
    }
    for ds_id, (spl_path, token) in expected.items():
        spl = spl_path.read_text(encoding="utf-8").strip()
        bound = spl.replace("__RUN_ID__", f'"${token}$"')
        assert definition["dataSources"][ds_id]["options"]["query"] == bound, ds_id
        assert definition["dataSources"][ds_id]["type"] == "ds.search"
    sim_spl = (SEARCH_DIR / "DET-MCP-001-POSITIVE-CONTROL.spl").read_text(encoding="utf-8").strip()
    assert definition["dataSources"]["ds_det_mcp_001_sim"]["options"]["query"] == sim_spl
    extra = {
        "ds_det_mcp_001_sim",
        "ds_observe_seq",
    }
    assert set(definition["dataSources"]) == set(expected) | extra


def test_display_searches_do_not_drift_from_validated_filter():
    definition = _definition()
    seq = definition["dataSources"]["ds_observe_seq"]["options"]["query"]
    assert "agentsec.mcp.requested_scope" in seq
    assert "agentsec.mcp.allowed_scope" in seq
    assert "agentsec.hop.index" in seq
    assert "agentsec.mcp.result.trust" in seq
    assert '"event.name"=agentsec.control.decision' in seq
    assert '"event.name"=agentsec.mcp.started' in seq
    for ds_id in ("ds_observe_seq",):
        query = definition["dataSources"][ds_id]["options"]["query"]
        assert "index=agentsec_telemetry" in query
        assert "mvindex(mvdedup(" in query
        assert "| join " not in query
        assert "| transaction " not in query
        assert "| map " not in query
        assert "event.name" in query
        assert "agentsec.event.name" not in query
        assert "agentsec.mcp.allowed_tools" not in query
        assert "gen_ai.tool.call.id" not in query


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
    assert "DET-MCP-005.spl" not in blob
    assert "action.notable" not in lowered
    assert "ds.savedsearch" not in lowered
    assert "ds.mltk" not in lowered
    assert "does not enable" in lowered
    assert "det-mcp-001" in lowered
    assert "simulated" in lowered
    assert "makeresults" in lowered
    assert "DET-MCP-001-POSITIVE-CONTROL" in blob
    assert "Q-MCP-RESULT-AUTHORITY" in blob
    for query_id in REQUIRED_IDS:
        assert query_id in blob
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "does **not** ALLOW or DENY" in markdown
    assert "Runtime handler count is authoritative" in markdown
    assert "INV-002" in markdown
    assert "DATA" in markdown and "AUTHORITY" in markdown
    assert "DETECTION ANALYZED" in markdown
    assert "NO NEW DETECTOR" in markdown
    assert "No DET-MCP-005" in markdown or "**No DET-MCP-005.**" in markdown
    assert "INTENTIONALLY VULNERABLE" in markdown
    assert "SERVER AUTHORITY EVIDENCE — LIMITED" in markdown
    assert "BOUNDED" in markdown
    assert "lookup_customer_tie" in markdown
    assert "not published" in markdown.lower()
    assert "Q-MCP-RESULT-FOLLOWON" in markdown
    assert "schema" in markdown.lower() and "1.3.0" in markdown
    assert "prompt-injection" in markdown.lower()
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in lowered
    for viz in _definition()["visualizations"].values():
        if viz["type"] == "splunk.markdown":
            assert viz["options"]["fontSize"] == "large"
            assert not viz["options"]["markdown"].startswith("        #"), viz
    titles = [viz["title"] for viz in _definition()["visualizations"].values() if "title" in viz]
    assert any("SIMULATED" in title for title in titles)
    ds_names = set(_definition()["dataSources"])
    assert not any("followon" in name.lower() and "authority" not in name.lower() for name in ds_names)
    assert not any("det_mcp_005" in name.lower() for name in ds_names)


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
        lowered = no_data.lower()
        assert "handler never ran" not in lowered
        assert "control worked" not in lowered
        assert "no security violation" not in lowered
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "3013aa39-fe08-4b58-9898-f3abb092ac06" in markdown
    learn = next(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz.get("title") == "LEARN"
    )
    assert learn.index("3013aa39-fe08-4b58-9898-f3abb092ac06") < learn.index("**Path:**") if "**Path:**" in learn else True
    assert "Control executed stays false on ALLOW" in json.dumps(_definition())


def test_what_happened_is_result_authority():
    definition = _definition()
    for ds_id in ("ds_what_baseline", "ds_what_attack", "ds_what_retest", "ds_q_result_authority"):
        query = definition["dataSources"][ds_id]["options"]["query"]
        assert "derived_authority" in query
        assert "followon_execution_observation" in query
        assert "result_derived_grant" in query
        assert "CTRL-MCP-RESULT-001" in query
    viz = definition["visualizations"]
    assert "viz_baseline_what" in viz
    assert "viz_attack_what" in viz
    assert "viz_retest_what" in viz
    assert "viz_prove_what" in viz
    assert viz["viz_prove_what"]["dataSources"]["primary"] == "ds_q_result_authority"


def test_specimen_uuids_and_hashes_are_complete():
    blob = json.dumps(_definition())
    for run_id in SPECIMEN_IDS.values():
        assert run_id in blob
    assert "sha256:f7d67b151741ef7c7efb60242b96f8325996709128293da424f53a547230c358" in blob
    assert "sha256:2c258a80464ede4113e7721119bc6a908951b8b723c61489ac27b737cdbeb68e" in blob
    hunt = [inp for inp in _definition()["inputs"].values() if inp["options"]["token"] == "run_id"][0]
    assert hunt["options"]["defaultValue"] == SPECIMEN_IDS["baseline_run_id"]


def test_det_mcp_001_file_is_not_rewritten():
    det = (SEARCH_DIR / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    blob = json.dumps(_definition())
    assert det.strip() not in blob
    assert "DET-MCP-001-POSITIVE-CONTROL" in blob
    assert "No DET-MCP-005" in blob or "no DET-MCP-005" in blob
    assert not list(LAB_DIR.glob("searches/DET-MCP-005.*"))
    assert not list(LAB_DIR.glob("searches/Q-MCP-RESULT-FOLLOWON.*"))


def test_q_mcp_source_files_unchanged_by_bind():
    original = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8")
    assert "__RUN_ID__" in original
    bound = _definition()["dataSources"]["ds_q_authz"]["options"]["query"]
    assert original.strip() != bound
    assert (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8") == original
    result = (RESULT_DIR / "Q-MCP-RESULT-AUTHORITY.spl").read_text(encoding="utf-8")
    assert "__RUN_ID__" in result
    assert result.strip() != _definition()["dataSources"]["ds_q_result_authority"]["options"]["query"]


def test_rejected_spl_is_not_a_datasource():
    definition = _definition()
    queries = "\n".join(ds["options"]["query"] for ds in definition["dataSources"].values())
    names = " ".join(definition["dataSources"])
    assert "Q-MCP-RESULT-FOLLOWON" not in names
    assert "followon_tool" in queries
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in definition["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "Q-MCP-RESULT-FOLLOWON" in markdown
    assert "not published" in markdown.lower() or "rejected" in markdown.lower()
