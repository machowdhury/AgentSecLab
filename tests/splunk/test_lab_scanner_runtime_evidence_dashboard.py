"""Dashboard Studio contracts for LAB-SCANNER-RUNTIME-EVIDENCE.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-SCANNER-RUNTIME-EVIDENCE"
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
CATALOG_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-CATALOG" / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_scanner_runtime_evidence.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_scanner_runtime_evidence_dashboard.py"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
AUTHZ = ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
META = ROOT / "src" / "agentsec" / "mcp" / "metadata_trust.py"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DET = SEARCH_DIR / "DET-MCP-001.spl"

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
REQUIRED_TOKENS = (
    "run_id",
    "scan_id",
    "baseline_run_id",
    "attack_run_id",
    "retest_run_id",
    "normal_scan_id",
    "malicious_scan_id",
)
SPECIMEN_IDS = {
    "run_id": "d95717ed-ffd2-46c0-a130-9a5d7d539a5d",
    "baseline_run_id": "d95717ed-ffd2-46c0-a130-9a5d7d539a5d",
    "attack_run_id": "a0937bff-31a5-453a-99bf-47d7b5148ce4",
    "retest_run_id": "23c222ea-6a87-40b7-a3e9-f12a5b572fa1",
    "scan_id": "b3061c4e-7a81-445c-8fd8-3108dd14c419",
    "normal_scan_id": "b3061c4e-7a81-445c-8fd8-3108dd14c419",
    "malicious_scan_id": "7ae3ea64-4e7a-40fe-943f-3e582bce5ee8",
}
NORMAL_HASH = "sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3"
MALICIOUS_HASH = "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"
FORBIDDEN_CLAIMS = (
    "scanner high caused execution",
    "scanner high = incident",
    "scanner finding = exploit",
    "scanner finding = execution",
    "zero findings = safe",
    "scanner pass",
    "scanner fail = deny",
    "metadata observe = authorization",
    "request = grant",
    "allow = execution",
    "mcp.started = success",
    "mcp.failed = prevention",
    "no splunk row = blocked",
    "splunk authorized",
    "splunk blocked",
    "splunk prevented",
    "simulated = live",
    "det-mcp-001 silence = safe",
)
PROHIBITED_FIELDS = (
    "agentsec.event.name",
    "agentsec.mcp.allowed_tools",
    "gen_ai.tool.call.id",
    "gen_ai.tool.call.arguments",
    "artifact.path",
)


def _definition() -> dict:
    return json.loads(DEFINITION_PATH.read_text(encoding="utf-8"))


def _xml_definition() -> dict:
    xml = VIEW_XML.read_text(encoding="utf-8")
    start = xml.index("<![CDATA[") + len("<![CDATA[")
    end = xml.index("]]>")
    return json.loads(xml[start:end].strip())


def test_files_and_nav_exist():
    assert DEFINITION_PATH.is_file()
    assert VIEW_XML.is_file()
    assert BUILDER.is_file()
    nav = NAV_XML.read_text(encoding="utf-8")
    assert "ws_lab_scanner_runtime_evidence" in nav
    assert "ws_lab_mcp_catalog" in nav
    file_def = _definition()
    xml_def = _xml_definition()
    assert file_def == xml_def
    xml = VIEW_XML.read_text(encoding="utf-8")
    assert xml.startswith("<?xml")
    assert 'version="2"' in xml
    assert 'theme="light"' in xml
    assert "LAB-SCANNER-RUNTIME" in xml


def test_ten_tabs_and_token_defaults():
    definition = _definition()
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    assert labels == list(WORKSHOP_TABS)
    tokens = {inp["options"]["token"] for inp in definition["inputs"].values()}
    assert tokens == set(REQUIRED_TOKENS)
    for input_id in definition["inputs"]:
        assert input_id in definition["layout"]["globalInputs"]
    for token, value in SPECIMEN_IDS.items():
        match = [
            inp for inp in definition["inputs"].values() if inp["options"]["token"] == token
        ]
        assert match[0]["options"]["defaultValue"] == value
    hunt = [inp for inp in definition["inputs"].values() if inp["options"]["token"] == "run_id"][0]
    assert hunt["title"] == "Hunt"
    scan_hunt = [
        inp for inp in definition["inputs"].values() if inp["options"]["token"] == "scan_id"
    ][0]
    assert scan_hunt["title"] == "Hunt scan"
    titles = {inp["title"] for inp in definition["inputs"].values()}
    assert titles == {
        "Hunt",
        "Hunt scan",
        "BASELINE RUN",
        "ATTACK RUN",
        "RETEST RUN",
        "NORMAL SCAN",
        "MALICIOUS SCAN",
    }
    for layout in definition["layout"]["layoutDefinitions"].values():
        assert layout["type"] == "grid"
        assert layout["options"]["backgroundColor"] == "#F6F8FB"
        assert layout["options"]["width"] == 1440


def test_search_reuse_bind_only():
    definition = _definition()
    queries = definition["dataSources"]
    who = (CATALOG_DIR / "Q-SCANNER-WHO.spl").read_text(encoding="utf-8").strip()
    art = (CATALOG_DIR / "Q-SCANNER-ARTIFACT.spl").read_text(encoding="utf-8").strip()
    findings = (CATALOG_DIR / "Q-SCANNER-FINDINGS.spl").read_text(encoding="utf-8").strip()
    corr = (CATALOG_DIR / "Q-SCANNER-RUNTIME-CORRELATION.spl").read_text(encoding="utf-8").strip()
    authz = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8").strip()
    tool = (SEARCH_DIR / "Q-MCP-TOOL.spl").read_text(encoding="utf-8").strip()
    executed = (SEARCH_DIR / "Q-MCP-EXECUTED.spl").read_text(encoding="utf-8").strip()
    after = (SEARCH_DIR / "Q-MCP-AFTER-DENY.spl").read_text(encoding="utf-8").strip()
    catalog = (CATALOG_DIR / "Q-MCP-CATALOG-AUTHORITY.spl").read_text(encoding="utf-8").strip()
    expected = {
        "ds_scan_who": who.replace("__SCAN_ID__", '"$scan_id$"'),
        "ds_scan_art": art.replace("__SCAN_ID__", '"$scan_id$"'),
        "ds_scan_find": findings.replace("__SCAN_ID__", '"$scan_id$"'),
        "ds_scan_who_n": who.replace("__SCAN_ID__", '"$normal_scan_id$"'),
        "ds_scan_art_n": art.replace("__SCAN_ID__", '"$normal_scan_id$"'),
        "ds_scan_find_n": findings.replace("__SCAN_ID__", '"$normal_scan_id$"'),
        "ds_scan_who_m": who.replace("__SCAN_ID__", '"$malicious_scan_id$"'),
        "ds_scan_art_m": art.replace("__SCAN_ID__", '"$malicious_scan_id$"'),
        "ds_scan_find_m": findings.replace("__SCAN_ID__", '"$malicious_scan_id$"'),
        "ds_corr_n": corr.replace("__DESCRIPTION_SHA256__", NORMAL_HASH),
        "ds_corr_m": corr.replace("__DESCRIPTION_SHA256__", MALICIOUS_HASH),
        "ds_q_authz": authz.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_tool": tool.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_executed": executed.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_catalog": catalog.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_authz_b": authz.replace("__RUN_ID__", '"$baseline_run_id$"'),
        "ds_q_authz_a": authz.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_authz_r": authz.replace("__RUN_ID__", '"$retest_run_id$"'),
        "ds_q_tool_r": tool.replace("__RUN_ID__", '"$retest_run_id$"'),
        "ds_q_exec_b": executed.replace("__RUN_ID__", '"$baseline_run_id$"'),
        "ds_q_exec_a": executed.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_exec_r": executed.replace("__RUN_ID__", '"$retest_run_id$"'),
        "ds_q_cat_b": catalog.replace("__RUN_ID__", '"$baseline_run_id$"'),
        "ds_q_cat_a": catalog.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_cat_r": catalog.replace("__RUN_ID__", '"$retest_run_id$"'),
        "ds_q_after_a": after.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_after_r": after.replace("__RUN_ID__", '"$retest_run_id$"'),
    }
    for ds_id, bound in expected.items():
        assert queries[ds_id]["options"]["query"] == bound, ds_id
        assert queries[ds_id]["type"] == "ds.search"
    sim = (SEARCH_DIR / "DET-MCP-001-POSITIVE-CONTROL.spl").read_text(encoding="utf-8").strip()
    assert queries["ds_det_mcp_001_sim"]["options"]["query"] == sim
    assert set(queries) == set(expected) | {"ds_det_mcp_001_sim"}
    for query in queries.values():
        text = query["options"]["query"]
        assert "| join " not in text
        assert "DET-SCANNER" not in text
        assert "DET-MCP-CATALOG" not in text
        for field in PROHIBITED_FIELDS:
            assert field not in text


def test_visualizations_cover_datasources_and_empty_states():
    definition = _definition()
    ds_ids = set(definition["dataSources"])
    viz_ids = set(definition["visualizations"])
    layout_items: set[str] = set()
    for layout in definition["layout"]["layoutDefinitions"].values():
        for item in layout["structure"]:
            layout_items.add(item["item"])
    assert layout_items == viz_ids
    used_ds = set()
    for viz in definition["visualizations"].values():
        assert viz["type"] in {"splunk.markdown", "splunk.table"}
        if viz["type"] == "splunk.table":
            used_ds.add(viz["dataSources"]["primary"])
            assert viz.get("hideWhenNoData") is False
            msg = viz["options"]["noDataMessage"].lower()
            assert "is safe" not in msg
            assert "was blocked" not in msg
            assert "was prevented" not in msg
            assert "is trusted" not in msg
            assert "scanner passed" not in msg
    assert used_ds == ds_ids


def test_no_new_detector_and_security_semantics():
    blob = json.dumps(_definition()) + VIEW_XML.read_text(encoding="utf-8")
    lowered = blob.lower()
    assert "DET-SCANNER.spl" not in blob
    assert "No DET-SCANNER" in blob
    assert "DET-MCP-CATALOG.spl" not in blob
    assert "No DET-MCP-CATALOG" in blob
    assert "DET-MCP-005" not in blob or "No DET-MCP-005" in blob
    assert "ds.savedsearch" not in lowered
    assert "action.notable" not in lowered
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in markdown
    assert "SCANNER FINDING != AUTHORIZATION DECISION" in markdown
    assert "ZERO FINDINGS != SAFE" in markdown
    assert "INTENTIONALLY VULNERABLE" in markdown
    assert "Scanner HIGH caused execution" not in markdown
    assert "does **not** feed CTRL-MCP-001" in markdown
    assert "does **not** ALLOW or DENY" in markdown
    assert "INV-002" in markdown
    assert "1.5.0" in markdown
    assert NORMAL_HASH in markdown
    assert MALICIOUS_HASH in markdown
    assert markdown.count(MALICIOUS_HASH) >= 4
    assert "PLANE 1" in markdown and "PLANE 2" in markdown and "PLANE 3" in markdown
    assert "CONTEXT / HUNT" in markdown
    assert "REJECT" in markdown
    assert "SIMULATED" in markdown
    assert "not display PASS" in markdown.lower() or "Do **not** display PASS" in markdown
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in lowered
    for viz in _definition()["visualizations"].values():
        if viz["type"] == "splunk.markdown":
            assert viz["options"]["fontSize"] == "large"


def test_schema_runtime_and_det_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.7.0"' in schema
    assert "agentsec.scanner" not in schema
    assert "CTRL-MCP-001" in AUTHZ.read_text(encoding="utf-8")
    assert "CTRL-MCP-METADATA-001" in META.read_text(encoding="utf-8")
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "scanner" not in det.lower()
    assert not list((ROOT / "learning").rglob("DET-SCANNER*"))
    assert not list((ROOT / "learning").rglob("DET-MCP-CATALOG*"))
    assert "Agent Scan" not in json.dumps(_definition())
    dumped = json.dumps(_definition())
    assert "A2A" not in dumped


def test_sourcetype_boundaries_in_queries():
    definition = _definition()
    scanner_ds = (
        "ds_scan_who",
        "ds_scan_art",
        "ds_scan_find",
        "ds_scan_who_n",
        "ds_scan_art_n",
        "ds_scan_find_n",
        "ds_scan_who_m",
        "ds_scan_art_m",
        "ds_scan_find_m",
    )
    runtime_ds = (
        "ds_q_authz",
        "ds_q_tool",
        "ds_q_executed",
        "ds_q_catalog",
        "ds_q_authz_b",
        "ds_q_authz_a",
        "ds_q_authz_r",
        "ds_q_tool_r",
        "ds_q_exec_b",
        "ds_q_exec_a",
        "ds_q_exec_r",
        "ds_q_cat_b",
        "ds_q_cat_a",
        "ds_q_cat_r",
        "ds_q_after_a",
        "ds_q_after_r",
    )
    for ds_id in scanner_ds:
        query = definition["dataSources"][ds_id]["options"]["query"]
        assert "sourcetype=agentsec:scanner:finding" in query
        assert "sourcetype=otel:agentic:json" not in query
    for ds_id in runtime_ds:
        query = definition["dataSources"][ds_id]["options"]["query"]
        assert "sourcetype=otel:agentic:json" in query
        assert "agentsec:scanner:finding" not in query
    corr = definition["dataSources"]["ds_corr_n"]["options"]["query"]
    assert "agentsec:scanner:finding" in corr
    assert "otel:agentic:json" in corr
    assert NORMAL_HASH in corr
    assert MALICIOUS_HASH in definition["dataSources"]["ds_corr_m"]["options"]["query"]
