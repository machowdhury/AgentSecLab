"""Dashboard Studio contracts for LAB-AGENT-DELEGATION-001.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001"
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
ID_DIR = LAB_DIR / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_agent_delegation.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_agent_delegation_dashboard.py"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
AUTHZ = ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
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
REQUIRED_TOKENS = ("run_id",)
SPECIMEN_IDS = {
    "run_id": "b419465c-84d8-4639-8449-34dd99841ba9",
    "baseline_run_id": "b419465c-84d8-4639-8449-34dd99841ba9",
    "attack_run_id": "f846be88-1f9d-4dde-ac80-193c01b47660",
    "retest_run_id": "271695f5-4739-44f2-8bf4-0749d04f4b03",
}
BASELINE_HASH = "sha256:93f1e257a7d6c7660aa8b1d1b980f1509b7da69e215b385ac79c222e1058b3eb"
ATTACK_HASH = "sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd"
FORBIDDEN_CLAIMS = (
    "authenticated=true",
    "identity_verified=true",
    "cryptographic_identity=true",
    "trusted_identity=true",
    "observe = authorization",
    "request = grant",
    "allow = execution",
    "mcp.started = success",
    "mcp.failed = prevention",
    "no splunk row = blocked",
    "splunk authorized",
    "splunk blocked",
    "splunk prevented",
    "splunk proves prevention",
    "det-mcp-001 silence = safe",
    "baseline = safe",
    "ml anomaly = incident",
)
PROHIBITED_FIELDS = (
    "agentsec.event.name",
    "agentsec.mcp.allowed_tools",
    "gen_ai.tool.call.id",
    "gen_ai.tool.call.arguments",
    "authenticated",
    "verified_identity",
    "trusted_identity",
    "cryptographic_passport_valid",
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
    assert "ws_lab_agent_delegation" in nav
    assert "ws_lab_agent_goal_integrity" in nav
    file_def = _definition()
    xml_def = _xml_definition()
    assert file_def == xml_def
    xml = VIEW_XML.read_text(encoding="utf-8")
    assert xml.startswith("<?xml")
    assert 'version="2"' in xml
    assert 'theme="light"' in xml
    assert "LAB-AGENT-DELEGATION-001" in xml


def test_ten_tabs_and_token_defaults():
    definition = _definition()
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    assert labels == list(WORKSHOP_TABS)
    tokens = {inp["options"]["token"] for inp in definition["inputs"].values()}
    assert tokens == set(REQUIRED_TOKENS)
    for input_id in definition["inputs"]:
        assert input_id in definition["layout"]["globalInputs"]
    hunt = [inp for inp in definition["inputs"].values() if inp["options"]["token"] == "run_id"][0]
    assert hunt["type"] == "input.dropdown"
    assert hunt["options"]["defaultValue"] == SPECIMEN_IDS["run_id"]
    item_values = {item["value"] for item in hunt["options"]["items"]}
    assert SPECIMEN_IDS["baseline_run_id"] in item_values
    assert SPECIMEN_IDS["attack_run_id"] in item_values
    assert SPECIMEN_IDS["retest_run_id"] in item_values
    assert hunt["title"] == "Investigate specimen"
    titles = {inp["title"] for inp in definition["inputs"].values()}
    assert titles == {"Investigate specimen"}
    for layout in definition["layout"]["layoutDefinitions"].values():
        assert layout["type"] == "grid"
        assert layout["options"]["backgroundColor"] == "#F6F8FB"
        assert layout["options"]["width"] == 1440


def test_search_reuse_bind_only():
    definition = _definition()
    queries = definition["dataSources"]
    ident = (ID_DIR / "Q-AGENT-DELEGATION-AUTHORITY.spl").read_text(encoding="utf-8").strip()
    who = (SEARCH_DIR / "Q-MCP-WHO.spl").read_text(encoding="utf-8").strip()
    authz = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8").strip()
    tool = (SEARCH_DIR / "Q-MCP-TOOL.spl").read_text(encoding="utf-8").strip()
    executed = (SEARCH_DIR / "Q-MCP-EXECUTED.spl").read_text(encoding="utf-8").strip()
    after = (SEARCH_DIR / "Q-MCP-AFTER-DENY.spl").read_text(encoding="utf-8").strip()
    expected = {
        "ds_q_id": ident.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_who": who.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_authz": authz.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_tool": tool.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_executed": executed.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_id_b": ident.replace("__RUN_ID__", f'"{SPECIMEN_IDS["baseline_run_id"]}"'),
        "ds_q_id_a": ident.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_run_id"]}"'),
        "ds_q_id_r": ident.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_run_id"]}"'),
        "ds_q_authz_b": authz.replace("__RUN_ID__", f'"{SPECIMEN_IDS["baseline_run_id"]}"'),
        "ds_q_authz_a": authz.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_run_id"]}"'),
        "ds_q_authz_r": authz.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_run_id"]}"'),
        "ds_q_tool_a": tool.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_run_id"]}"'),
        "ds_q_tool_r": tool.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_run_id"]}"'),
        "ds_q_exec_b": executed.replace("__RUN_ID__", f'"{SPECIMEN_IDS["baseline_run_id"]}"'),
        "ds_q_exec_a": executed.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_run_id"]}"'),
        "ds_q_exec_r": executed.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_run_id"]}"'),
        "ds_q_after_b": after.replace("__RUN_ID__", f'"{SPECIMEN_IDS["baseline_run_id"]}"'),
        "ds_q_after_a": after.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_run_id"]}"'),
        "ds_q_after_r": after.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_run_id"]}"'),
    }
    for ds_id, bound in expected.items():
        assert queries[ds_id]["options"]["query"] == bound, ds_id
        assert queries[ds_id]["type"] == "ds.search"
    sim = (SEARCH_DIR / "DET-MCP-001-POSITIVE-CONTROL.spl").read_text(encoding="utf-8").strip()
    assert queries["ds_det_mcp_001_sim"]["options"]["query"] == sim
    seq = queries["ds_observe_seq"]["options"]["query"]
    assert "agentsec.sequence" in seq
    assert "agentsec.identity.caller_agent_id" in seq
    assert "_raw" not in seq
    assert set(queries) == set(expected) | {"ds_det_mcp_001_sim", "ds_observe_seq"}
    for query in queries.values():
        text = query["options"]["query"]
        assert "| join " not in text
        assert "DET-A2A" not in text or "No DET-A2A" in text
        assert "Q-A2A-WHO" not in text
        for field in PROHIBITED_FIELDS:
            if field == "authenticated":
                continue
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
            assert "no attack" not in msg
    assert used_ds == ds_ids


def test_no_new_detector_and_security_semantics():
    blob = json.dumps(_definition()) + VIEW_XML.read_text(encoding="utf-8")
    lowered = blob.lower()
    assert "DET-A2A.spl" not in blob
    assert "No DET-A2A" in blob
    assert "ds.savedsearch" not in lowered
    assert "action.notable" not in lowered
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "DETECTION ANALYZED — NO NEW IDENTITY DETECTOR" in markdown
    assert "IDENTITY CLAIM IS DATA" in markdown
    assert "DELEGATION CLAIM != AUTHORIZATION" in markdown
    assert "REQUEST != GRANT" in markdown
    assert "OBSERVE != ALLOW" in markdown
    assert "ALLOW != EXECUTION" in markdown
    assert "SPLUNK != ENFORCEMENT" in markdown
    assert "WHO AUTHENTICATED = NOT PROVEN / NOT MODELED" in markdown
    assert "INTENTIONALLY VULNERABLE LAB PROFILE" in markdown
    assert "0 rows is **CORRECT**" in markdown or "0 rows is CORRECT" in markdown
    assert "0 rows != **SAFE**" in markdown or "0 rows != SAFE" in markdown
    assert "FUTURE — NOT IMPLEMENTED" in markdown
    assert "ML MUST NOT GRANT OR DENY AUTHORITY" in markdown
    assert "PLANE" in markdown
    assert BASELINE_HASH in markdown
    assert ATTACK_HASH in markdown
    assert markdown.count(ATTACK_HASH) >= 4
    assert "Do **not** label this SAFE" in markdown
    assert "incorrect claims" in lowered
    assert "caller_agent_id proves authentication" in lowered
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in lowered
    for viz in _definition()["visualizations"].values():
        if viz["type"] == "splunk.markdown":
            assert viz["options"]["fontSize"] == "large"


def test_schema_runtime_and_det_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "CTRL-MCP-001" in AUTHZ.read_text(encoding="utf-8")
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "CTRL-IDENTITY" not in det
    assert not list((ROOT / "learning").rglob("DET-A2A*"))
    dumped = json.dumps(_definition())
    assert "DET-A2A" in dumped
    assert "No DET-A2A" in dumped
    assert "1.9.0" in dumped


def test_path_a_path_b_and_live_vs_replay():
    definition = _definition()
    blob = json.dumps(definition)
    assert "Path A" in blob
    assert "Path B" in blob
    assert "viz_i1_q" in definition["visualizations"]
    assert "viz_i1_h1" in definition["visualizations"]
    assert "viz_i1_sol" in definition["visualizations"]
    hunt_layout = definition["layout"]["layoutDefinitions"]["layout_hunt"]
    assert hunt_layout["options"]["display"] == "fit-to-width"
    assert "LIVE vs REPLAY" in blob
    assert "REPLAY specimen" in blob
    assert "SAME IDENTITY CLAIM. SAME DELEGATION CLAIM. SAME PRIVILEGED REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION." in blob
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in definition["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "| Role |" not in markdown
    assert "| run.id |" not in markdown
    assert "http://127.0.0.1:5001/labs/LAB-AGENT-DELEGATION-001" in markdown
    assert "Studio tokens" in markdown or "Studio cannot receive" in markdown
