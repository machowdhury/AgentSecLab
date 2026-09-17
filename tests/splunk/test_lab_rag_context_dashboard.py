"""Dashboard Studio contracts for LAB-RAG-CONTEXT WS-RAG-CONTEXT.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT"
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RAG_DIR = LAB_DIR / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_rag_context.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_rag_context_dashboard.py"
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
REQUIRED_TOKENS = (
    "run_id",
    "baseline_run_id",
    "attack_run_id",
    "retest_run_id",
)
SPECIMEN_IDS = {
    "run_id": "51f70fb9-994e-4dd4-9b36-cac6fb1e8232",
    "baseline_run_id": "51f70fb9-994e-4dd4-9b36-cac6fb1e8232",
    "attack_run_id": "3a43d24f-9281-42f6-8375-1fb2efaa80ac",
    "retest_run_id": "bea97bae-491b-4b36-b52f-1417d2bad01b",
}
NORMAL_HASH = "sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e"
MALICIOUS_HASH = "sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef"
FORBIDDEN_CLAIMS = (
    "untrusted_data = malicious",
    "retrieval = attack",
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
    "normal = safe",
    "ml anomaly = incident",
    "the retrieved text authorized",
)
PROHIBITED_FIELDS = (
    "agentsec.event.name",
    "agentsec.mcp.allowed_tools",
    "gen_ai.tool.call.id",
    "gen_ai.tool.call.arguments",
    "trusted_document",
    "document_authorized",
    "rag_allowed_tools",
    "full_document",
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
    assert "ws_lab_rag_context" in nav
    assert "ws_lab_scanner_runtime_evidence" in nav
    file_def = _definition()
    xml_def = _xml_definition()
    assert file_def == xml_def
    xml = VIEW_XML.read_text(encoding="utf-8")
    assert xml.startswith("<?xml")
    assert 'version="2"' in xml
    assert 'theme="light"' in xml
    assert "LAB-RAG-CONTEXT" in xml


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
    titles = {inp["title"] for inp in definition["inputs"].values()}
    assert titles == {"Hunt", "BASELINE", "ATTACK", "RETEST"}
    for layout in definition["layout"]["layoutDefinitions"].values():
        assert layout["type"] == "grid"
        assert layout["options"]["backgroundColor"] == "#F6F8FB"
        assert layout["options"]["width"] == 1440


def test_search_reuse_bind_only():
    definition = _definition()
    queries = definition["dataSources"]
    rag = (RAG_DIR / "Q-RAG-CONTEXT-AUTHORITY.spl").read_text(encoding="utf-8").strip()
    who = (SEARCH_DIR / "Q-MCP-WHO.spl").read_text(encoding="utf-8").strip()
    authz = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8").strip()
    tool = (SEARCH_DIR / "Q-MCP-TOOL.spl").read_text(encoding="utf-8").strip()
    executed = (SEARCH_DIR / "Q-MCP-EXECUTED.spl").read_text(encoding="utf-8").strip()
    after = (SEARCH_DIR / "Q-MCP-AFTER-DENY.spl").read_text(encoding="utf-8").strip()
    expected = {
        "ds_q_rag": rag.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_who": who.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_authz": authz.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_tool": tool.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_executed": executed.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_rag_b": rag.replace("__RUN_ID__", '"$baseline_run_id$"'),
        "ds_q_rag_a": rag.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_rag_r": rag.replace("__RUN_ID__", '"$retest_run_id$"'),
        "ds_q_authz_b": authz.replace("__RUN_ID__", '"$baseline_run_id$"'),
        "ds_q_authz_a": authz.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_authz_r": authz.replace("__RUN_ID__", '"$retest_run_id$"'),
        "ds_q_tool_a": tool.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_tool_r": tool.replace("__RUN_ID__", '"$retest_run_id$"'),
        "ds_q_exec_b": executed.replace("__RUN_ID__", '"$baseline_run_id$"'),
        "ds_q_exec_a": executed.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_exec_r": executed.replace("__RUN_ID__", '"$retest_run_id$"'),
        "ds_q_after_b": after.replace("__RUN_ID__", '"$baseline_run_id$"'),
        "ds_q_after_a": after.replace("__RUN_ID__", '"$attack_run_id$"'),
        "ds_q_after_r": after.replace("__RUN_ID__", '"$retest_run_id$"'),
    }
    for ds_id, bound in expected.items():
        assert queries[ds_id]["options"]["query"] == bound, ds_id
        assert queries[ds_id]["type"] == "ds.search"
    sim = (SEARCH_DIR / "DET-MCP-001-POSITIVE-CONTROL.spl").read_text(encoding="utf-8").strip()
    assert queries["ds_det_mcp_001_sim"]["options"]["query"] == sim
    seq = queries["ds_observe_seq"]["options"]["query"]
    assert "agentsec.sequence" in seq
    assert "agentsec.rag.context.document.id" in seq
    assert "_raw" not in seq
    assert set(queries) == set(expected) | {"ds_det_mcp_001_sim", "ds_observe_seq"}
    for query in queries.values():
        text = query["options"]["query"]
        assert "| join " not in text
        assert "DET-RAG" not in text
        assert "Q-RAG-INJECTION" not in text
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
            assert "no attack" not in msg
    assert used_ds == ds_ids


def test_no_new_detector_and_security_semantics():
    blob = json.dumps(_definition()) + VIEW_XML.read_text(encoding="utf-8")
    lowered = blob.lower()
    assert "DET-RAG.spl" not in blob
    assert "No DET-RAG" in blob
    assert "ds.savedsearch" not in lowered
    assert "action.notable" not in lowered
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "DETECTION ANALYZED — NO NEW RAG DETECTOR" in markdown
    assert "RETRIEVED CONTENT IS DATA" in markdown
    assert "REQUEST != GRANT" in markdown
    assert "OBSERVE != ALLOW" in markdown
    assert "ALLOW != EXECUTION" in markdown
    assert "SPLUNK != ENFORCEMENT" in markdown
    assert "INTENTIONALLY VULNERABLE LAB PROFILE" in markdown
    assert "0 rows is **CORRECT**" in markdown or "0 rows is CORRECT" in markdown
    assert "0 rows != **SAFE**" in markdown or "0 rows != SAFE" in markdown
    assert "FUTURE — NOT IMPLEMENTED" in markdown
    assert "ML MUST NOT GRANT OR DENY AUTHORITY" in markdown
    assert "PLANE" in markdown or "1 RETRIEVAL" in markdown
    assert NORMAL_HASH in markdown
    assert MALICIOUS_HASH in markdown
    assert markdown.count(MALICIOUS_HASH) >= 4
    assert "Do **not** label this SAFE" in markdown
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in lowered
    for viz in _definition()["visualizations"].values():
        if viz["type"] == "splunk.markdown":
            assert viz["options"]["fontSize"] == "large"


def test_schema_runtime_and_det_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.6.0"' in schema
    assert "CTRL-MCP-001" in AUTHZ.read_text(encoding="utf-8")
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "CTRL-RAG" not in det
    assert not list((ROOT / "learning").rglob("DET-RAG*"))
    dumped = json.dumps(_definition())
    assert "DET-RAG" in dumped
    assert "No DET-RAG" in dumped
    assert "A2A" in dumped
    assert "Phase 11 not started" in dumped
