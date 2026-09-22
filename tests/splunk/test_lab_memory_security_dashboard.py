"""Dashboard Studio contracts for LAB-MEMORY-001 WS-MEMORY-SECURITY.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-MEMORY-001"
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
MEMORY_DIR = LAB_DIR / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_memory_security.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_memory_security_dashboard.py"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
AUTHZ = ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DET = SEARCH_DIR / "DET-MCP-001.spl"
RAG_VIEW = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_rag_context.xml"
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
REQUIRED_TOKENS = ("write_run_id", "run_id")
SPECIMEN_IDS = {
    "write_run_id": "a8407246-7992-4ad8-bd02-cb701e150f30",
    "run_id": "914c41ce-5123-49eb-892c-c948295dbc46",
    "baseline_write_run_id": "a8407246-7992-4ad8-bd02-cb701e150f30",
    "baseline_recall_run_id": "914c41ce-5123-49eb-892c-c948295dbc46",
    "attack_write_run_id": "05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464",
    "attack_recall_run_id": "b8737cd9-9b6b-48f2-acfa-178ae1446ddc",
    "retest_write_run_id": "060a0a72-ceb5-4b99-8330-98de81d8ae5e",
    "retest_recall_run_id": "5d5b9d1b-092d-4ddb-8422-4092d289cd49",
}
NORMAL_HASH = "sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b"
MALICIOUS_HASH = "sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9"
FORBIDDEN_CLAIMS = (
    "untrusted_data = malicious",
    "recall = attack",
    "write = compromise",
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
    "the memory authorized",
    "memory itself granted",
)
PROHIBITED_FIELDS = (
    "agentsec.event.name",
    "agentsec.mcp.allowed_tools",
    "gen_ai.tool.call.id",
    "gen_ai.tool.call.arguments",
    "trusted_memory",
    "memory_authorized",
    "session.id",
    "invocation.id",
    "full_memory",
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
    assert "ws_lab_memory_security" in nav
    assert "ws_lab_rag_context" in nav
    file_def = _definition()
    xml_def = _xml_definition()
    assert file_def == xml_def
    xml = VIEW_XML.read_text(encoding="utf-8")
    assert xml.startswith("<?xml")
    assert 'version="2"' in xml
    assert 'theme="light"' in xml
    assert "LAB-MEMORY-001" in xml


def test_ten_tabs_and_token_defaults():
    definition = _definition()
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    assert labels == list(WORKSHOP_TABS)
    tokens = {inp["options"]["token"] for inp in definition["inputs"].values()}
    assert tokens == set(REQUIRED_TOKENS)
    for input_id in definition["inputs"]:
        assert input_id in definition["layout"]["globalInputs"]
    for token in REQUIRED_TOKENS:
        match = [
            inp for inp in definition["inputs"].values() if inp["options"]["token"] == token
        ]
        assert match[0]["options"]["defaultValue"] == SPECIMEN_IDS[token]
    hunt_recall = [
        inp for inp in definition["inputs"].values() if inp["options"]["token"] == "run_id"
    ][0]
    assert hunt_recall["title"] == "Investigate recall specimen"
    hunt_write = [
        inp for inp in definition["inputs"].values() if inp["options"]["token"] == "write_run_id"
    ][0]
    assert hunt_write["title"] == "Investigate write specimen"
    titles = {inp["title"] for inp in definition["inputs"].values()}
    assert titles == {
        "Investigate write specimen",
        "Investigate recall specimen",
    }
    for inp in definition["inputs"].values():
        assert inp["type"] == "input.dropdown"
    for layout in definition["layout"]["layoutDefinitions"].values():
        assert layout["type"] == "grid"
        assert layout["options"]["backgroundColor"] == "#F6F8FB"
        assert layout["options"]["width"] == 1440


def test_search_reuse_bind_only():
    definition = _definition()
    queries = definition["dataSources"]
    mem = (MEMORY_DIR / "Q-MEMORY-CONTEXT-AUTHORITY.spl").read_text(encoding="utf-8").strip()
    who = (SEARCH_DIR / "Q-MCP-WHO.spl").read_text(encoding="utf-8").strip()
    authz = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8").strip()
    tool = (SEARCH_DIR / "Q-MCP-TOOL.spl").read_text(encoding="utf-8").strip()
    executed = (SEARCH_DIR / "Q-MCP-EXECUTED.spl").read_text(encoding="utf-8").strip()
    after = (SEARCH_DIR / "Q-MCP-AFTER-DENY.spl").read_text(encoding="utf-8").strip()

    def bind_mem(write_tok: str, recall_tok: str) -> str:
        return mem.replace("__WRITE_RUN_ID__", f'"${write_tok}$"').replace(
            "__RECALL_RUN_ID__", f'"${recall_tok}$"'
        )

    def bind_mem_literal(write_id: str, recall_id: str) -> str:
        return mem.replace("__WRITE_RUN_ID__", f'"{write_id}"').replace(
            "__RECALL_RUN_ID__", f'"{recall_id}"'
        )

    expected = {
        "ds_q_mem": bind_mem("write_run_id", "run_id"),
        "ds_q_who": who.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_authz": authz.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_tool": tool.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_executed": executed.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_mem_b": bind_mem_literal(
            SPECIMEN_IDS["baseline_write_run_id"], SPECIMEN_IDS["baseline_recall_run_id"]
        ),
        "ds_q_mem_a": bind_mem_literal(
            SPECIMEN_IDS["attack_write_run_id"], SPECIMEN_IDS["attack_recall_run_id"]
        ),
        "ds_q_mem_r": bind_mem_literal(
            SPECIMEN_IDS["retest_write_run_id"], SPECIMEN_IDS["retest_recall_run_id"]
        ),
        "ds_q_authz_b": authz.replace("__RUN_ID__", f'"{SPECIMEN_IDS["baseline_recall_run_id"]}"'),
        "ds_q_authz_a": authz.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_recall_run_id"]}"'),
        "ds_q_authz_r": authz.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_recall_run_id"]}"'),
        "ds_q_tool_a": tool.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_recall_run_id"]}"'),
        "ds_q_tool_r": tool.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_recall_run_id"]}"'),
        "ds_q_exec_b": executed.replace("__RUN_ID__", f'"{SPECIMEN_IDS["baseline_recall_run_id"]}"'),
        "ds_q_exec_a": executed.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_recall_run_id"]}"'),
        "ds_q_exec_r": executed.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_recall_run_id"]}"'),
        "ds_q_after_b": after.replace("__RUN_ID__", f'"{SPECIMEN_IDS["baseline_recall_run_id"]}"'),
        "ds_q_after_a": after.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_recall_run_id"]}"'),
        "ds_q_after_r": after.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_recall_run_id"]}"'),
    }
    for ds_id, bound in expected.items():
        assert queries[ds_id]["options"]["query"] == bound, ds_id
        assert queries[ds_id]["type"] == "ds.search"
    sim = (SEARCH_DIR / "DET-MCP-001-POSITIVE-CONTROL.spl").read_text(encoding="utf-8").strip()
    assert queries["ds_det_mcp_001_sim"]["options"]["query"] == sim
    write_seq = queries["ds_observe_write"]["options"]["query"]
    recall_seq = queries["ds_observe_recall"]["options"]["query"]
    assert "agentsec.memory.id" in write_seq
    assert "agentsec.sequence" in recall_seq
    assert "_raw" not in write_seq
    assert "_raw" not in recall_seq
    assert set(queries) == set(expected) | {
        "ds_det_mcp_001_sim",
        "ds_observe_write",
        "ds_observe_recall",
    }
    for query in queries.values():
        text = query["options"]["query"]
        assert "| join " not in text
        assert "DET-MEMORY" not in text
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
            assert "no indexed event matched this evidence question" in msg or "simulated" in msg
    assert used_ds == ds_ids


def test_no_new_detector_and_security_semantics():
    blob = json.dumps(_definition()) + VIEW_XML.read_text(encoding="utf-8")
    lowered = blob.lower()
    assert "DET-MEMORY.spl" not in blob
    assert "No DET-MEMORY" in blob
    assert "ds.savedsearch" not in lowered
    assert "action.notable" not in lowered
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "DETECTION ANALYZED — NO NEW MEMORY DETECTOR" in markdown
    assert "PERSISTED MEMORY != TRUSTED INSTRUCTION" in markdown
    assert "MEMORY RECALL != AUTHORIZATION" in markdown
    assert "REQUEST != GRANT" in markdown
    assert "OBSERVE != ALLOW" in markdown
    assert "ALLOW != EXECUTION" in markdown
    assert "SPLUNK != ENFORCEMENT" in markdown
    assert "INTENTIONALLY VULNERABLE LAB PROFILE" in markdown
    assert "LAB-ONLY VULNERABLE PROFILE MECHANISM" in markdown
    assert "0 rows is **CORRECT**" in markdown or "0 rows is CORRECT" in markdown
    assert "0 rows != **SAFE**" in markdown or "0 rows != SAFE" in markdown
    assert "FUTURE — NOT IMPLEMENTED" in markdown
    assert "ML MUST NOT GRANT OR DENY AUTHORITY" in markdown
    assert "WHAT WE CANNOT PROVE YET" in markdown
    assert "SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION." in markdown
    assert "PLANE" in markdown or "PERSISTENCE" in markdown
    assert NORMAL_HASH in markdown
    assert MALICIOUS_HASH in markdown
    assert markdown.count(MALICIOUS_HASH) >= 4
    assert "Do **not** label this SAFE" in markdown
    assert "Path A — Try it yourself" in markdown
    assert "Path B — Show solution" in markdown
    assert "LIVE EXPERIMENT" in markdown
    assert "REPLAY SPECIMEN" in markdown
    assert "http://127.0.0.1:5001/labs/LAB-MEMORY-001" in markdown
    assert "MEMORY-I1-FIND-THE-WRITE" in markdown or "Find the write" in markdown
    assert SPECIMEN_IDS["attack_write_run_id"] in markdown
    assert SPECIMEN_IDS["attack_recall_run_id"] in markdown
    assert SPECIMEN_IDS["retest_write_run_id"] in markdown
    assert SPECIMEN_IDS["retest_recall_run_id"] in markdown
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
    assert "CTRL-MEMORY" not in det
    assert "MEMORY-001" not in det
    assert not list((ROOT / "learning").rglob("DET-MEMORY*"))
    dumped = json.dumps(_definition())
    assert "DET-MEMORY" in dumped
    assert "No DET-MEMORY" in dumped
    assert "Goal Integrity is a later lab" in dumped
    assert "Phase 15D not started" not in dumped
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")
    assert RAG_VIEW.is_file()
    rag = RAG_VIEW.read_text(encoding="utf-8")
    assert "ws_lab_rag_context" in rag or "LAB-RAG-CONTEXT" in rag
