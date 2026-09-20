"""Dashboard Studio contracts for LAB-AGENT-GOAL-INTEGRITY-001 WS-GOAL-INTEGRITY.

These tests do not execute SPL against Splunk and do not prove the dashboard
loaded in a browser.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001"
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
GOAL_DIR = LAB_DIR / "searches"
DEFINITION_PATH = LAB_DIR / "dashboard.definition.json"
VIEW_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_agent_goal_integrity.xml"
)
NAV_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
BUILDER = ROOT / "scripts" / "build_lab_agent_goal_integrity_dashboard.py"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
AUTHZ = ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DET = SEARCH_DIR / "DET-MCP-001.spl"
MEMORY_VIEW = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_memory_security.xml"
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
REQUIRED_TOKENS = ("run_id",)
SPECIMEN_IDS = {
    "run_id": "0aced342-1295-4820-b807-9a8718d9e847",
    "baseline_run_id": "0aced342-1295-4820-b807-9a8718d9e847",
    "attack_run_id": "fd994587-7e1c-4a70-8013-54cb2c85254d",
    "retest_run_id": "605ba7c1-449b-4338-92df-7da3b704b08e",
}
TASK_HASH = "sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c"
INSTRUCTION_HASH = "sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2"
PROPOSED_HASH = "sha256:6326e3be47ecf73831a06be2b718f42219e0c950d4c989de23aa558bfdc01b34"
FORBIDDEN_CLAIMS = (
    "untrusted_instruction = malicious",
    "instruction = authorization",
    "proposed goal = authorized goal",
    "goal observe = goal allow",
    "goal deny = mcp deny",
    "authorized tool = authorized task",
    "authorized tool = authorized use",
    "mcp allow = goal authorization",
    "mcp allow = execution",
    "mcp.started = successful completion",
    "mcp.failed = prevention",
    "missing splunk row = blocked",
    "baseline = safe",
    "known hash = compromise",
    "det-mcp-001 silence = safe",
    "anomaly = incident",
    "splunk = enforcement",
    "llm = authorization authority",
    "simulated = live",
    "splunk authorized",
    "splunk blocked",
    "splunk prevented",
    "mcp blocked retest",
    "lookup_policy was compromised",
    "mcp authorization failed",
)
PROHIBITED_FIELDS = (
    "agentsec.event.name",
    "agentsec.mcp.allowed_tools",
    "gen_ai.tool.call.id",
    "gen_ai.tool.call.arguments",
    "session.id",
    "invocation.id",
    "task_authorized",
    "goal_authorized",
    "AGENT NOTE",
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
    assert "ws_lab_agent_goal_integrity" in nav
    assert "ws_lab_memory_security" in nav
    file_def = _definition()
    xml_def = _xml_definition()
    assert file_def == xml_def
    xml = VIEW_XML.read_text(encoding="utf-8")
    assert xml.startswith("<?xml")
    assert 'version="2"' in xml
    assert 'theme="light"' in xml
    assert "LAB-AGENT-GOAL-INTEGRITY-001" in xml


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
    assert item_values == {
        SPECIMEN_IDS["baseline_run_id"],
        SPECIMEN_IDS["attack_run_id"],
        SPECIMEN_IDS["retest_run_id"],
    }
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
    goal = (GOAL_DIR / "Q-GOAL-INTEGRITY-AUTHORITY.spl").read_text(encoding="utf-8").strip()
    who = (SEARCH_DIR / "Q-MCP-WHO.spl").read_text(encoding="utf-8").strip()
    authz = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8").strip()
    tool = (SEARCH_DIR / "Q-MCP-TOOL.spl").read_text(encoding="utf-8").strip()
    executed = (SEARCH_DIR / "Q-MCP-EXECUTED.spl").read_text(encoding="utf-8").strip()
    after = (SEARCH_DIR / "Q-MCP-AFTER-DENY.spl").read_text(encoding="utf-8").strip()

    expected = {
        "ds_q_goal": goal.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_who": who.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_authz": authz.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_tool": tool.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_executed": executed.replace("__RUN_ID__", '"$run_id$"'),
        "ds_q_goal_b": goal.replace("__RUN_ID__", f'"{SPECIMEN_IDS["baseline_run_id"]}"'),
        "ds_q_goal_a": goal.replace("__RUN_ID__", f'"{SPECIMEN_IDS["attack_run_id"]}"'),
        "ds_q_goal_r": goal.replace("__RUN_ID__", f'"{SPECIMEN_IDS["retest_run_id"]}"'),
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
    assert "agentsec.task.hash" in seq
    assert "agentsec.instruction.trust" in seq
    assert "agentsec.goal.proposed" in seq
    assert "_raw" not in seq
    assert set(queries) == set(expected) | {"ds_det_mcp_001_sim", "ds_observe_seq"}
    for query in queries.values():
        text = query["options"]["query"]
        assert "| join " not in text
        assert "DET-GOAL" not in text
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
    assert "DET-GOAL.spl" not in blob
    assert "No DET-GOAL" in blob
    assert "ds.savedsearch" not in lowered
    assert "action.notable" not in lowered
    markdown = "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )
    assert "DETECTION ANALYZED — NO NEW GOAL DETECTOR" in markdown
    assert "AUTHORIZED TOOL != AUTHORIZED GOAL" in markdown
    assert "AUTHORIZED TOOL != AUTHORIZED USE OF TOOL" in markdown
    assert "REQUEST != GRANT" in markdown
    assert "OBSERVE != ALLOW" in markdown
    assert "ALLOW != EXECUTION" in markdown
    assert "SPLUNK != ENFORCEMENT" in markdown
    assert "INTENTIONALLY VULNERABLE LAB PROFILE" in markdown
    assert "LAB-ONLY" in markdown
    assert "0 rows is **CORRECT**" in markdown or "0 rows is CORRECT" in markdown
    assert "0 rows != **SAFE**" in markdown or "0 rows != SAFE" in markdown
    assert "FUTURE — NOT IMPLEMENTED" in markdown
    assert "ML MUST NOT GRANT OR DENY AUTHORITY" in markdown
    assert "WHAT WE CANNOT PROVE YET" in markdown
    assert "SAME TASK. SAME MALICIOUS INSTRUCTION. SAME PROPOSED GOAL. SAME AUTHORIZED TOOL." in markdown
    assert "Do not say MCP blocked the attack." in markdown
    assert "Do **not** label this SAFE" in markdown
    assert "PLANE" in markdown or "TASK" in markdown
    assert TASK_HASH in markdown
    assert INSTRUCTION_HASH in markdown
    assert PROPOSED_HASH in markdown
    assert "PARTIALLY SUPPORTED" in markdown
    assert SPECIMEN_IDS["attack_run_id"] in markdown
    assert SPECIMEN_IDS["retest_run_id"] in markdown
    assert SPECIMEN_IDS["baseline_run_id"] in markdown
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
    assert "CTRL-GOAL" not in det
    assert "GOAL-001" not in det
    assert not list((ROOT / "learning").rglob("DET-GOAL*"))
    dumped = json.dumps(_definition())
    assert "DET-GOAL" in dumped
    assert "No DET-GOAL" in dumped
    assert "Phase 14 not started" in dumped
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")
    assert MEMORY_VIEW.is_file()
    memory = MEMORY_VIEW.read_text(encoding="utf-8")
    assert "ws_lab_memory_security" in memory or "LAB-MEMORY-001" in memory
