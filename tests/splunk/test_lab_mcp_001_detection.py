"""Contract tests for DET-MCP-001 saved search packaging.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE3E_MCP_DETECTION.md.
"""

from __future__ import annotations

import json
from configparser import ConfigParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
CATALOG_PATH = SEARCH_DIR / "catalog.json"
SAVEDSEARCHES = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
DEFINITION_PATH = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json"

OUTPUT_FIELDS = (
    "run_id",
    "tool",
    "agent",
    "principal",
    "control_id",
    "decision",
    "deny_sequence",
    "mcp_start_sequence",
    "profile",
    "mode",
    "requested_scope",
    "allowed_scope",
    "trace_id",
)

NEGATIVES = {
    "BASELINE": "163d11e2-e751-4282-9406-19b490542ed4",
    "ATTACK": "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49",
    "RETEST": "7a1d37b5-d589-4dfd-8322-25ebd0152dbc",
    "UNKNOWN_TOOL": "2e804c0d-eb86-405a-ab8d-360616df0ef9",
    "MALFORMED_ARG": "f2ef017e-d66c-4712-bacd-07138a30d2e6",
    "HANDLER_FAILURE": "5b83b6e4-f8c4-4989-8ef5-b76614b49ca5",
}

EXPENSIVE = ("| join ", "| transaction ", "| map ", "| append ")


def _catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _normalize(spl: str) -> str:
    return " ".join(spl.split())


def _core(spl: str) -> str:
    start = spl.index("| eval run_id=mvindex")
    table = [line for line in spl.splitlines() if line.startswith("| table ")][-1]
    return spl[start : spl.index(table)].strip()


def _savedsearches() -> ConfigParser:
    parser = ConfigParser(interpolation=None)
    parser.optionxform = str
    read = parser.read(SAVEDSEARCHES)
    assert read, SAVEDSEARCHES
    return parser


def test_detection_files_exist():
    catalog = _catalog()["detection"]
    assert catalog["id"] == "DET-MCP-001"
    assert catalog["savedsearch_name"] == "AgentSec - MCP Execution After Authorization Deny"
    assert catalog["severity"] == "HIGH"
    assert catalog["disabled_by_default"] is True
    assert (SEARCH_DIR / catalog["spl_file"]).is_file()
    assert (SEARCH_DIR / catalog["doc_file"]).is_file()
    pos = catalog["positive_control"]
    assert pos["evidence_class"] == "SIMULATED"
    assert pos["indexed"] is False
    assert pos["expected_violation_rows"] == 1
    assert (SEARCH_DIR / pos["spl_file"]).is_file()
    assert (SEARCH_DIR / pos["doc_file"]).is_file()


def test_detection_spl_contract():
    catalog = _catalog()["detection"]
    spl = (SEARCH_DIR / catalog["spl_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "sourcetype=otel:agentic:json" in spl
    assert "__RUN_ID__" not in spl
    assert '"event.name"=agentsec.control.decision' in spl
    assert '"event.name"=agentsec.mcp.started' in spl
    assert "is_deny" in spl and "is_started" in spl
    assert "sequence>deny_sequence" in spl
    assert "by run_id, tool" in spl
    for command in EXPENSIVE:
        assert command not in spl
    table = [line for line in spl.splitlines() if line.startswith("| table ")][-1]
    for field in OUTPUT_FIELDS:
        assert field in table, field
    assert catalog["required_output_fields"] == list(OUTPUT_FIELDS)
    for field in (
        "event.name",
        "agentsec.run.id",
        "gen_ai.tool.name",
        "agentsec.sequence",
        "agentsec.control.decision",
        "gen_ai.agent.id",
        "agentsec.principal.id",
        "agentsec.control.id",
        "agentsec.security.profile",
        "agentsec.testbed.mode",
        "agentsec.mcp.requested_scope",
        "agentsec.mcp.allowed_scope",
        "trace_id",
    ):
        assert field in spl
    assert "agentsec.event.name" not in spl
    assert "session.id" not in spl
    assert "mcp.completed" not in spl
    assert "mcp.failed" not in spl


def test_savedsearch_matches_spl_and_stays_disabled():
    catalog = _catalog()["detection"]
    parser = _savedsearches()
    name = catalog["savedsearch_name"]
    assert parser.has_section(name)
    stanza = parser[name]
    assert stanza.get("disabled") == "1"
    assert stanza.get("enableSched") == "0"
    assert stanza.get("cron_schedule") == catalog["cron_schedule"]
    assert stanza.get("dispatch.earliest_time") == catalog["dispatch_earliest"]
    assert stanza.get("dispatch.latest_time") == catalog["dispatch_latest"]
    assert "action.notable" not in stanza
    assert "action.email" not in stanza
    spl = (SEARCH_DIR / catalog["spl_file"]).read_text(encoding="utf-8")
    assert _normalize(stanza.get("search")) == _normalize(spl)
    desc = stanza.get("description")
    assert "CTRL-MCP-001" in desc
    assert "HIGH" in desc
    assert "Not a general MCP bypass" in desc
    assert "Disabled by default" in desc


def test_positive_control_shares_detection_core():
    catalog = _catalog()["detection"]
    live = (SEARCH_DIR / catalog["spl_file"]).read_text(encoding="utf-8")
    sim = (SEARCH_DIR / catalog["positive_control"]["spl_file"]).read_text(encoding="utf-8")
    assert sim.lstrip().startswith("| makeresults")
    assert "index=agentsec_telemetry" not in sim
    assert 'evidence_class="SIMULATED"' in sim
    assert '"agentsec.sequence"=if(row=1,"3","4")' in sim
    assert "agentsec.mcp.started" in sim
    assert _core(sim) == _core(live)
    doc = (SEARCH_DIR / catalog["positive_control"]["doc_file"]).read_text(encoding="utf-8")
    assert "This is **not** OBSERVED runtime behavior" in doc


def test_negatives_are_documented():
    catalog = _catalog()
    for run_id in NEGATIVES.values():
        assert run_id in json.dumps(catalog["validated_runs"])
    doc = (SEARCH_DIR / catalog["detection"]["doc_file"]).read_text(encoding="utf-8")
    for needle in catalog["detection"]["does_not_alert_on"]:
        assert needle in doc
    hunt = (SEARCH_DIR / "Q-MCP-AFTER-DENY.spl").read_text(encoding="utf-8")
    det = (SEARCH_DIR / catalog["detection"]["spl_file"]).read_text(encoding="utf-8")
    assert "__RUN_ID__" in hunt
    assert "__RUN_ID__" not in det


def test_dashboard_detect_teaches_hunt_and_detection():
    definition = json.loads(DEFINITION_PATH.read_text(encoding="utf-8"))
    detect = definition["visualizations"]["viz_detect_md"]["options"]["markdown"]
    assert "HUNT" in detect and "DETECTION" in detect
    assert "Q-MCP-AFTER-DENY" in detect
    assert "DET-MCP-001" in detect
    assert "does **not** enable" in detect
    assert "did **not** fire" in detect
    assert "SIMULATED" in detect
    assert definition["visualizations"]["viz_detect_sim"]["title"].startswith(
        "DET-MCP-001-POSITIVE-CONTROL"
    )
    assert "SIMULATED" in definition["visualizations"]["viz_detect_sim"]["title"]
    assert (
        definition["visualizations"]["viz_detect_sim"]["dataSources"]["primary"]
        == "ds_det_mcp_001_sim"
    )
    assert definition["visualizations"]["viz_detect_live"]["dataSources"]["primary"] == "ds_q_after_deny"
    lowered = json.dumps(definition).lower()
    assert "action.notable" not in lowered
    assert "ds.savedsearch" not in lowered
