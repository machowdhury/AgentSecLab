"""MCP-006 Splunk hunt contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/MCP006_SPLUNK_VALIDATION.md and docs/MCP006_DETECTION_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
MCP006 = ROOT / "learning" / "level_1" / "LAB-MCP-006" / "searches"
DOCS = ROOT / "docs"

REUSED = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-SCOPE",
    "Q-MCP-PARAMS",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-RESULT",
    "Q-MCP-RESULT-TRUST",
)

DOC_HEADINGS = (
    "## Required fields (indexed names)",
    "## SPL",
    "## Line-by-line explanation",
    "## Expected result",
    "## Actual result",
    "## Validated run.id / test data",
    "## Performance notes",
    "## Known limitations",
    "## No-data semantics",
)

EXPENSIVE = ("| join ", "| transaction ", "| map ", "| append ")
PROHIBITED = (
    "agentsec.event.name",
    "session.id",
    "mcp.session.id",
    "gen_ai.tool.call.arguments",
    "agentsec.mcp.allowed_tools",
    "gen_ai.tool.call.id",
    "agentsec.deputy.agent.id",
    "effective_authority",
)


def _catalog() -> dict:
    return json.loads((MCP006 / "catalog.json").read_text(encoding="utf-8"))


def test_existing_q_mcp_spl_is_schema_version_agnostic():
    for path in sorted(MCP001.glob("Q-MCP-*.spl")):
        spl = path.read_text(encoding="utf-8")
        assert "schema.version=1.1.0" not in spl, path.name
        assert "schema.version=1.2.0" not in spl, path.name
        assert "schema.version=1.3.0" not in spl, path.name
        assert "schema.version=1.4.0" not in spl, path.name
        assert "agentsec.schema.version=1.1.0" not in spl, path.name
        assert "agentsec.schema.version=1.2.0" not in spl, path.name
        assert "agentsec.schema.version=1.3.0" not in spl, path.name
        assert "agentsec.schema.version=1.4.0" not in spl, path.name
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "schema.version" not in det


def test_does_not_create_det_mcp_006():
    assert not list(MCP006.glob("DET-MCP-006.*"))
    assert not list(MCP001.glob("DET-MCP-006.*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-MCP-006*"))
    for name in (
        "Q-MCP-DELEGATION-AUTHORITY",
        "Q-MCP-DELEGATION-CHAIN",
        "Q-MCP-DELEGATION-EXECUTED",
        "Q-MCP-AMBIENT-USE",
    ):
        assert not list(MCP006.glob(f"{name}.*"))
    assert (ROOT / "learning" / "level_1" / "LAB-MCP-006" / "workshop.md").is_file()
    assert (
        ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_mcp_006.xml"
    ).is_file()


def test_det_mcp_001_file_unchanged_contract():
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    assert "DET-MCP-006" not in det
    assert "ambient_deputy" not in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert catalog["detection"]["status"] == "DETECTION ANALYZED — NO NEW DETECTOR"


def test_delegation_search_contract():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-MCP-006"
    assert catalog["schema.version"] == "1.4.0"
    assert catalog["reuses_lab_mcp_001_queries"] == list(REUSED)
    query = catalog["queries"][0]
    assert query["id"] == "Q-MCP-DELEGATION"
    spl = (MCP006 / query["spl_file"]).read_text(encoding="utf-8")
    doc = (MCP006 / query["doc_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" in spl
    assert "CTRL-DELEGATION-001" in spl
    assert "CTRL-MCP-001" in spl
    assert "agentsec.delegation.authority.source" in spl
    assert "deputy_not_on_indexed_hop1" in spl
    assert "no_indexed_mcp_execution_event" in spl
    assert "no_downstream_mcp_control_event" in spl
    assert "schema.version" not in spl
    assert "content.preview" not in spl
    for heading in DOC_HEADINGS:
        assert heading in doc, heading
    for command in EXPENSIVE:
        assert command not in spl
    for field in PROHIBITED:
        assert field not in spl
    assert "handler definitely never ran" in doc
    assert "no-data" in doc.lower() or "Zero rows" in doc
    assert catalog["validated_runs"]["BASELINE"] == "1cf98c4d-1bd8-4df5-be70-b82419e2c2b2"
    assert catalog["validated_runs"]["ATTACK"] == "d7524a4e-8da6-4171-8867-d2a2168128ac"
    assert catalog["validated_runs"]["RETEST"] == "50f7ec04-7524-41c0-95a8-3b1ef4d91dc4"


