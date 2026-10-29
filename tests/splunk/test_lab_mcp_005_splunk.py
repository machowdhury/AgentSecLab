"""MCP-005 Splunk hunt contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/MCP005_SPLUNK_VALIDATION.md and docs/MCP005_DETECTION_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
MCP004 = ROOT / "learning" / "level_1" / "LAB-MCP-004" / "searches"
MCP005 = ROOT / "learning" / "level_1" / "LAB-MCP-005" / "searches"
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
    "result.authorized",
    "trusted_result",
    "agent.super_secret_field",
)


def _catalog() -> dict:
    return json.loads((MCP005 / "catalog.json").read_text(encoding="utf-8"))


def test_existing_q_mcp_spl_is_schema_version_agnostic():
    for path in sorted(MCP001.glob("Q-MCP-*.spl")):
        spl = path.read_text(encoding="utf-8")
        assert "schema.version=1.1.0" not in spl, path.name
        assert "schema.version=1.2.0" not in spl, path.name
        assert "schema.version=1.3.0" not in spl, path.name
        assert "agentsec.schema.version=1.1.0" not in spl, path.name
        assert "agentsec.schema.version=1.2.0" not in spl, path.name
        assert "agentsec.schema.version=1.3.0" not in spl, path.name
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "schema.version" not in det


def test_does_not_create_det_mcp_005():
    assert not list(MCP005.glob("DET-MCP-005.*"))
    assert not list(MCP001.glob("DET-MCP-005.*"))
    assert not list(MCP004.glob("DET-MCP-005.*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-MCP-005*"))
    assert not list(MCP005.glob("Q-MCP-RESULT-FOLLOWON.*"))


def test_det_mcp_001_file_unchanged_contract():
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    assert "DET-MCP-005" not in det
    assert "result_derived_grant" not in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert catalog["detection"]["status"] == "DETECTION ANALYZED — NO NEW DETECTOR"


def test_result_authority_search_contract():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-MCP-005"
    assert catalog["schema.version"] == "1.3.0"
    assert catalog["reuses_lab_mcp_001_queries"] == list(REUSED)
    query = catalog["queries"][0]
    assert query["id"] == "Q-MCP-RESULT-AUTHORITY"
    spl = (MCP005 / query["spl_file"]).read_text(encoding="utf-8")
    doc = (MCP005 / query["doc_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" in spl
    assert "CTRL-MCP-RESULT-001" in spl
    assert 'hop="0"' in spl
    assert 'hop="1"' in spl
    assert "derived_authority" in spl
    assert "result_derived_grant" in spl
    assert "no_indexed_followon_execution_event" in spl
    assert "SECURITY_OVERRIDE" not in spl
    for heading in DOC_HEADINGS:
        assert heading in doc, heading
    assert "untrusted_data" in (MCP001 / "Q-MCP-RESULT-TRUST.md").read_text(encoding="utf-8")
    assert "used as authority" in doc.lower() or "influence authorization" in doc.lower()
    for command in EXPENSIVE:
        assert command not in spl
    for field in PROHIBITED:
        assert field not in spl
    assert "Do not write “handler definitely never ran” from Splunk alone." in doc or "handler definitely never ran" in doc
    assert "no-data" in doc.lower() or "Zero rows" in doc


def test_result_trust_query_remains_classification_not_authority():
    spl = (MCP001 / "Q-MCP-RESULT-TRUST.spl").read_text(encoding="utf-8")
    doc = (MCP001 / "Q-MCP-RESULT-TRUST.md").read_text(encoding="utf-8")
    assert "agentsec.mcp.result.trust" in spl
    assert "CTRL-MCP-RESULT-001" not in spl
    assert "result_derived_grant" not in spl
    assert "Does **not** implement MCP-005" in doc or "used as authority" in doc


