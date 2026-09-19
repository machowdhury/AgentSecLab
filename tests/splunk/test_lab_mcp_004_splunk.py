"""MCP-004 Splunk hunt contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
MCP004 = ROOT / "learning" / "level_1" / "LAB-MCP-004" / "searches"
DOCS = ROOT / "docs"

REUSED = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-SCOPE",
    "Q-MCP-PARAMS",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
)

RESOURCE_FIELDS = (
    "agentsec.mcp.resource.id",
    "agentsec.mcp.allowed_resource.ids",
    "agentsec.control.decision",
    "agentsec.control.reason",
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
    "effective_resource",
    "resource.authorized",
)


def _catalog() -> dict:
    return json.loads((MCP004 / "catalog.json").read_text(encoding="utf-8"))


def _core(spl: str) -> str:
    start = spl.index("| eval run_id=mvindex")
    table = [line for line in spl.splitlines() if line.startswith("| table ")][-1]
    return spl[start : spl.index(table)].strip()


def test_existing_q_mcp_spl_is_schema_version_agnostic():
    for path in sorted(MCP001.glob("Q-MCP-*.spl")):
        spl = path.read_text(encoding="utf-8")
        assert "schema.version=1.1.0" not in spl, path.name
        assert "schema.version=1.2.0" not in spl, path.name
        assert "agentsec.schema.version=1.1.0" not in spl, path.name
        assert "agentsec.schema.version=1.2.0" not in spl, path.name
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "schema.version" not in det
    catalog = json.loads((MCP001 / "catalog.json").read_text(encoding="utf-8"))
    assert catalog["schema.version"] == "1.1.0"


def test_does_not_create_det_mcp_004():
    assert not list(MCP004.glob("DET-MCP-004.*"))
    assert not list(MCP001.glob("DET-MCP-004.*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-MCP-004*"))


def test_det_mcp_001_file_unchanged_contract():
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    assert "DET-MCP-004" not in det
    assert "agentsec.mcp.resource.id" not in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"


def test_resource_authz_search_contract():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-MCP-004"
    assert catalog["schema.version"] == "1.2.0"
    assert catalog["reuses_lab_mcp_001_queries"] == list(REUSED)
    query = catalog["queries"][0]
    assert query["id"] == "Q-MCP-RESOURCE-AUTHZ"
    spl = (MCP004 / query["spl_file"]).read_text(encoding="utf-8")
    doc = (MCP004 / query["doc_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" in spl
    assert '"event.name"=agentsec.control.decision' in spl
    for field in RESOURCE_FIELDS:
        assert field in spl
        assert field in query["required_fields"]
    assert 'decision="ERROR","not_a_grant"' in spl
    error_at = spl.index('decision="ERROR","not_a_grant"')
    ungranted_at = spl.index('match(reason,"resource_not_granted")')
    granted_at = spl.index('"granted"')
    assert error_at < ungranted_at < granted_at
    assert "resource_id=allowed_resource_ids" in spl
    for heading in DOC_HEADINGS:
        assert heading in doc, heading
    assert "known_but_ungranted" in doc
    assert "does-not-exist" in doc
    assert "malformed_arguments" in doc
    assert "gen_ai.tool.call.arguments" not in spl
    for command in EXPENSIVE:
        assert command not in spl
    for field in PROHIBITED:
        assert field not in spl
    assert "Do not infer catalog membership" in doc or "cannot distinguish" in doc.lower() or "CONTROL REASON" in doc or "control reason" in doc.lower()


def test_params_still_not_full_arguments():
    spl = (MCP001 / "Q-MCP-PARAMS.spl").read_text(encoding="utf-8")
    assert "agentsec.content.preview" in spl
    assert "agentsec.content.hash" in spl
    assert "gen_ai.tool.call.arguments" not in spl
    assert "agentsec.mcp.resource.id" not in spl


def test_resource_teaching_fixture_is_simulated_and_shares_det_core():
    catalog = _catalog()
    fixture = catalog["detection"]["resource_teaching_fixture"]
    assert fixture["id"] == "DET-MCP-001-RESOURCE-POSITIVE-CONTROL"
    assert fixture["evidence_class"] == "SIMULATED"
    assert fixture["generator"] == "makeresults"
    assert fixture["indexed"] is False
    assert fixture["expected_violation_rows"] == 1
    spl = (MCP004 / fixture["spl_file"]).read_text(encoding="utf-8")
    doc = (MCP004 / fixture["doc_file"]).read_text(encoding="utf-8")
    live = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert spl.lstrip().startswith("| makeresults")
    assert "index=agentsec_telemetry" not in spl
    assert not any(line.lstrip().startswith("index=") for line in spl.splitlines())
    assert 'evidence_class="SIMULATED"' in spl
    assert "resource_not_granted" in spl
    assert "executive-restricted" in spl
    assert "lending-basics" in spl
    assert "lookup_policy" in spl
    assert "agentsec.mcp.started" in spl
    assert "DENY" in spl
    assert _core(spl) == _core(live)
    assert "This is **not** OBSERVED runtime behavior" in doc
    assert "DET-MCP-004" in doc
    for heading in DOC_HEADINGS:
        assert heading in doc, heading
    for command in EXPENSIVE:
        assert command not in spl


def test_phase5c_documentation_exists():
    required = (
        DOCS / "PHASE5C_MCP004_SPLUNK_VALIDATION.md",
        DOCS / "MCP004_SPLUNK_FIELD_VALIDATION.md",
        DOCS / "learning-notes" / "mcp-resource-splunk.md",
        DOCS / "IMPLEMENTATION_STATUS.md",
        DOCS / "MCP004_EVENT_MODEL_REVIEW.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE5C_MCP004_SPLUNK_VALIDATION.md").read_text(encoding="utf-8")
    for needle in (
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-SCOPE",
        "Q-MCP-PARAMS",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
        "Q-MCP-RESOURCE-AUTHZ",
        "unknown_resource",
        "DET-MCP-001",
        "SIMULATED",
        "no-data",
        "COMPLETE",
        "not_a_grant",
        "DET-MCP-004",
        "1.2.0",
        "duplicate_json_keys",
        "run_id",
    ):
        assert needle in phase, needle
    fields = (DOCS / "MCP004_SPLUNK_FIELD_VALIDATION.md").read_text(encoding="utf-8")
    for field in (
        "agentsec.run.id",
        "trace_id",
        "event.name",
        "agentsec.mcp.resource.id",
        "agentsec.mcp.allowed_resource.ids",
        "mvcount",
        "1.2.0",
    ):
        assert field in fields, field
    notes = (DOCS / "learning-notes" / "mcp-resource-splunk.md").read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "5C" in status
    assert "DET-MCP-004" in phase
    assert "not created" in phase.lower() or "No DET-MCP-004" in phase
