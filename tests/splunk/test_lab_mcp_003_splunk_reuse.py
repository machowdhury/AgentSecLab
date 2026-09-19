"""MCP-003 Splunk reuse contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
CATALOG_PATH = SEARCH_DIR / "catalog.json"
DOCS = ROOT / "docs"

REQUIRED_REUSED_IDS = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-SCOPE",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
)

FORBIDDEN_NEW_SEARCH_IDS = (
    "Q-MCP-003",
    "Q-MCP-SCOPE-REQUEST",
    "Q-MCP-SCOPE-AUTHZ",
    "Q-MCP-SCOPE-MISMATCH",
    "Q-MCP-SCOPE-EXECUTED",
    "Q-MCP-SCOPE-AFTER-DENY",
    "DET-MCP-003",
)

MCP003_FIELDS = (
    "agentsec.run.id",
    "event.name",
    "gen_ai.tool.name",
    "mcp.method.name",
    "agentsec.control.decision",
    "agentsec.control.reason",
    "agentsec.mcp.requested_scope",
    "agentsec.mcp.allowed_scope",
    "agentsec.operation.executed",
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


def _catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _core(spl: str) -> str:
    start = spl.index("| eval run_id=mvindex")
    table = [line for line in spl.splitlines() if line.startswith("| table ")][-1]
    return spl[start : spl.index(table)].strip()


def test_does_not_create_duplicate_mcp003_searches():
    catalog = _catalog()
    ids = [query["id"] for query in catalog["queries"]]
    for forbidden in FORBIDDEN_NEW_SEARCH_IDS:
        assert forbidden not in ids
        assert not list(SEARCH_DIR.glob(f"{forbidden}.*"))
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert not list(SEARCH_DIR.glob("DET-MCP-003.*"))
    assert not list(SEARCH_DIR.glob("Q-MCP-003.*"))


def test_reused_searches_still_exist():
    catalog = _catalog()
    ids = [query["id"] for query in catalog["queries"]]
    for query_id in REQUIRED_REUSED_IDS:
        assert query_id in ids
        assert (SEARCH_DIR / f"{query_id}.spl").is_file()


def test_scope_relation_evaluates_error_before_mismatch():
    spl = (SEARCH_DIR / "Q-MCP-SCOPE.spl").read_text(encoding="utf-8")
    assert 'decision="ERROR","not_a_grant"' in spl
    error_at = spl.index('decision="ERROR","not_a_grant"')
    mismatch_at = spl.index('requested_scope!=allowed_scope,"known_but_ungranted"')
    assert error_at < mismatch_at
    doc = (SEARCH_DIR / "Q-MCP-SCOPE.md").read_text(encoding="utf-8")
    assert "not_a_grant" in doc
    assert "unknown_scope" in doc
    assert "ERROR" in doc


def test_authz_still_distinguishes_deny_and_error():
    spl = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8")
    assert "agentsec.control.decision" in spl
    assert "agentsec.control.reason" in spl
    doc = (SEARCH_DIR / "Q-MCP-AUTHZ.md").read_text(encoding="utf-8")
    assert "Do not collapse ERROR into DENY" in doc


def test_mcp003_field_references_exist_in_reused_spl():
    blob = "\n".join(
        (SEARCH_DIR / f"{query_id}.spl").read_text(encoding="utf-8")
        for query_id in REQUIRED_REUSED_IDS
    )
    for field in MCP003_FIELDS:
        assert field in blob, field
    scope = (SEARCH_DIR / "Q-MCP-SCOPE.spl").read_text(encoding="utf-8")
    for field in (
        "agentsec.mcp.requested_scope",
        "agentsec.mcp.allowed_scope",
        "agentsec.control.decision",
    ):
        assert field in scope
    executed = (SEARCH_DIR / "Q-MCP-EXECUTED.spl").read_text(encoding="utf-8")
    assert "agentsec.mcp.started" in executed
    assert "agentsec.mcp.completed" in executed
    assert "agentsec.mcp.failed" in executed
    assert "no_mcp_execution_event" in executed


def test_det_mcp_001_reuse_contract_unchanged():
    det = (SEARCH_DIR / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    assert "DET-MCP-003" not in det
    for command in EXPENSIVE:
        assert command not in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert catalog["detection"]["spl_file"] == "DET-MCP-001.spl"


def test_scope_teaching_fixture_is_simulated_and_shares_det_core():
    catalog = _catalog()
    fixture = catalog["detection"]["scope_teaching_fixture"]
    assert fixture["id"] == "DET-MCP-001-SCOPE-POSITIVE-CONTROL"
    assert fixture["evidence_class"] == "SIMULATED"
    assert fixture["generator"] == "makeresults"
    assert fixture["indexed"] is False
    assert fixture["expected_violation_rows"] == 1
    assert fixture["id"] not in [query["id"] for query in catalog["queries"]]
    spl = (SEARCH_DIR / fixture["spl_file"]).read_text(encoding="utf-8")
    doc = (SEARCH_DIR / fixture["doc_file"]).read_text(encoding="utf-8")
    live = (SEARCH_DIR / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert spl.lstrip().startswith("| makeresults")
    assert "index=agentsec_telemetry" not in spl
    assert not any(line.lstrip().startswith("index=") for line in spl.splitlines())
    assert 'evidence_class="SIMULATED"' in spl
    assert "scope_not_granted" in spl
    assert "policy:restricted:read" in spl
    assert "policy:read" in spl
    assert "lookup_policy" in spl
    assert "agentsec.mcp.started" in spl
    assert "DENY" in spl
    assert _core(spl) == _core(live)
    assert "This is **not** OBSERVED runtime behavior" in doc
    assert "DET-MCP-003" in doc
    for heading in DOC_HEADINGS:
        assert heading in doc, heading
    for command in EXPENSIVE:
        assert command not in spl


def test_phase4c_documentation_exists():
    required = (
        DOCS / "PHASE4C_MCP003_SPLUNK_VALIDATION.md",
        DOCS / "MCP003_SPLUNK_FIELD_VALIDATION.md",
        DOCS / "learning-notes" / "mcp-scope-splunk.md",
        DOCS / "IMPLEMENTATION_STATUS.md",
        DOCS / "MCP003_EVENT_MODEL_REVIEW.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE4C_MCP003_SPLUNK_VALIDATION.md").read_text(encoding="utf-8")
    for needle in (
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-SCOPE",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
        "unknown_scope",
        "DET-MCP-001",
        "SIMULATED",
        "no-data",
        "COMPLETE",
        "not_a_grant",
        "DET-MCP-003",
    ):
        assert needle in phase, needle
    fields = (DOCS / "MCP003_SPLUNK_FIELD_VALIDATION.md").read_text(encoding="utf-8")
    for field in (
        "agentsec.run.id",
        "trace_id",
        "event.name",
        "agentsec.mcp.requested_scope",
        "agentsec.mcp.allowed_scope",
        "mvcount",
    ):
        assert field in fields, field
    notes = (DOCS / "learning-notes" / "mcp-scope-splunk.md").read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "4C" in status
    assert "reused" in phase.lower()
