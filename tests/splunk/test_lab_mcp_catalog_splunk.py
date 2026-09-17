"""LAB-MCP-CATALOG Splunk hunt contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
CATALOG = ROOT / "learning" / "level_1" / "LAB-MCP-CATALOG" / "searches"
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
    "agentsec.mcp.catalog.fixture",
    "trusted_metadata",
)


def _catalog() -> dict:
    return json.loads((CATALOG / "catalog.json").read_text(encoding="utf-8"))


def test_existing_q_mcp_spl_is_schema_version_agnostic():
    for path in sorted(MCP001.glob("Q-MCP-*.spl")):
        spl = path.read_text(encoding="utf-8")
        assert "schema.version=1.1.0" not in spl, path.name
        assert "schema.version=1.5.0" not in spl, path.name
        assert "agentsec.schema.version=1.5.0" not in spl, path.name
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "schema.version" not in det


def test_does_not_create_det_mcp_catalog_or_extra_hunts():
    assert not list(CATALOG.glob("DET-MCP-CATALOG.*"))
    assert not list(MCP001.glob("DET-MCP-CATALOG.*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-MCP-CATALOG*"))
    assert not (CATALOG / "Q-MCP-CATALOG.spl").exists()
    for name in (
        "Q-MCP-CATALOG-METADATA",
        "Q-MCP-CATALOG-TRUST",
        "Q-MCP-CATALOG-FINGERPRINT",
        "Q-MCP-CATALOG-FOLLOWON",
        "Q-MCP-CATALOG-AUTHZ",
    ):
        assert not list(CATALOG.glob(f"{name}.*"))
    studio = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    catalog_view = studio / "ws_lab_mcp_catalog.xml"
    assert catalog_view.is_file()
    catalog_xml = catalog_view.read_text(encoding="utf-8")
    assert "DET-MCP-CATALOG.spl" not in catalog_xml
    assert "No DET-MCP-CATALOG" in catalog_xml


def test_det_mcp_001_file_unchanged_contract():
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    assert "DET-MCP-CATALOG" not in det
    assert "CTRL-MCP-METADATA" not in det
    assert "metadata_derived_authority" not in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert catalog["detection"]["status"] == (
        "DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN"
    )


def test_catalog_authority_search_contract():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-MCP-CATALOG"
    assert catalog["schema.version"] == "1.5.0"
    assert catalog["reuses_lab_mcp_001_queries"] == list(REUSED)
    query = catalog["queries"][0]
    assert query["id"] == "Q-MCP-CATALOG-AUTHORITY"
    spl = (CATALOG / query["spl_file"]).read_text(encoding="utf-8")
    doc = (CATALOG / query["doc_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" in spl
    assert "CTRL-MCP-METADATA-001" in spl
    assert "CTRL-MCP-001" in spl
    assert "agentsec.mcp.metadata.trust" in spl
    assert "agentsec.mcp.metadata.provenance" in spl
    assert "agentsec.content.hash" in spl
    assert 'hop="0"' in spl
    assert 'hop="1"' in spl
    assert "derived_authority" in spl
    assert "metadata_derived_authority" in spl
    assert "no_indexed_followon_execution_event" in spl
    assert "schema.version" not in spl
    assert "| join " not in spl
    for heading in DOC_HEADINGS:
        assert heading in doc, heading
    for command in EXPENSIVE:
        assert command not in spl
    for field in PROHIBITED:
        assert field not in spl
    assert "handler definitely never ran" in doc
    assert "no-data" in doc.lower() or "Zero rows" in doc
    assert catalog["validated_runs"]["BASELINE"] == "d95717ed-ffd2-46c0-a130-9a5d7d539a5d"
    assert catalog["validated_runs"]["ATTACK"] == "a0937bff-31a5-453a-99bf-47d7b5148ce4"
    assert catalog["validated_runs"]["RETEST"] == "23c222ea-6a87-40b7-a3e9-f12a5b572fa1"
    not_created = {item["id"] for item in catalog["queries_not_created"]}
    assert "Q-MCP-CATALOG-METADATA" in not_created
    assert "Q-CATALOG-WHAT-WAS-ADVERTISED" in not_created


def test_phase8d_documentation_exists():
    required = (
        DOCS / "PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md",
        DOCS / "MCP_CATALOG_SPLUNK_FIELD_CONTRACT.md",
        DOCS / "MCP_CATALOG_SEARCH_CONTRACT.md",
        DOCS / "learning-notes" / "mcp-catalog-splunk-investigation.md",
        DOCS / "reviews" / "splunk-ko-review-lab-mcp-catalog-2026-09-16.md",
        DOCS / "IMPLEMENTATION_STATUS.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md").read_text(encoding="utf-8")
    for needle in (
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
        "Q-MCP-CATALOG-AUTHORITY",
        "DET-MCP-001",
        "DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN",
        "1.5.0",
        "COMPLETE",
        "no_indexed_followon_execution_event",
        "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1",
        "d95717ed-ffd2-46c0-a130-9a5d7d539a5d",
        "a0937bff-31a5-453a-99bf-47d7b5148ce4",
        "23c222ea-6a87-40b7-a3e9-f12a5b572fa1",
        "SIMULATED",
        "mvindex(mvdedup",
        "NOT INDEXED / NOT EXTRACTED",
        "Phase 8E not started",
    ):
        assert needle in phase, needle
    fields = (DOCS / "MCP_CATALOG_SPLUNK_FIELD_CONTRACT.md").read_text(encoding="utf-8")
    for field in (
        "agentsec.run.id",
        "CTRL-MCP-METADATA-001",
        "agentsec.mcp.metadata.trust",
        "agentsec.mcp.metadata.provenance",
        "agentsec.content.hash",
        "mvcount",
        "1.5.0",
        "agentsec.mcp.allowed_tools",
        "NOT INDEXED / NOT EXTRACTED",
    ):
        assert field in fields, field
    notes = (DOCS / "learning-notes" / "mcp-catalog-splunk-investigation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "8D" in status
    assert "SPLUNK VALIDATED" in status
    assert "DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN" in status
    assert "ws_lab_mcp_catalog" not in phase or "No Dashboard Studio" in phase
