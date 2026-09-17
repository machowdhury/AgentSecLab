"""LAB-RAG-001 Splunk hunt contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE10C_RAG_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RAG = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "searches"
DOCS = ROOT / "docs"

REUSED = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
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
    "trusted_document",
    "document_authorized",
    "rag_allowed_tools",
    "full_document",
)


def _catalog() -> dict:
    return json.loads((RAG / "catalog.json").read_text(encoding="utf-8"))


def test_existing_q_mcp_spl_not_rewritten_for_rag():
    for path in sorted(MCP001.glob("Q-MCP-*.spl")):
        spl = path.read_text(encoding="utf-8")
        assert "schema.version=1.6.0" not in spl, path.name
        assert "rag.context" not in spl, path.name
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "schema.version" not in det
    assert "CTRL-RAG" not in det
    assert "RAG-001" not in det


def test_does_not_create_det_rag_or_extra_hunts():
    assert not list(RAG.glob("DET-RAG*"))
    assert not list(MCP001.glob("DET-RAG*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-RAG*"))
    assert not (RAG / "Q-RAG.spl").exists()
    for name in (
        "Q-RAG-CONTEXT",
        "Q-RAG-TRUST",
        "Q-RAG-FINGERPRINT",
        "Q-RAG-FOLLOWON",
        "Q-RAG-AUTHZ",
    ):
        assert not list(RAG.glob(f"{name}.*"))
    studio = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    assert {path.name for path in studio.glob("*rag*")} <= {"ws_lab_rag_context.xml"}


def test_det_mcp_001_file_unchanged_contract():
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert catalog["detection"]["status"] == "DETECTION ANALYZED — NO NEW DETECTOR"


def test_rag_authority_search_contract():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-RAG-001"
    assert catalog["schema.version"] == "1.6.0"
    assert catalog["reuses_lab_mcp_001_queries"] == list(REUSED)
    query = catalog["queries"][0]
    assert query["id"] == "Q-RAG-CONTEXT-AUTHORITY"
    spl = (RAG / query["spl_file"]).read_text(encoding="utf-8")
    doc = (RAG / query["doc_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" in spl
    assert "CTRL-RAG-CONTEXT-001" in spl
    assert "CTRL-MCP-001" in spl
    assert "agentsec.rag.context.trust" in spl
    assert "agentsec.rag.context.provenance" in spl
    assert "agentsec.rag.context.document.id" in spl
    assert "agentsec.content.hash" in spl
    assert 'hop="1"' in spl
    assert "derived_authority" in spl
    assert "retrieved_context_derived_authority" in spl
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
    assert catalog["validated_runs"]["BASELINE"] == "51f70fb9-994e-4dd4-9b36-cac6fb1e8232"
    assert catalog["validated_runs"]["ATTACK"] == "3a43d24f-9281-42f6-8375-1fb2efaa80ac"
    assert catalog["validated_runs"]["RETEST"] == "bea97bae-491b-4b36-b52f-1417d2bad01b"
    not_created = {item["id"] for item in catalog["queries_not_created"]}
    assert "Q-RAG-CONTEXT" in not_created
    assert "Q-RAG-FINGERPRINT" in not_created


def test_phase10c_documentation_exists():
    required = (
        DOCS / "PHASE10C_RAG_SPLUNK_VALIDATION.md",
        DOCS / "RAG_SPLUNK_FIELD_CONTRACT.md",
        DOCS / "RAG_SEARCH_CONTRACT.md",
        DOCS / "learning-notes" / "rag-splunk-investigation.md",
        DOCS / "reviews" / "splunk-ko-review-rag-2026-09-16.md",
        DOCS / "IMPLEMENTATION_STATUS.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE10C_RAG_SPLUNK_VALIDATION.md").read_text(encoding="utf-8")
    for needle in (
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
        "Q-RAG-CONTEXT-AUTHORITY",
        "DET-MCP-001",
        "DETECTION ANALYZED — NO NEW DETECTOR",
        "1.6.0",
        "COMPLETE",
        "no_indexed_followon_execution_event",
        "sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef",
        "51f70fb9-994e-4dd4-9b36-cac6fb1e8232",
        "3a43d24f-9281-42f6-8375-1fb2efaa80ac",
        "bea97bae-491b-4b36-b52f-1417d2bad01b",
        "INTENTIONALLY VULNERABLE LAB PROFILE",
        "mvindex(mvdedup",
        "NOT INDEXED / NOT EXTRACTED",
        "Phase 10D not started",
        "No Dashboard Studio",
    ):
        assert needle in phase, needle
    fields = (DOCS / "RAG_SPLUNK_FIELD_CONTRACT.md").read_text(encoding="utf-8")
    for field in (
        "agentsec.run.id",
        "CTRL-RAG-CONTEXT-001",
        "agentsec.rag.context.trust",
        "agentsec.rag.context.provenance",
        "agentsec.rag.context.document.id",
        "agentsec.content.hash",
        "mvcount",
        "1.6.0",
        "trusted_document",
        "NOT INDEXED / NOT EXTRACTED",
    ):
        assert field in fields, field
    notes = (DOCS / "learning-notes" / "rag-splunk-investigation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "10C" in status
    assert "SPLUNK VALIDATED" in status
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in status
