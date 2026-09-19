"""LAB-MEMORY-001 Splunk hunt contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE11C_MEMORY_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
MEMORY = ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "searches"
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
    "invocation.id",
    "gen_ai.tool.call.arguments",
    "agentsec.mcp.allowed_tools",
    "gen_ai.tool.call.id",
    "trusted_memory",
    "memory_authorized",
    "full_memory",
)


def _catalog() -> dict:
    return json.loads((MEMORY / "catalog.json").read_text(encoding="utf-8"))


def test_existing_q_mcp_spl_not_rewritten_for_memory():
    for path in sorted(MCP001.glob("Q-MCP-*.spl")):
        spl = path.read_text(encoding="utf-8")
        assert "schema.version=1.7.0" not in spl, path.name
        assert "agentsec.memory" not in spl, path.name
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "schema.version" not in det
    assert "CTRL-MEMORY" not in det
    assert "MEMORY-001" not in det


def test_does_not_create_det_memory_or_extra_hunts():
    assert not list(MEMORY.glob("DET-MEMORY*"))
    assert not list(MCP001.glob("DET-MEMORY*"))
    assert not list((ROOT / "splunk_app").rglob("*DET-MEMORY*"))
    assert not (MEMORY / "Q-MEMORY.spl").exists()
    for name in (
        "Q-MEMORY-WRITE",
        "Q-MEMORY-TRUST",
        "Q-MEMORY-FINGERPRINT",
        "Q-MEMORY-FOLLOWON",
        "Q-MEMORY-AUTHZ",
    ):
        assert not list(MEMORY.glob(f"{name}.*"))
    studio = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    assert {path.name for path in studio.glob("*memory*")} <= {"ws_lab_memory_security.xml"}


def test_det_mcp_001_file_unchanged_contract():
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert catalog["detection"]["status"] == "DETECTION ANALYZED — NO NEW DETECTOR"


def test_memory_authority_search_contract():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-MEMORY-001"
    assert catalog["schema.version"] == "1.7.0"
    assert catalog["reuses_lab_mcp_001_queries"] == list(REUSED)
    query = catalog["queries"][0]
    assert query["id"] == "Q-MEMORY-CONTEXT-AUTHORITY"
    spl = (MEMORY / query["spl_file"]).read_text(encoding="utf-8")
    doc = (MEMORY / query["doc_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "__WRITE_RUN_ID__" in spl
    assert "__RECALL_RUN_ID__" in spl
    assert "CTRL-MEMORY-CONTEXT-001" in spl
    assert "CTRL-MCP-001" in spl
    assert "agentsec.memory.id" in spl
    assert "agentsec.memory.trust" in spl
    assert "agentsec.memory.provenance" in spl
    assert "agentsec.memory.source_run_id" in spl
    assert "agentsec.content.hash" in spl
    assert 'hop="1"' in spl
    assert "derived_authority" in spl
    assert "memory_derived_authority" in spl
    assert "write_recall_linked" in spl
    assert "fingerprint_survived" in spl
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
    assert catalog["validated_runs"]["BASELINE"]["write"] == "a8407246-7992-4ad8-bd02-cb701e150f30"
    assert catalog["validated_runs"]["BASELINE"]["recall"] == "914c41ce-5123-49eb-892c-c948295dbc46"
    assert catalog["validated_runs"]["ATTACK"]["write"] == "05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464"
    assert catalog["validated_runs"]["ATTACK"]["recall"] == "b8737cd9-9b6b-48f2-acfa-178ae1446ddc"
    assert catalog["validated_runs"]["RETEST"]["write"] == "060a0a72-ceb5-4b99-8330-98de81d8ae5e"
    assert catalog["validated_runs"]["RETEST"]["recall"] == "5d5b9d1b-092d-4ddb-8422-4092d289cd49"
    not_created = {item["id"] for item in catalog["queries_not_created"]}
    assert "Q-MEMORY-WRITE" in not_created
    assert "Q-MEMORY-FINGERPRINT" in not_created


def test_phase11c_documentation_exists():
    required = (
        DOCS / "PHASE11C_MEMORY_SPLUNK_VALIDATION.md",
        DOCS / "MEMORY_SPLUNK_FIELD_CONTRACT.md",
        DOCS / "MEMORY_SEARCH_CONTRACT.md",
        DOCS / "learning-notes" / "memory-splunk-investigation.md",
        DOCS / "reviews" / "splunk-ko-review-memory-2026-09-17.md",
        DOCS / "IMPLEMENTATION_STATUS.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE11C_MEMORY_SPLUNK_VALIDATION.md").read_text(encoding="utf-8")
    for needle in (
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
        "Q-MEMORY-CONTEXT-AUTHORITY",
        "DET-MCP-001",
        "DETECTION ANALYZED — NO NEW DETECTOR",
        "1.7.0",
        "COMPLETE",
        "no_indexed_followon_execution_event",
        "sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9",
        "a8407246-7992-4ad8-bd02-cb701e150f30",
        "914c41ce-5123-49eb-892c-c948295dbc46",
        "05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464",
        "b8737cd9-9b6b-48f2-acfa-178ae1446ddc",
        "060a0a72-ceb5-4b99-8330-98de81d8ae5e",
        "5d5b9d1b-092d-4ddb-8422-4092d289cd49",
        "INTENTIONALLY VULNERABLE LAB PROFILE",
        "mvindex(mvdedup",
        "NOT INDEXED / NOT EXTRACTED",
        "Phase 11D not started",
        "No Dashboard Studio",
        "SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION.",
        "PASS — MEMORY SECURITY SPLUNK VALIDATED",
    ):
        assert needle in phase, needle
    fields = (DOCS / "MEMORY_SPLUNK_FIELD_CONTRACT.md").read_text(encoding="utf-8")
    for field in (
        "agentsec.run.id",
        "CTRL-MEMORY-CONTEXT-001",
        "agentsec.memory.trust",
        "agentsec.memory.provenance",
        "agentsec.memory.source_run_id",
        "agentsec.content.hash",
        "mvcount",
        "1.7.0",
        "trusted_memory",
        "NOT INDEXED / NOT EXTRACTED",
    ):
        assert field in fields, field
    notes = (DOCS / "learning-notes" / "memory-splunk-investigation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "11C" in status
    assert "SPLUNK VALIDATED" in status
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in status
