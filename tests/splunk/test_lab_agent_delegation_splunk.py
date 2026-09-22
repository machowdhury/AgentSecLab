"""LAB-AGENT-DELEGATION-001 Splunk hunt contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
DELEGATION = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001" / "searches"
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
    "authenticated=true",
    "verified_identity",
    "trusted_identity",
    "cryptographic_passport_valid",
)


def _catalog() -> dict:
    return json.loads((DELEGATION / "catalog.json").read_text(encoding="utf-8"))


def test_existing_q_mcp_spl_not_rewritten_for_identity():
    for path in sorted(MCP001.glob("Q-MCP-*.spl")):
        spl = path.read_text(encoding="utf-8")
        assert "schema.version=1.8.0" not in spl, path.name
        assert "agentsec.identity" not in spl, path.name
        assert "CTRL-IDENTITY-001" not in spl, path.name
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "schema.version" not in det
    assert "CTRL-IDENTITY" not in det
    assert "A2A-001" not in det


def test_does_not_create_det_a2a_or_extra_hunts_or_studio():
    assert not list(DELEGATION.glob("DET-A2A*"))
    assert not list(DELEGATION.glob("DET-DELEGATION*"))
    assert not list((ROOT / "learning").rglob("DET-A2A*"))
    assert not list((ROOT / "learning").rglob("DET-DELEGATION*"))
    assert not list((ROOT / "learning").rglob("Q-A2A*"))
    studio = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    names = {path.name for path in studio.glob("*")}
    assert "ws_lab_agent_delegation.xml" in names  # Phase 15E LIVE workshop
    assert "ws_lab_a2a.xml" not in names
    assert not (DELEGATION.parent / "workshop.md").exists()
    for name in (
        "Q-A2A-WHO",
        "Q-A2A-CLAIM",
        "Q-AGENT-IDENTITY-OBSERVE",
        "Q-AGENT-DELEGATION-EXECUTED",
    ):
        assert not list(DELEGATION.glob(f"{name}.*"))


def test_det_mcp_001_file_unchanged_contract():
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert catalog["detection"]["status"] == "DETECTION ANALYZED — NO NEW DETECTOR"


def test_agent_delegation_authority_search_contract():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-AGENT-DELEGATION-001"
    assert catalog["schema.version"] == "1.8.0"
    assert catalog["reuses_lab_mcp_001_queries"] == list(REUSED)
    query = catalog["queries"][0]
    assert query["id"] == "Q-AGENT-DELEGATION-AUTHORITY"
    spl = (DELEGATION / query["spl_file"]).read_text(encoding="utf-8")
    doc = (DELEGATION / query["doc_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" in spl
    assert "CTRL-IDENTITY-001" in spl
    assert "CTRL-MCP-001" in spl
    assert "agentsec.identity.caller_agent_id" in spl
    assert "agentsec.identity.callee_agent_id" in spl
    assert "agentsec.identity.claim.trust" in spl
    assert "agentsec.delegation.claimed_scope" in spl
    assert "agentsec.content.hash" in spl
    assert 'hop="1"' in spl
    assert "identity_claim_hash" in spl
    assert "no_indexed_followon_execution_event" in spl
    assert "schema.version" not in spl
    assert "| join " not in spl
    for heading in DOC_HEADINGS:
        assert heading in doc, heading
    for command in EXPENSIVE:
        assert command not in spl
    for field in PROHIBITED:
        assert field not in spl
    assert "handler count" in doc.lower() or "handler count remains" in doc
    assert "no-data" in doc.lower() or "Zero rows" in doc
    assert catalog["validated_runs"]["BASELINE"] == "b419465c-84d8-4639-8449-34dd99841ba9"
    assert catalog["validated_runs"]["ATTACK"] == "f846be88-1f9d-4dde-ac80-193c01b47660"
    assert catalog["validated_runs"]["RETEST"] == "271695f5-4739-44f2-8bf4-0749d04f4b03"
    not_created = {item["id"] for item in catalog["queries_not_created"]}
    assert "Q-A2A-WHO" in not_created
    assert "Q-MCP-DELEGATION" in not_created


def test_phase12c_documentation_exists():
    required = (
        DOCS / "PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md",
        DOCS / "AGENT_DELEGATION_SPLUNK_FIELD_CONTRACT.md",
        DOCS / "AGENT_DELEGATION_SEARCH_CONTRACT.md",
        DOCS / "learning-notes" / "agent-delegation-splunk-investigation.md",
        DOCS / "reviews" / "splunk-ko-review-agent-delegation-2026-09-18.md",
        DOCS / "IMPLEMENTATION_STATUS.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md").read_text(
        encoding="utf-8"
    )
    for needle in (
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
        "Q-AGENT-DELEGATION-AUTHORITY",
        "DET-MCP-001",
        "DETECTION ANALYZED — NO NEW DETECTOR",
        "1.8.0",
        "COMPLETE",
        "no_indexed_followon_execution_event",
        "sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd",
        "b419465c-84d8-4639-8449-34dd99841ba9",
        "f846be88-1f9d-4dde-ac80-193c01b47660",
        "271695f5-4739-44f2-8bf4-0749d04f4b03",
        "INTENTIONALLY VULNERABLE LAB PROFILE",
        "mvindex(mvdedup",
        "NOT INDEXED / NOT EXTRACTED",
        "Phase 12D not started",
        "No Dashboard Studio",
        "SAME DELEGATION REQUEST",
        "PASS — AGENT IDENTITY / DELEGATION SPLUNK VALIDATED",
        "WHO AUTHENTICATED",
        "TELEMETRY GAP",
        "CIM NOT APPLICABLE",
    ):
        assert needle in phase, needle
    fields = (DOCS / "AGENT_DELEGATION_SPLUNK_FIELD_CONTRACT.md").read_text(
        encoding="utf-8"
    )
    for field in (
        "agentsec.run.id",
        "CTRL-IDENTITY-001",
        "agentsec.identity.caller_agent_id",
        "agentsec.identity.claim.trust",
        "agentsec.delegation.claimed_scope",
        "mvcount",
        "1.8.0",
        "authenticated",
        "NOT INDEXED / NOT EXTRACTED",
    ):
        assert field in fields, field
    notes = (DOCS / "learning-notes" / "agent-delegation-splunk-investigation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "12C" in status
    assert "SPLUNK VALIDATED" in status
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in status
