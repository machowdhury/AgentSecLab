"""LAB-AGENT-GOAL-INTEGRITY-001 Splunk hunt contracts.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
GOAL = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001" / "searches"
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
    "trusted_instruction",
    "task_authorized",
    "goal_authorized",
    "AGENT NOTE",
)


def _catalog() -> dict:
    return json.loads((GOAL / "catalog.json").read_text(encoding="utf-8"))


def test_existing_q_mcp_spl_not_rewritten_for_goal():
    for path in sorted(MCP001.glob("Q-MCP-*.spl")):
        spl = path.read_text(encoding="utf-8")
        assert "schema.version=1.9.0" not in spl, path.name
        assert "agentsec.goal" not in spl, path.name
        assert "CTRL-GOAL-INTEGRITY-001" not in spl, path.name
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "schema.version" not in det
    assert "CTRL-GOAL" not in det
    assert "GOAL-001" not in det


def test_does_not_create_det_goal_or_extra_hunts_or_studio():
    assert not list(GOAL.glob("DET-GOAL*"))
    assert not list((ROOT / "learning").rglob("DET-GOAL*"))
    studio = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    names = {path.name for path in studio.glob("*goal*")}
    assert names <= {"ws_lab_agent_goal_integrity.xml"}
    assert "ws_lab_goal.xml" not in names
    for name in ("Q-GOAL-TASK", "Q-GOAL-INSTRUCTION", "Q-GOAL-EXECUTED"):
        assert not list(GOAL.glob(f"{name}.*"))


def test_det_mcp_001_file_unchanged_contract():
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" not in det
    assert "sequence>deny_sequence" in det
    assert "by run_id, tool" in det
    catalog = _catalog()
    assert catalog["detection"]["id"] == "DET-MCP-001"
    assert catalog["detection"]["status"] == "DETECTION ANALYZED — NO NEW DETECTOR"


def test_goal_integrity_authority_search_contract():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-AGENT-GOAL-INTEGRITY-001"
    assert catalog["schema.version"] == "1.9.0"
    assert catalog["reuses_lab_mcp_001_queries"] == list(REUSED)
    query = catalog["queries"][0]
    assert query["id"] == "Q-GOAL-INTEGRITY-AUTHORITY"
    spl = (GOAL / query["spl_file"]).read_text(encoding="utf-8")
    doc = (GOAL / query["doc_file"]).read_text(encoding="utf-8")
    assert spl.startswith("index=agentsec_telemetry")
    assert "__RUN_ID__" in spl
    assert "CTRL-GOAL-INTEGRITY-001" in spl
    assert "CTRL-MCP-001" in spl
    assert "agentsec.task.hash" in spl
    assert "agentsec.instruction.trust" in spl
    assert "agentsec.goal.proposed" in spl
    assert "agentsec.content.hash" in spl
    assert 'hop="1"' in spl
    assert "goal_snapshot_hash" in spl
    assert "no_indexed_followon_execution_event" in spl
    assert "schema.version" not in spl
    assert "| rex " not in spl
    for heading in DOC_HEADINGS:
        assert heading in doc, heading
    for command in EXPENSIVE:
        assert command not in spl
    for field in PROHIBITED:
        assert field not in spl
    assert "handler count" in doc.lower() or "handler counts" in doc.lower()
    assert "Zero rows" in doc
    assert catalog["validated_runs"]["BASELINE"] == "0aced342-1295-4820-b807-9a8718d9e847"
    assert catalog["validated_runs"]["ATTACK"] == "fd994587-7e1c-4a70-8013-54cb2c85254d"
    assert catalog["validated_runs"]["RETEST"] == "605ba7c1-449b-4338-92df-7da3b704b08e"
    not_created = {item["id"] for item in catalog["queries_not_created"]}
    assert "Q-GOAL-TASK" in not_created
    assert "Q-MCP-DELEGATION" in not_created


def test_phase13c_documentation_exists():
    required = (
        DOCS / "PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md",
        DOCS / "GOAL_INTEGRITY_SPLUNK_FIELD_CONTRACT.md",
        DOCS / "GOAL_INTEGRITY_SEARCH_CONTRACT.md",
        DOCS / "learning-notes" / "goal-integrity-splunk-investigation.md",
        DOCS / "reviews" / "splunk-ko-review-goal-integrity-2026-09-18.md",
        DOCS / "IMPLEMENTATION_STATUS.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md").read_text(
        encoding="utf-8"
    )
    for needle in (
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
        "Q-GOAL-INTEGRITY-AUTHORITY",
        "DET-MCP-001",
        "DETECTION ANALYZED — NO NEW DETECTOR",
        "1.9.0",
        "COMPLETE",
        "sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c",
        "sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2",
        "sha256:6326e3be47ecf73831a06be2b718f42219e0c950d4c989de23aa558bfdc01b34",
        "0aced342-1295-4820-b807-9a8718d9e847",
        "fd994587-7e1c-4a70-8013-54cb2c85254d",
        "605ba7c1-449b-4338-92df-7da3b704b08e",
        "INTENTIONALLY VULNERABLE LAB PROFILE",
        "mvindex(mvdedup",
        "NOT INDEXED / NOT EXTRACTED",
        "Phase 13D not started",
        "No Dashboard Studio",
        "PASS — AGENT GOAL / INSTRUCTION INTEGRITY SPLUNK VALIDATED",
        "CIM NOT APPLICABLE",
        "MCP ALLOW DOES NOT MEAN",
        "props.conf",
    ):
        assert needle in phase, needle
    fields = (DOCS / "GOAL_INTEGRITY_SPLUNK_FIELD_CONTRACT.md").read_text(
        encoding="utf-8"
    )
    for field in (
        "agentsec.run.id",
        "CTRL-GOAL-INTEGRITY-001",
        "agentsec.task.hash",
        "agentsec.instruction.trust",
        "agentsec.goal.proposed",
        "mvcount",
        "1.9.0",
        "trusted_instruction",
        "NOT INDEXED / NOT EXTRACTED",
    ):
        assert field in fields, field
    notes = (DOCS / "learning-notes" / "goal-integrity-splunk-investigation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "13C" in status
    assert "SPLUNK VALIDATED" in status
    assert "DETECTION ANALYZED — NO NEW DETECTOR" in status
