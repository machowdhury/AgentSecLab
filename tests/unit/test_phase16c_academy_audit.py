"""Phase 16C is academy audit / design only.

Does not add attacks, detectors, schema bumps, or authorization changes.
Pytest proves repository consistency — not LIVE Splunk or runtime security.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.investigations import validate_investigations
from agentsec.lab_manifest import validate_lab_manifest
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.policy import ALLOWED_SCOPES, ALLOWED_TOOLS, coded_policy

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
LEARNING = ROOT / "learning" / "level_1"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
ATTACK_APP = ROOT / "src" / "agentsec" / "attack_app.py"
BANK_APP = ROOT / "src" / "agentsec" / "bank_app.py"
POLICY = ROOT / "src" / "agentsec" / "mcp" / "policy.py"

LIVE_LABS = (
    "LAB-PI-001",
    "LAB-MCP-001",
    "LAB-RAG-CONTEXT",
    "LAB-MEMORY-001",
    "LAB-AGENT-GOAL-INTEGRITY-001",
    "LAB-AGENT-DELEGATION-001",
    "LAB-AGENTSEC-CAPSTONE-001",
)

PUBLISHED_VIEWS = frozenset(
    {
        "ws_agentsec_home.xml",
        "ws_lab_pi_001.xml",
        "ws_lab_mcp_001.xml",
        "ws_lab_mcp_003.xml",
        "ws_lab_mcp_004.xml",
        "ws_lab_mcp_005.xml",
        "ws_lab_mcp_006.xml",
        "ws_lab_mcp_catalog.xml",
        "ws_lab_rag_context.xml",
        "ws_lab_memory_security.xml",
        "ws_lab_agent_goal_integrity.xml",
        "ws_lab_agent_delegation.xml",
        "ws_lab_scanner_runtime_evidence.xml",
        "ws_lab_external_evaluation_garak.xml",
        "ws_lab_agentsec_capstone.xml",
        "ws_agentsec_mastery.xml",
    }
)

PHASE16C_DOCS = (
    DOCS / "PHASE16C_AGENTSEC_ACADEMY_AUDIT.md",
    DOCS / "AGENTSEC_CURRICULUM_MAP.md",
    DOCS / "AGENTSEC_SECURITY_KNOWLEDGE_GRAPH.md",
    DOCS / "AGENTSEC_COMPETENCY_MODEL.md",
    DOCS / "AGENTSEC_SPLUNK_SKILL_PROGRESSION.md",
    DOCS / "AGENTSEC_ASSESSMENT_MODEL.md",
    DOCS / "AGENTSEC_LIVE_LAB_MATRIX.md",
    DOCS / "AGENTSEC_GRADUATE_PROFILE.md",
    DOCS / "AGENTSEC_NEXT_BUILD_GAP_MATRIX.md",
    DOCS / "learning-notes" / "agentsec-learning-journey.md",
)


def test_phase16c_design_docs_exist():
    for path in PHASE16C_DOCS:
        assert path.is_file(), path
    note = DOCS / "learning-notes" / "agentsec-learning-journey.md"
    text = note.read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in text


def test_phase16c_is_audit_only_and_forbids_16d_implementation():
    hub = (DOCS / "PHASE16C_AGENTSEC_ACADEMY_AUDIT.md").read_text(encoding="utf-8")
    for needle in (
        "DESIGN / AUDIT",
        "Do not start Phase 16D",
        "OPTION B",
        "1.9.0",
        "NO DET-CAPSTONE",
        "SPLUNK ≠ ENFORCEMENT",
        "Path A",
        "Path B",
        "LAB-AGENTSEC-CAPSTONE-001",
    ):
        assert needle in hub, needle
    matrix = (DOCS / "AGENTSEC_NEXT_BUILD_GAP_MATRIX.md").read_text(encoding="utf-8")
    assert "Do not implement from this file" in matrix


def test_all_published_workshop_views_resolve():
    names = {path.name for path in VIEWS.glob("ws_*.xml")}
    assert names == PUBLISHED_VIEWS, names ^ PUBLISHED_VIEWS
    nav = NAV.read_text(encoding="utf-8")
    for name in sorted(PUBLISHED_VIEWS):
        stem = name.removesuffix(".xml")
        assert f'name="{stem}"' in nav, stem
        assert (VIEWS / name).is_file()


def test_nav_uses_human_titles_not_top_level_lab_ids():
    nav = NAV.read_text(encoding="utf-8")
    labels = re.findall(r"<view name=\"[^\"]+\">([^<]+)</view>", nav)
    assert labels
    for label in labels:
        assert not label.startswith("LAB-"), label
    assert "Lending Assistant Investigation" in nav
    assert "Direct Prompt Injection" in nav
    assert "LAB-AGENTSEC-CAPSTONE-001" not in nav


def test_every_live_lab_has_valid_manifest_and_investigations():
    assert known_lab_ids() == frozenset(LIVE_LABS)
    for lab_id in LIVE_LABS:
        manifest = validate_lab_manifest(lab_id)
        assert manifest["lab_id"] == lab_id
        assert manifest.get("title"), lab_id
        assert not str(manifest["title"]).startswith("LAB-"), lab_id
        assert manifest.get("not_authorization") is True, lab_id
        assert "Splunk does not" in json.dumps(manifest), lab_id
        rows = validate_investigations(lab_id)
        assert rows
        inv = json.loads(
            (LEARNING / lab_id / "investigations.json").read_text(encoding="utf-8")
        )
        assert inv.get("not_authorization") is True, lab_id
        assert inv.get("path_a"), lab_id
        assert inv.get("path_b"), lab_id


def test_schema_remains_1_9_0_and_no_new_detector():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    operational = {path.stem for path in LEARNING.rglob("DET-*.spl")}
    for banned in (
        "DET-CAPSTONE",
        "DET-RAG",
        "DET-MEMORY",
        "DET-GOAL",
        "DET-A2A",
        "DET-SCANNER",
        "DET-MCP-005",
    ):
        assert banned not in operational, banned
    saved = SAVED.read_text(encoding="utf-8")
    assert saved.count("[AgentSec -") == 1
    assert "DET-CAPSTONE" not in saved
    assert "MCP Execution After Authorization Deny" in saved


def test_authorization_semantics_unchanged():
    policy = coded_policy()
    assert policy.allowed_tools == frozenset({"lookup_policy"}) == ALLOWED_TOOLS
    assert policy.allowed_scopes == frozenset({"policy:read"}) == ALLOWED_SCOPES
    bank = BANK_APP.read_text(encoding="utf-8")
    assert '@app.post("/capstone' not in bank
    assert '@app.post("/a2a' not in bank
    policy_src = POLICY.read_text(encoding="utf-8")
    assert "ALLOWED_TOOLS = frozenset({\"lookup_policy\"})" in policy_src
    attack = ATTACK_APP.read_text(encoding="utf-8")
    assert "LAB-MCP-003" not in attack


def test_security_semantics_gate_in_16c_docs():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in PHASE16C_DOCS)
    for needle in (
        "OBSERVE ≠ ALLOW",
        "ALLOW ≠ EXECUTION",
        "MISSING EVENT ≠ PREVENTION",
        "BASELINE ≠ SAFE",
        "0 rows ≠ SAFE",
        "WHO AUTHENTICATED",
        "DATA ≠ AUTHORITY",
        "REQUEST ≠ GRANT",
    ):
        assert needle in blob, needle
    assert "must not" in blob.lower()
    assert "Splunk blocked the attack" in blob


def test_status_records_16c_audit_only():
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    learning = (DOCS / "AGENTSEC_LEARNING_ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "16C" in status
    assert "DESIGN" in status
    assert "Phase 16C" in roadmap
    assert "Do not start Phase 16D" in roadmap
    assert "PHASE16C_AGENTSEC_ACADEMY_AUDIT.md" in learning
