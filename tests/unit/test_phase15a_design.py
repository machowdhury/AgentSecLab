"""Phase 15A is curriculum architecture / design only.

Does not migrate labs, Studio, Attack Service launchers, detectors, or schema.
Pytest proves repository consistency only — not LIVE, Splunk, or runtime validation.
"""

from __future__ import annotations

import re
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.launch_catalog import known_lab_ids

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
LEARNING = ROOT / "learning" / "level_1"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
ATTACK_APP = ROOT / "src" / "agentsec" / "attack_app.py"
LAUNCH = ROOT / "src" / "agentsec" / "launch_catalog.py"
EXPERIMENT = ROOT / "src" / "agentsec" / "experiment_context.py"

PHASE15A_DOCS = (
    DOCS / "PHASE15A_AGENTSEC_CURRICULUM_ARCHITECTURE.md",
    DOCS / "AGENTSEC_EXISTING_LAB_INVENTORY.md",
    DOCS / "AGENTSEC_SECURITY_REASONING_MODEL.md",
    DOCS / "AGENTSEC_COMPETENCY_MODEL.md",
    DOCS / "AGENTSEC_CURRICULUM_LEVELS.md",
    DOCS / "AGENTSEC_LAB_MIGRATION_MATRIX.md",
    DOCS / "AGENTSEC_SPLUNK_SKILL_PROGRESSION.md",
    DOCS / "AGENTSEC_ATTACK_SERVICE_MIGRATION_STRATEGY.md",
    DOCS / "AGENTSEC_CAPSTONE_DESIGN.md",
    DOCS / "AGENTSEC_CURRICULUM_INFORMATION_ARCHITECTURE.md",
    DOCS / "learning-notes" / "how-to-learn-agentic-security-with-agentsec.md",
)

INVENTORIED_LABS = frozenset(
    {
        "LAB-PI-001",
        "LAB-MCP-001",
        "LAB-MCP-003",
        "LAB-MCP-004",
        "LAB-MCP-005",
        "LAB-MCP-006",
        "LAB-MCP-CATALOG",
        "LAB-SCANNER-RUNTIME-EVIDENCE",
        "LAB-RAG-CONTEXT",
        "LAB-MEMORY-001",
        "LAB-AGENT-DELEGATION-001",
        "LAB-AGENT-GOAL-INTEGRITY-001",
        "LAB-AGENTSEC-CAPSTONE-001",
    }
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
        "ws_lab_agentsec_capstone.xml",
        "ws_agentsec_mastery.xml",
    }
)

Q_REFS = (
    "Q-RUN-EVENTS",
    "Q-CONTROL-DECISION",
    "Q-LLM-EXECUTED",
    "Q-LLM-AFTER-DENY",
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-SCOPE",
    "Q-MCP-PARAMS",
    "Q-MCP-RESULT",
    "Q-MCP-RESULT-TRUST",
    "Q-MCP-RESOURCE-AUTHZ",
    "Q-MCP-RESULT-AUTHORITY",
    "Q-MCP-DELEGATION",
    "Q-MCP-CATALOG-AUTHORITY",
    "Q-SCANNER-WHO",
    "Q-SCANNER-ARTIFACT",
    "Q-SCANNER-FINDINGS",
    "Q-SCANNER-RUNTIME-CORRELATION",
    "Q-RAG-CONTEXT-AUTHORITY",
    "Q-MEMORY-CONTEXT-AUTHORITY",
    "Q-AGENT-DELEGATION-AUTHORITY",
    "Q-GOAL-INTEGRITY-AUTHORITY",
)


def _blob() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in PHASE15A_DOCS)


def test_phase15a_design_docs_exist():
    for path in PHASE15A_DOCS:
        assert path.is_file(), path


def test_phase15a_is_design_only_and_forbids_15b():
    blob = _blob()
    for needle in (
        "DESIGN",
        "Do not start Phase 15B",
        "Do not implement",
        "REQUEST ≠ GRANT",
        "SPLUNK ≠ ENFORCEMENT",
        "LAB-PI-001",
        "LAB-MCP-001",
        "LAB-MCP-003",
        "LAB-MCP-004",
        "LIVE",
        "REPLAY",
        "SIMULATED",
        "Path A",
        "Path B",
        "FOUNDATION",
        "ARCHITECT",
        "Wave 1",
        "DET-MCP-001",
        "NONE JUSTIFIED",
        "ANOMALY != INCIDENT",
        "Learning metadata",
        "capstone",
    ):
        assert needle in blob, needle
    hub = (DOCS / "PHASE15A_AGENTSEC_CURRICULUM_ARCHITECTURE.md").read_text(
        encoding="utf-8"
    )
    assert "1.9.0" in hub
    assert "LAB-MCP-003 then LAB-MCP-004" in hub
    note = (
        DOCS / "learning-notes" / "how-to-learn-agentic-security-with-agentsec.md"
    ).read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in note


def test_inventoried_labs_match_repository_directories():
    on_disk = {p.name for p in LEARNING.iterdir() if p.is_dir() and p.name.startswith("LAB-")}
    assert on_disk == INVENTORIED_LABS, on_disk ^ INVENTORIED_LABS
    inventory = (DOCS / "AGENTSEC_EXISTING_LAB_INVENTORY.md").read_text(encoding="utf-8")
    for lab_id in INVENTORIED_LABS:
        assert lab_id in inventory, lab_id


def test_attack_service_allowlist_excludes_unmigrated_labs():
    assert known_lab_ids() == frozenset(
        {
            "LAB-PI-001",
            "LAB-MCP-001",
            "LAB-RAG-CONTEXT",
            "LAB-MEMORY-001",
            "LAB-AGENT-GOAL-INTEGRITY-001",
        "LAB-AGENT-DELEGATION-001",
        "LAB-AGENTSEC-CAPSTONE-001",
    }
)
    manifests = list(LEARNING.rglob("lab-manifest.json"))
    assert {p.parent.name for p in manifests} == {
        "LAB-PI-001",
        "LAB-MCP-001",
        "LAB-RAG-CONTEXT",
        "LAB-MEMORY-001",
        "LAB-AGENT-GOAL-INTEGRITY-001",
        "LAB-AGENT-DELEGATION-001",
        "LAB-AGENTSEC-CAPSTONE-001",
    }
    attack = ATTACK_APP.read_text(encoding="utf-8")
    assert "LAB-MCP-003" not in attack
    assert "LAB-MCP-004" not in attack
    launch = LAUNCH.read_text(encoding="utf-8")
    assert "LAB-MCP-003" not in launch
    experiment = EXPERIMENT.read_text(encoding="utf-8")
    assert 'LAB_MCP = "LAB-MCP-001"' in experiment
    assert "LAB-MCP-003" not in experiment
    assert "LAB-RAG-CONTEXT" in experiment
    assert "LAB-MEMORY-001" in experiment
    assert "LAB-AGENT-GOAL-INTEGRITY-001" in experiment
    assert "LAB-AGENT-DELEGATION-001" in experiment


def test_studio_views_match_inventory_no_invented_identity_or_capstone_view():
    names = {path.name for path in VIEWS.glob("ws_*.xml")}
    assert names == PUBLISHED_VIEWS, names ^ PUBLISHED_VIEWS
    blob = _blob()
    assert "ws_lab_identity" not in blob
    assert "ws_lab_capstone" not in blob
    assert "ws_attack_simulator.xml" not in names
    # 15A design docs do not invent ws_lab_capstone.xml. Phase 16B publishes
    # ws_lab_agentsec_capstone.xml on disk.


def test_curriculum_q_star_references_exist_as_spl():
    spl_names = {path.stem for path in LEARNING.rglob("Q-*.spl")}
    for hunt in Q_REFS:
        assert hunt in spl_names, hunt
    blob = _blob()
    mentioned = set(re.findall(r"\bQ-[A-Z0-9]+(?:-[A-Z0-9]+)+\b", blob))
    missing = {name for name in mentioned if name not in spl_names}
    assert not missing, missing


def test_no_invented_detectors_or_operational_det_besides_mcp001():
    operational = list(LEARNING.rglob("DET-*.spl"))
    operational_stems = {p.stem for p in operational}
    allowed = {
        "DET-MCP-001",
        "DET-MCP-001-POSITIVE-CONTROL",
        "DET-MCP-001-SCOPE-POSITIVE-CONTROL",
        "DET-MCP-001-RESOURCE-POSITIVE-CONTROL",
    }
    assert "DET-MCP-001" in operational_stems
    extra = operational_stems - allowed
    assert not extra, extra
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-GOAL" not in saved
    assert "DET-RAG" not in saved
    assert "DET-MEMORY" not in saved
    assert "DET-MCP-CATALOG" not in saved
    blob = _blob()
    assert "DET-PI-002" not in blob
    assert "DET-CAPSTONE" not in blob
    assert "DET-MCP-NEW" not in blob
    # Negations such as "no DET-GOAL" are allowed; operational files are not.


def test_schema_and_controls_unchanged_by_15a():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "15A" in status
    assert "DESIGN" in status
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    assert "Do not start Phase 15B" in roadmap
    assert "Phase 15A" in roadmap
    learning = (DOCS / "AGENTSEC_LEARNING_ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "AGENTSEC_CURRICULUM_LEVELS.md" in learning
    assert "14E" in learning


def test_invariants_and_controls_in_inventory_are_existing_ids():
    inventory = (DOCS / "AGENTSEC_EXISTING_LAB_INVENTORY.md").read_text(encoding="utf-8")
    for token in (
        "INV-001",
        "INV-002",
        "INV-003",
        "INV-005",
        "INV-006",
        "INV-007",
        "INV-008",
        "CTRL-INPUT-001",
        "CTRL-MCP-001",
        "CTRL-MCP-METADATA-001",
        "CTRL-MCP-RESULT-001",
        "CTRL-DELEGATION-001",
        "CTRL-RAG-CONTEXT-001",
        "CTRL-MEMORY-CONTEXT-001",
        "CTRL-IDENTITY-001",
        "CTRL-GOAL-INTEGRITY-001",
    ):
        assert token in inventory, token
    assert "INV-009" not in inventory
    assert "no CTRL-MCP-003" in inventory
