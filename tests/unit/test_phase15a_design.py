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
        "LAB-LOANDESK-001",  # Batch 4: first-class Academy mission
        "LAB-PI-001",
        "LAB-MCP-001",
        "LAB-MCP-003",
        "LAB-MCP-004",
        "LAB-MCP-005",
        "LAB-MCP-006",
        "LAB-MCP-CATALOG",
        "LAB-SCANNER-RUNTIME-EVIDENCE",
        "LAB-EXTERNAL-EVALUATION-GARAK",
        "LAB-RAG-CONTEXT",
        "LAB-MEMORY-001",
        "LAB-AGENT-DELEGATION-001",
        "LAB-AGENT-GOAL-INTEGRITY-001",
        "LAB-AGENTSEC-CAPSTONE-001",
        "LAB-SPLUNK-DEFENDER-BRIDGE",
        "LAB-DETECTION-ENGINEERING",
        "LAB-AGENT-IDENTITY-NHI",
        "LAB-A2A-AUTH-DELEGATION",
        "LAB-HITL-APPROVAL",
        "LAB-CREDENTIAL-LIFETIME",
        "LAB-RAG-PURPOSE",
        "LAB-RECALL-ISOLATION",
        "LAB-ASSET-INVENTORY",
        "LAB-COMPONENT-PROVENANCE",
        "LAB-CODE-AGENT-BOUNDS",
        "LAB-CHANGE-BOUNDS",
        "LAB-BLUE-TEAM-INCIDENT-001",
        "LAB-THREAT-MODELING-001",
        "LAB-PRIVACY-DATA-GOVERNANCE-001",
        "LAB-MULTI-STAGE-INCIDENT-001",
        "LAB-ADVANCED-CAPSTONE-MASTERY-001",
    }
)

PUBLISHED_VIEWS = frozenset(
    {
        "ws_lab_loandesk_001.xml",  # Batch 4
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
        "ws_lab_splunk_defender_bridge.xml",
        "ws_lab_blue_team_incident.xml",
        "ws_lab_detection_engineering.xml",
        "ws_lab_agent_identity_nhi.xml",
        "ws_lab_a2a_auth_delegation.xml",
        "ws_lab_hitl_approval.xml",
        "ws_lab_credential_lifetime.xml",
        "ws_lab_purpose_authorization.xml",
        "ws_lab_recall_isolation.xml",
        "ws_lab_asset_inventory.xml",
        "ws_lab_component_provenance.xml",
        "ws_lab_code_agent_bounds.xml",
        "ws_lab_change_bounds.xml",
        "ws_lab_threat_modeling.xml",
        "ws_lab_privacy_data_governance.xml",
        "ws_lab_multi_stage_incident.xml",
        "ws_lab_advanced_capstone.xml",
        "ws_agentsec_mastery.xml",
        "ws_agentsec_arena.xml",
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








def test_attack_service_allowlist_excludes_unmigrated_labs():
    migrated = {"LAB-PI-001", "LAB-MCP-001", "LAB-RAG-CONTEXT", "LAB-MEMORY-001", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001",
                "LAB-AGENTSEC-CAPSTONE-001",
                "LAB-MCP-003", "LAB-MCP-004", "LAB-MCP-005", "LAB-MCP-CATALOG", "LAB-MCP-006"}      # the four MCP workshops launch through the same /mcp/invoke path as LAB-MCP-001
    assert known_lab_ids() == frozenset(migrated)
    manifests = list(LEARNING.rglob("lab-manifest.json"))
    assert {p.parent.name for p in manifests} == migrated | {"LAB-LOANDESK-001"}      # LOANDESK: manifest only; it is NOT in the /api/launch allowlist
    attack = ATTACK_APP.read_text(encoding="utf-8")
    assert "LAB-MCP-003" not in attack                  # the classic Attack UI lists only the labs it renders itself; the four MCP workshops launch from the Academy
    launch = LAUNCH.read_text(encoding="utf-8")
    assert "LAB-MCP-003" not in launch
    experiment = EXPERIMENT.read_text(encoding="utf-8")
    assert 'LAB_MCP = "LAB-MCP-001"' in experiment
    assert 'LAB_MCP_003 = "LAB-MCP-003"' in experiment
    assert "LAB-RAG-CONTEXT" in experiment
    assert "LAB-MEMORY-001" in experiment
    assert "LAB-AGENT-GOAL-INTEGRITY-001" in experiment
    assert "LAB-AGENT-DELEGATION-001" in experiment


    # 15A design docs do not invent ws_lab_capstone.xml. Phase 16B publishes
    # ws_lab_agentsec_capstone.xml on disk.




    # Negations such as "no DET-GOAL" are allowed; operational files are not.




