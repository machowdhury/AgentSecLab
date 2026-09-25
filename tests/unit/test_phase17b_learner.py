"""Phase 17B fresh-learner usability. Copy-only. Schema 1.9.0. Authorization unchanged.

Pytest proves repository consistency — not LIVE Splunk, rendering, or learner
comprehension.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.academy import LIVE_INVESTIGATE_GATE, REPLAY_HUNT_BANNER, load_assessments
from agentsec.attack_app import AcmeBankClient, create_app as create_attack_app
from agentsec.experiment import SCHEMA_VERSION
from agentsec.mcp.policy import ALLOWED_SCOPES, ALLOWED_TOOLS, coded_policy

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
POLICY = ROOT / "src" / "agentsec" / "mcp" / "policy.py"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
ATTACK_HTML = ROOT / "src" / "agentsec" / "templates" / "attack.html"
HOME_XML = VIEWS / "ws_agentsec_home.xml"
MASTERY_XML = VIEWS / "ws_agentsec_mastery.xml"
GOAL_XML = VIEWS / "ws_lab_agent_goal_integrity.xml"
CAPSTONE_XML = VIEWS / "ws_lab_agentsec_capstone.xml"
MEMORY_XML = VIEWS / "ws_lab_memory_security.xml"
PI_XML = VIEWS / "ws_lab_pi_001.xml"
MCP001_XML = VIEWS / "ws_lab_mcp_001.xml"
MCP003_XML = VIEWS / "ws_lab_mcp_003.xml"
MCP004_XML = VIEWS / "ws_lab_mcp_004.xml"
MCP005_XML = VIEWS / "ws_lab_mcp_005.xml"
MCP006_XML = VIEWS / "ws_lab_mcp_006.xml"
CATALOG_XML = VIEWS / "ws_lab_mcp_catalog.xml"
SCANNER_XML = VIEWS / "ws_lab_scanner_runtime_evidence.xml"
EXTERNAL_TOOLBOX_XML = VIEWS / "ws_lab_external_evaluation_garak.xml"

REPLAY_VIEWS = (
    MCP003_XML,
    MCP004_XML,
    MCP005_XML,
    MCP006_XML,
    CATALOG_XML,
    SCANNER_XML,
    EXTERNAL_TOOLBOX_XML,
)

PHASE17B_DOCS = (
    DOCS / "PHASE17B_FRESH_LEARNER_VALIDATION.md",
    DOCS / "AGENTSEC_FRESH_LEARNER_FRICTION_LOG.md",
    DOCS / "AGENTSEC_INSTRUCTIONAL_QUALITY_MATRIX.md",
    DOCS / "AGENTSEC_LEARNER_JOURNEY.md",
    DOCS / "AGENTSEC_SPLUNK_NOTEBOOK_EXPERIENCE.md",
    DOCS / "AGENTSEC_ATTACK_LEARNING_EXPERIENCE.md",
    DOCS / "AGENTSEC_LIVE_REPLAY_LEARNER_GUIDE.md",
    DOCS / "AGENTSEC_TROUBLESHOOTING_FOR_LEARNERS.md",
    DOCS / "learning-notes" / "learning-agentic-security-with-agentsec.md",
    DOCS / "reviews" / "ui-review-agentsec-academy-17b-2026-09-21.md",
)


def _xml(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_schema_and_authorization_frozen():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    policy = coded_policy()
    assert policy.allowed_tools == frozenset({"lookup_policy"}) == ALLOWED_TOOLS
    assert policy.allowed_scopes == frozenset({"policy:read"}) == ALLOWED_SCOPES
    policy_src = POLICY.read_text(encoding="utf-8")
    assert "ALLOWED_TOOLS = frozenset({\"lookup_policy\"})" in policy_src
    saved = SAVED.read_text(encoding="utf-8")
    assert saved.count("[AgentSec -") == 1
    assert "DET-CAPSTONE" not in saved
    assert "DET-LEARNER" not in saved
    assessments = load_assessments()
    assert assessments["not_authorization"] is True
    assert assessments["schema_version"] == "1.9.0"


def test_why_before_click_on_goal_and_capstone_attack():
    goal = _xml(GOAL_XML)
    assert "WHY ARE WE DOING THIS?" in goal
    assert "WHAT DO YOU PREDICT?" in goal
    assert "AUTHORIZED TOOL != AUTHORIZED GOAL" in goal
    assert "Phase 15D" not in goal
    cap = _xml(CAPSTONE_XML)
    assert "WHY ARE WE DOING THIS?" in cap
    assert "WHAT DO YOU PREDICT?" in cap
    assert "ws_agentsec_mastery" in cap
    assert "not a certificate" in cap.lower()


def test_replay_labs_are_not_labeled_live_evidence():
    for path in REPLAY_VIEWS:
        text = _xml(path)
        assert "**LIVE EVIDENCE**" not in text, path.name
        assert "REPLAY SPECIMEN" in text or "REPLAY workshop" in text, path.name
        assert "historical evidence" in text, path.name
        assert "Empty is not DENY" in text, path.name


def test_replay_hunt_banner_explains_output():
    assert "historical evidence" in REPLAY_HUNT_BANNER
    assert "Empty is not DENY" in REPLAY_HUNT_BANNER
    assert "IT DOES NOT MEAN" in REPLAY_HUNT_BANNER
    assert "EVIDENCE READY" in LIVE_INVESTIGATE_GATE
    assert "Empty is not DENY" in LIVE_INVESTIGATE_GATE


def test_memory_attack_cta_and_two_run_teaching():
    mem = _xml(MEMORY_XML)
    assert "Launch ATTACK (LIVE)" in mem
    assert "LAB-MEMORY-001]" not in mem
    assert "RECALL" in mem
    assert "source_run_id" in mem or "source_run" in mem
    assert "Phase 15D not started" not in mem
    assert "Goal Integrity is a later lab" in mem


def test_empty_search_is_not_deny():
    pi = _xml(PI_XML)
    assert "EVIDENCE READY" in pi
    assert "Empty is not prevention" in pi or "not DENY" in pi
    html = ATTACK_HTML.read_text(encoding="utf-8")
    assert "EVIDENCE READY" in html
    assert "Empty Search is not DENY" in html
    assert "Mastery Check" in html
    assert "Capstone is the last LIVE launcher." in html


def test_home_skip_and_required_terms():
    home = _xml(HOME_XML)
    assert "If you already know agents" in home
    assert "overlay" in home.lower()
    assert "Fingerprint" in home
    assert "source_run_id" in home


def test_mastery_none_does_not_require_search():
    mastery = _xml(MASTERY_XML)
    assert "You do not need Splunk Search for this challenge" in mastery
    assert "Open Splunk Search" in mastery
    assert "Who enforces" in mastery


def test_learner_surfaces_do_not_require_repo_paths():
    for path in (MCP001_XML, MCP003_XML, MCP004_XML, GOAL_XML, MEMORY_XML, PI_XML):
        text = _xml(path)
        assert "src/agentsec/mcp/authorize.py" not in text, path.name
        assert "knowledge-check.md" not in text, path.name


def test_attack_service_wait_copy_is_served():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/").get_data(as_text=True)
    assert "EVIDENCE READY" in html
    assert "Empty Search is not DENY" in html
    cap = client.get("/labs/LAB-AGENTSEC-CAPSTONE-001").get_data(as_text=True)
    assert "Capstone is the last LIVE launcher." in cap
    assert "Mastery Check" in cap


def test_phase17b_docs_exist():
    for path in PHASE17B_DOCS:
        assert path.is_file(), path.name
    note = DOCS / "learning-notes" / "learning-agentic-security-with-agentsec.md"
    text = note.read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in text


def test_status_records_17b_without_starting_17c():
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    assert "17B" in status
    assert "Do not start Phase 17C" in roadmap
    hub_17a = (DOCS / "PHASE17A_LEARNER_MASTERY_VALIDATION.md").read_text(encoding="utf-8")
    assert "Do not start Phase 17B from this file" in hub_17a
