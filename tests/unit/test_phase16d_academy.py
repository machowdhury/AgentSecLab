"""Phase 16D academy packaging. Learning metadata is not policy.

Pytest proves repository consistency — not LIVE Splunk, rendering, or security
effectiveness. Schema remains 1.9.0. Authorization is unchanged.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.academy import lab_row, load_curriculum, next_lab, previous_lab
from agentsec.attack_app import AcmeBankClient, create_app as create_attack_app
from agentsec.experiment import SCHEMA_VERSION
from agentsec.lab_manifest import validate_lab_manifest
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.policy import ALLOWED_SCOPES, ALLOWED_TOOLS, coded_policy

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
ATTACK_APP = ROOT / "src" / "agentsec" / "attack_app.py"
POLICY = ROOT / "src" / "agentsec" / "mcp" / "policy.py"
CURRICULUM = ROOT / "learning" / "academy" / "curriculum.json"

LIVE_LABS = (
    "LAB-PI-001",
    "LAB-MCP-001",
    "LAB-RAG-CONTEXT",
    "LAB-MEMORY-001",
    "LAB-AGENT-GOAL-INTEGRITY-001",
    "LAB-AGENT-DELEGATION-001",
    "LAB-AGENTSEC-CAPSTONE-001",
)

LIVE_VIEWS = {
    "LAB-PI-001": "ws_lab_pi_001.xml",
    "LAB-MCP-001": "ws_lab_mcp_001.xml",
    "LAB-RAG-CONTEXT": "ws_lab_rag_context.xml",
    "LAB-MEMORY-001": "ws_lab_memory_security.xml",
    "LAB-AGENT-GOAL-INTEGRITY-001": "ws_lab_agent_goal_integrity.xml",
    "LAB-AGENT-DELEGATION-001": "ws_lab_agent_delegation.xml",
    "LAB-AGENTSEC-CAPSTONE-001": "ws_lab_agentsec_capstone.xml",
}

REPLAY_VIEWS = (
    "ws_lab_mcp_003.xml",
    "ws_lab_mcp_004.xml",
    "ws_lab_mcp_005.xml",
    "ws_lab_mcp_006.xml",
    "ws_lab_mcp_catalog.xml",
    "ws_lab_scanner_runtime_evidence.xml",
)

PHASE16D_DOCS = (
    DOCS / "PHASE16D_ACADEMY_REMEDIATION.md",
    DOCS / "PHASE16D_P0_P1_IMPLEMENTATION_MATRIX.md",
    DOCS / "PHASE16D_LEARNER_JOURNEY_VALIDATION.md",
    DOCS / "PHASE16D_SPLUNK_LEARNING_VALIDATION.md",
    DOCS / "PHASE16D_SECURITY_SEMANTICS_REVIEW.md",
    DOCS / "PHASE16D_UI_UX_VALIDATION.md",
    DOCS / "learning-notes" / "agentsec-academy-getting-started.md",
)


def _view_markdown(xml_name: str) -> str:
    xml = (VIEWS / xml_name).read_text(encoding="utf-8")
    start = xml.index("<![CDATA[") + len("<![CDATA[")
    end = xml.index("]]>")
    definition = json.loads(xml[start:end].strip())
    return "\n".join(
        viz["options"]["markdown"]
        for viz in definition["visualizations"].values()
        if viz.get("type") == "splunk.markdown"
    )


def test_phase16d_docs_exist():
    for path in PHASE16D_DOCS:
        assert path.is_file(), path
    note = DOCS / "learning-notes" / "agentsec-academy-getting-started.md"
    text = note.read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in text


def test_curriculum_is_learning_metadata_not_policy():
    data = load_curriculum()
    raw = json.loads(CURRICULUM.read_text(encoding="utf-8"))
    assert data == raw
    assert data["not_authorization"] is True
    assert data["schema_version"] == "1.9.0"
    assert data["start_lab_id"] == "LAB-PI-001"
    ids = [level["id"] for level in data["levels"]]
    assert ids == ["L0", "L1", "L2", "L3", "L4", "L5"]
    assert data["nav_collections"][0]["label"] == "Foundations"
    assert data["nav_collections"][-1]["label"] == "Capstone"
    assert lab_row("LAB-PI-001")["level_id"] == "L1"
    assert next_lab("LAB-PI-001")["lab_id"] == "LAB-MCP-001"
    assert previous_lab("LAB-PI-001") is None
    assert next_lab("LAB-AGENTSEC-CAPSTONE-001") is None
    assert previous_lab("LAB-AGENTSEC-CAPSTONE-001")["lab_id"] == "LAB-MCP-006"


def test_nav_follows_learner_curriculum_not_build_order():
    nav = NAV.read_text(encoding="utf-8")
    assert 'name="ws_agentsec_home" default="true"' in nav
    for label in ("Foundations", "Context Security", "Agent Intent", "Capstone"):
        assert f'<collection label="{label}">' in nav
    assert "Attack Labs" not in nav
    assert "Agent Authority" not in nav
    assert "Supply Chain" not in nav
    assert not re.search(r"<view name=\"ws_lab_[^\"]+\" default=", nav)
    assert nav.index("ws_lab_pi_001") < nav.index("ws_lab_mcp_001")
    assert nav.index("ws_lab_mcp_001") < nav.index("ws_lab_rag_context")
    assert nav.index("ws_lab_agent_delegation") < nav.index("ws_lab_agentsec_capstone")
    assert ">Direct Prompt Injection</view>" in nav
    assert ">Lending Assistant Investigation</view>" in nav
    assert ">Mastery Check</view>" in nav
    for lab_id in LIVE_LABS:
        assert lab_id not in nav


def test_live_labs_keep_manifests_path_a_path_b_and_human_titles():
    assert known_lab_ids() == frozenset(LIVE_LABS)
    for lab_id in LIVE_LABS:
        manifest = validate_lab_manifest(lab_id)
        assert manifest["not_authorization"] is True
        assert not str(manifest["title"]).startswith("LAB-")
        prediction = manifest["prediction"]["ATTACK"]
        assert prediction.get("predict_before_launch")
        assert prediction.get("what_will_not_change")
        inv_path = ROOT / "learning" / "level_1" / lab_id / "investigations.json"
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        assert inv["not_authorization"] is True
        assert inv["path_a"]
        assert inv["path_b"]
        view = LIVE_VIEWS[lab_id]
        md = _view_markdown(view)
        assert "Path A" in md, lab_id
        assert "Path B" in md, lab_id
        assert "YOU JUST LEARNED" in md or "Before you start" in md, lab_id


def test_replay_hunts_disclose_path_a_before_bound_tables():
    for name in REPLAY_VIEWS:
        md = _view_markdown(name)
        assert "REPLAY workshop" in md or "Path A" in md, name
        assert "Path B" in md, name
        assert "not policy" in md.lower(), name


def test_capstone_is_graduation_not_mid_path():
    md = _view_markdown("ws_lab_agentsec_capstone.xml")
    assert "Before you start" in md
    assert "review key" in md.lower()
    assert "Debrief" in md
    assert "CTRL-MCP-001" in md
    home = _view_markdown("ws_agentsec_home.xml")
    assert "Lending Assistant Investigation" in home
    assert "graduation" in home.lower() or "Capstone" in home


def test_home_orientation_and_splunk_bootcamp():
    md = _view_markdown("ws_agentsec_home.xml")
    for needle in (
        "hands-on Agentic Security academy",
        "LLM",
        "MCP",
        "RAG",
        "PDP",
        "LIVE",
        "REPLAY",
        "BASELINE",
        "Splunk does **not** grant",
        "index=agentsec_telemetry",
        "agentsec.run.id",
        "FOUNDATIONAL",
        "PRACTITIONER",
        "INVESTIGATOR",
        "ADVANCED / PURPLE TEAM",
        "Start here",
    ):
        assert needle in md, needle
    assert "not published" not in md.lower()
    assert "| --- |" not in md


def test_schema_unchanged_no_new_detector_no_authz_mutation():
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
    assert "LAB-MCP-003" not in ATTACK_APP.read_text(encoding="utf-8")


def test_curriculum_is_copied_for_attack_service_image():
    dockerfile = (ROOT / "docker" / "Dockerfile.attack").read_text(encoding="utf-8")
    assert "learning/academy/curriculum.json" in dockerfile
    assert CURRICULUM.is_file()


def test_attack_service_academy_strip_is_educational_not_authority():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/").get_data(as_text=True)
    assert "Where you are" in html
    assert "Input and tool authority" in html
    assert "WHAT THE ATTACKER DOES NOT CONTROL" in html
    assert "WHAT SHOULD REMAIN SERVER-OWNED" in html
    assert "Predict before ATTACK" in html
    assert "Direct Prompt Injection" in html
    assert "Tool Authorization" in html
    assert "profile: profile" not in html
    mcp = client.get("/labs/LAB-MCP-001").get_data(as_text=True)
    assert "Scope Escalation" in mcp
    assert "REPLAY" in mcp
    cap = client.get("/labs/LAB-AGENTSEC-CAPSTONE-001").get_data(as_text=True)
    assert "Capstone is the last LIVE launcher." in cap
    assert "does not authorize" in html


def test_status_records_16d_without_rewriting_16c_audit_only():
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    learning = (DOCS / "AGENTSEC_LEARNING_ARCHITECTURE.md").read_text(encoding="utf-8")
    hub_16c = (DOCS / "PHASE16C_AGENTSEC_ACADEMY_AUDIT.md").read_text(encoding="utf-8")
    assert "16D" in status
    assert "DESIGN / AUDIT" in status
    assert "Do not start Phase 16D" in hub_16c
    assert "Do not start Phase 16D from this file" in roadmap
    assert "PHASE16D_ACADEMY_REMEDIATION.md" in learning
    assert "Do not start Phase 17A" in roadmap
