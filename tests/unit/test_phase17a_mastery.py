"""Phase 17A learner mastery / assessment. Learning metadata is not policy.

Pytest proves repository consistency — not LIVE Splunk, rendering, or security
effectiveness. Schema remains 1.9.0. Authorization is unchanged.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.academy import (
    ASSESSMENTS_PATH,
    challenges_for,
    hunt_path,
    load_assessments,
    load_curriculum,
    path_b_spl,
    validate_assessments,
)
from agentsec.attack_app import AcmeBankClient, create_app as create_attack_app
from agentsec.experiment import SCHEMA_VERSION
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.policy import ALLOWED_SCOPES, ALLOWED_TOOLS, coded_policy

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
ATTACK_APP = ROOT / "src" / "agentsec" / "attack_app.py"
BANK_APP = ROOT / "src" / "agentsec" / "bank_app.py"
POLICY = ROOT / "src" / "agentsec" / "mcp" / "policy.py"
DOCKERFILE = ROOT / "docker" / "Dockerfile.attack"
DEFINITION = ROOT / "learning" / "academy" / "mastery.definition.json"
VIEW_XML = VIEWS / "ws_agentsec_mastery.xml"

LIVE_LABS = (
    "LAB-PI-001",
    "LAB-MCP-001",
    "LAB-RAG-CONTEXT",
    "LAB-MEMORY-001",
    "LAB-AGENT-GOAL-INTEGRITY-001",
    "LAB-AGENT-DELEGATION-001",
    "LAB-AGENTSEC-CAPSTONE-001",
)

PHASE17A_DOCS = (
    DOCS / "PHASE17A_LEARNER_MASTERY_VALIDATION.md",
    DOCS / "AGENTSEC_ASSESSMENT_MODEL.md",
    DOCS / "AGENTSEC_MASTERY_RUBRIC.md",
    DOCS / "AGENTSEC_CAPSTONE_ASSESSMENT.md",
    DOCS / "AGENTSEC_SPLUNK_INVESTIGATION_ASSESSMENT.md",
    DOCS / "AGENTSEC_SECURITY_REASONING_ASSESSMENT.md",
    DOCS / "PHASE17A_FRESH_LEARNER_WALKTHROUGH.md",
    DOCS / "PHASE17A_ADVANCED_LEARNER_WALKTHROUGH.md",
    DOCS / "PHASE17A_UI_UX_VALIDATION.md",
    DOCS / "learning-notes" / "agentsec-mastery-and-assessment.md",
)


def _definition() -> dict:
    xml = VIEW_XML.read_text(encoding="utf-8")
    start = xml.index("<![CDATA[") + len("<![CDATA[")
    end = xml.index("]]>")
    return json.loads(xml[start:end].strip())


def _markdown() -> str:
    return "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz.get("type") == "splunk.markdown"
    )


def test_phase17a_docs_exist():
    for path in PHASE17A_DOCS:
        assert path.is_file(), path
    note = DOCS / "learning-notes" / "agentsec-mastery-and-assessment.md"
    text = note.read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in text


def test_assessments_parse_and_are_not_policy():
    data = load_assessments()
    rows = validate_assessments()
    raw = json.loads(ASSESSMENTS_PATH.read_text(encoding="utf-8"))
    assert data == raw
    assert data["not_authorization"] is True
    assert data["schema_version"] == "1.9.0"
    assert data["progress_persistence"] is False
    assert data["not_certification"] is True
    assert "Security Score" not in json.dumps(data)
    assert len(rows) == 10
    assert [row["assessment_id"] for row in rows] == [
        "MA-F1-WHO-ENFORCES",
        "MA-F2-REWRITE-CLAIMS",
        "MA-P1-FIND-THE-RUN",
        "MA-P2-CONTROL-AND-EXECUTION",
        "MA-I1-ATTACK-RETEST",
        "MA-A1-ALLOW-IS-NOT-GOAL",
        "MA-A2-OBSERVE-IS-NOT-AUTHN",
        "MA-A3-MISSING-STARTED",
        "MA-X1-CROSS-DOMAIN",
        "MA-PT1-CAPSTONE-GATE",
    ]
    assert {row["competency_level"] for row in rows} == {
        "FOUNDATIONAL",
        "PRACTITIONER",
        "INVESTIGATOR",
        "ADVANCED",
        "PURPLE TEAM",
    }
    assert len(challenges_for("FOUNDATIONAL")) == 2
    assert len(challenges_for("PRACTITIONER")) == 2
    assert len(challenges_for("INVESTIGATOR")) == 1
    assert len(challenges_for("ADVANCED")) == 4
    assert len(challenges_for("PURPLE TEAM")) == 1


def test_assessment_references_are_real_and_honest():
    known = {
        row["lab_id"]
        for level in load_curriculum()["levels"]
        for row in level.get("labs") or []
    }
    for row in validate_assessments():
        if row["lab_id"] is not None:
            assert row["lab_id"] in known, row["lab_id"]
        assert row["evidence_mode"] in {"NONE", "REPLAY", "LIVE"}
        if row["evidence_mode"] == "NONE":
            assert not row["run_ids"]
        else:
            assert row["run_ids"]
        for spl_id in (row["solution_spl_id"], row["related_hunt"]):
            if spl_id:
                assert not str(spl_id).startswith("DET-")
                assert hunt_path(str(spl_id)).is_file()
        assert row["incorrect_claims"]
        assert row["hint_1"]
        assert row["task"]
        assert row["expected_reasoning"]
        assert "security_profile" not in row
        assert "grants" not in row
        assert "allowed_tools" not in row
        assert "coded_policy" not in row
        path_text = f"{row['task']} {row['starter_context']}".lower()
        if row["evidence_mode"] == "REPLAY":
            assert "replay" in path_text
        if row["evidence_mode"] == "LIVE":
            assert "replay" in path_text
            assert "live" in path_text


def test_path_a_and_path_b_exist_on_mastery_view():
    md = _markdown()
    assert "Path A" in md
    assert "Path B" in md
    assert "cannot hide" in md.lower()
    assert "Open Splunk Search" in md
    assert "Hint 1" in md
    assert "Hint 2" in md
    assert "SUPPORTED" in md
    assert "CORROBORATED" in md
    assert "NOT PROVEN" in md
    assert "INCORRECT" in md
    assert "not a certificate" in md.lower()
    assert "Phase 17A" not in md
    assert "Next challenge:** MA-" not in md
    assert "Next challenge:** Rewrite the indefensible sentence" in md
    assert "official REPLAY ATTACK recall" in md
    assert "| --- |" not in md
    file_def = json.loads(DEFINITION.read_text(encoding="utf-8"))
    assert file_def == _definition()
    assert "dataSources" not in file_def
    labels = [item["label"] for item in file_def["layout"]["tabs"]["items"]]
    assert labels == [
        "INTRO",
        "FOUNDATIONAL",
        "PRACTITIONER",
        "INVESTIGATOR",
        "ADVANCED",
        "PURPLE TEAM",
        "RUBRIC",
    ]
    assert "<label>Mastery Check</label>" in VIEW_XML.read_text(encoding="utf-8")
    for row in validate_assessments():
        if row["solution_spl_id"]:
            spl = path_b_spl(row)
            assert spl
            assert "__RUN_ID__" not in spl


def test_cross_domain_and_capstone_gate():
    md = _markdown()
    for needle in (
        "prompt",
        "tool authorization",
        "RAG",
        "memory",
        "goal",
        "identity",
        "capstone",
        "CTRL-MCP-001",
        "NOT PROVEN",
        "NOT MODELED",
        "Attacker controlled",
        "Server owned",
        "Observability only",
        "15-point",
        "NEEDS REVIEW",
        "DEMONSTRATED",
    ):
        assert needle.lower() in md.lower(), needle
    purple = next(
        row for row in validate_assessments() if row["assessment_id"] == "MA-PT1-CAPSTONE-GATE"
    )
    assert purple["evidence_mode"] == "LIVE"
    assert purple["lab_id"] == "LAB-AGENTSEC-CAPSTONE-001"
    identity = next(
        row
        for row in validate_assessments()
        if row["assessment_id"] == "MA-A2-OBSERVE-IS-NOT-AUTHN"
    )
    assert any("authenticated" in claim.lower() for claim in identity["incorrect_claims"])
    missing = next(
        row
        for row in validate_assessments()
        if row["assessment_id"] == "MA-A3-MISSING-STARTED"
    )
    assert any("prevention" in claim.lower() for claim in missing["incorrect_claims"])


def test_home_and_nav_expose_mastery_without_new_collection():
    nav = NAV.read_text(encoding="utf-8")
    assert 'name="ws_agentsec_mastery">Mastery Check</view>' in nav
    assert nav.index("ws_agentsec_mastery") < nav.index('name="search"')
    assert nav.index("ws_lab_agentsec_capstone") < nav.index("ws_agentsec_mastery")
    curriculum = load_curriculum()
    assert curriculum["mastery_view"] == "ws_agentsec_mastery"
    assert curriculum["mastery_title"] == "Mastery Check"
    assert curriculum["nav_collections"][-1]["label"] == "Privacy & Data Governance"
    home_xml = (VIEWS / "ws_agentsec_home.xml").read_text(encoding="utf-8")
    assert "Mastery Check" in home_xml
    assert "ws_agentsec_mastery" in home_xml


def test_assessments_cannot_choose_profile_or_grants():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "assessments.json" not in dockerfile
    assert "load_assessments" not in ATTACK_APP.read_text(encoding="utf-8")
    assert "assessments.json" not in ATTACK_APP.read_text(encoding="utf-8")
    assert "assessments.json" not in BANK_APP.read_text(encoding="utf-8")
    assert known_lab_ids() == frozenset(LIVE_LABS)


def test_schema_authz_and_detectors_unchanged():
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
    assert "DET-ASSESSMENT" not in saved
    assert "DET-CAPSTONE" not in saved
    assert "DET-LEARNER" not in saved
    md = _markdown()
    assert "DET-ASSESSMENT" not in md
    assert "no leaderboard" in md.lower()
    assert not re.search(r"Security Score:\s*\d", md)


def test_knowledge_checks_prefer_reasoning():
    pi = (ROOT / "learning" / "level_1" / "LAB-PI-001" / "knowledge-check.md").read_text(
        encoding="utf-8"
    )
    assert "What payload is ATK-002?" not in pi
    assert "memorizing the ATK-002 string" in pi
    identity = (
        ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001" / "knowledge-check.md"
    ).read_text(encoding="utf-8")
    assert "Has the caller been authenticated?" in identity
    assert "NOT PROVEN" in identity
    rag = (ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "knowledge-check.md").read_text(
        encoding="utf-8"
    )
    assert "Was provenance equivalent to trust?" in rag


def test_attack_service_still_educational_not_authority():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/").get_data(as_text=True)
    assert "does not authorize" in html
    assert "profile: profile" not in html


def test_status_records_17a_without_rewriting_16d_stop():
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    hub_16d = (DOCS / "PHASE16D_ACADEMY_REMEDIATION.md").read_text(encoding="utf-8")
    assert "17A" in status
    assert "Do not start Phase 17A" in hub_16d
    assert "Do not start Phase 17B" in roadmap
    assert "PHASE17A_LEARNER_MASTERY_VALIDATION.md" in (
        DOCS / "AGENTSEC_LEARNING_ARCHITECTURE.md"
    ).read_text(encoding="utf-8")
