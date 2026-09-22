"""Phase 17C technical-correctness audit. Copy corrections only.

Pytest proves repository consistency — not LIVE Splunk, security effectiveness,
or learner understanding. Schema 1.9.0. Authorization unchanged.
"""

from __future__ import annotations

from pathlib import Path

from agentsec.academy import load_assessments, validate_assessments
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
MEMORY_XML = VIEWS / "ws_lab_memory_security.xml"
PI_XML = VIEWS / "ws_lab_pi_001.xml"
CAPSTONE_XML = VIEWS / "ws_lab_agentsec_capstone.xml"
GOAL_XML = VIEWS / "ws_lab_agent_goal_integrity.xml"

PHASE17C_DOCS = (
    DOCS / "PHASE17C_TECHNICAL_CORRECTNESS_AUDIT.md",
    DOCS / "AGENTSEC_SECURITY_CLAIM_LEDGER.md",
    DOCS / "AGENTSEC_TECHNICAL_CORRECTNESS_MATRIX.md",
    DOCS / "AGENTSEC_CONTROL_OWNERSHIP_MATRIX.md",
    DOCS / "AGENTSEC_EVIDENCE_AUTHORITY_MODEL.md",
    DOCS / "AGENTSEC_SPLUNK_QUERY_VALIDATION.md",
    DOCS / "AGENTSEC_LIVE_REPLAY_EVIDENCE_AUDIT.md",
    DOCS / "AGENTSEC_ATTACK_RETEST_EQUIVALENCE_AUDIT.md",
    DOCS / "AGENTSEC_DETECTION_CLAIM_AUDIT.md",
    DOCS / "AGENTSEC_FRAMEWORK_CLAIM_AUDIT.md",
    DOCS / "learning-notes" / "how-to-make-defensible-agentsec-claims.md",
    DOCS / "reviews" / "ui-review-agentsec-academy-17c-2026-09-21.md",
)


def _xml(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_schema_and_authorization_frozen():
    assert SCHEMA_VERSION == "1.9.0"
    assert '"const": "1.9.0"' in SCHEMA.read_text(encoding="utf-8")
    policy = coded_policy()
    assert policy.allowed_tools == frozenset({"lookup_policy"}) == ALLOWED_TOOLS
    assert policy.allowed_scopes == frozenset({"policy:read"}) == ALLOWED_SCOPES
    policy_src = POLICY.read_text(encoding="utf-8")
    assert 'ALLOWED_TOOLS = frozenset({"lookup_policy"})' in policy_src
    saved = SAVED.read_text(encoding="utf-8")
    assert saved.count("[AgentSec -") == 1
    assert "DET-RAG" not in saved
    assert "DET-MEMORY" not in saved
    assert "DET-GOAL" not in saved
    assert "DET-CAPSTONE" not in saved
    assert "DET-A2A" not in saved
    assessments = load_assessments()
    assert assessments["not_authorization"] is True
    assert assessments["schema_version"] == "1.9.0"


def test_memory_canonical_pairs_are_replay_specimens():
    mem = _xml(MEMORY_XML)
    assert "**LIVE** · write defended · recall defended · mode BASELINE" not in mem
    assert "**LIVE** · write defended · recall defended · mode RETEST" not in mem
    assert "**REPLAY SPECIMEN** · write defended · recall defended · mode BASELINE" in mem
    assert "**REPLAY SPECIMEN** · write defended · recall defended · mode RETEST" in mem
    assert "a8407246-7992-4ad8-bd02-cb701e150f30" in mem
    assert "Launch ATTACK (LIVE)" in mem


def test_pi_mixed_evidence_label_is_not_live_evidence_alone():
    pi = _xml(PI_XML)
    assert "**LIVE EVIDENCE**" not in pi
    assert "**LIVE EXPERIMENT** vs **REPLAY SPECIMEN**" in pi


def test_atlas_mapping_is_qualified_on_attack_service():
    html = ATTACK_HTML.read_text(encoding="utf-8")
    assert "AML.T0054" in html
    assert "REQUIRES REVALIDATION" in html
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    page = client.get("/").get_data(as_text=True)
    assert "AML.T0054" in page
    assert "REQUIRES REVALIDATION" in page
    assert "educational label" in page


def test_home_fingerprint_does_not_claim_equivalent_input():
    home = _xml(HOME_XML)
    assert "proves equivalent input" not in home
    assert "equivalent hashed bytes" in home


def test_mastery_capstone_path_b_is_not_the_readout():
    mastery = _xml(MASTERY_XML)
    assert "not the 15-point" in mastery
    assert "official REPLAY ATTACK recall" in mastery
    purple = next(
        row for row in validate_assessments() if row["assessment_id"] == "MA-PT1-CAPSTONE-GATE"
    )
    assert purple["evidence_mode"] == "LIVE"
    assert any("15-point readout" in claim for claim in purple["incorrect_claims"])
    assert any("fresh LIVE launch" in claim for claim in purple["incorrect_claims"])


def test_capstone_empty_goal_identity_is_not_present_not_required():
    cap = _xml(CAPSTONE_XML)
    assert "NOT REQUIRED TO EXPLAIN INCIDENT" not in cap
    assert "NOT PRESENT in this packet" in cap
    assert "instrumented absence" in cap


def test_goal_retest_is_not_mcp_deny():
    goal = _xml(GOAL_XML)
    assert "AUTHORIZED TOOL != AUTHORIZED GOAL" in goal
    assert "RETEST is not MCP DENY" in goal
    assert "CTRL-MCP-001 ALLOW lookup_policy on A/B/C" in goal


def test_stale_how_to_learn_note_is_historical():
    note = DOCS / "learning-notes" / "how-to-learn-agentic-security-with-agentsec.md"
    text = note.read_text(encoding="utf-8")
    assert "HISTORICAL" in text
    assert "Not current" in text
    assert "learning-agentic-security-with-agentsec.md" in text


def test_mcp_started_is_not_authoritative_execution_on_mcp001():
    mcp = _xml(VIEWS / "ws_lab_mcp_001.xml")
    assert "Execution is `mcp.started`." not in mcp
    assert "Runtime handler count is authoritative" in mcp


def test_phase17c_docs_exist():
    for path in PHASE17C_DOCS:
        assert path.is_file(), path.name
    note = DOCS / "learning-notes" / "how-to-make-defensible-agentsec-claims.md"
    text = note.read_text(encoding="utf-8")
    assert "## What I should now be able to explain" in text


def test_status_records_17c_without_starting_17d():
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    assert "17C" in status
    assert "Do not start Phase 17D" in roadmap
    assert "Do not start Phase 17C from this file" in roadmap
