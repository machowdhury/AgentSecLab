"""Phase 13B must not create SPL, detectors, Studio, or a second tool PDP."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
AUTHZ_PY = ROOT / "src" / "agentsec" / "mcp" / "authorize.py"


def test_no_det_goal_and_det_mcp_001_unchanged():
    text = DET.read_text(encoding="utf-8")
    assert text.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "sequence>deny_sequence" in text
    assert "CTRL-GOAL" not in text
    assert "GOAL-001" not in text
    assert list((ROOT / "learning").rglob("DET-GOAL*")) == []
    allowed_q_goal = {
        ROOT
        / "learning"
        / "level_1"
        / "LAB-AGENT-GOAL-INTEGRITY-001"
        / "searches"
        / "Q-GOAL-INTEGRITY-AUTHORITY.spl",
        ROOT
        / "learning"
        / "level_1"
        / "LAB-AGENT-GOAL-INTEGRITY-001"
        / "searches"
        / "Q-GOAL-INTEGRITY-AUTHORITY.md",
    }
    found_q_goal = set((ROOT / "learning").rglob("Q-GOAL*"))
    assert found_q_goal <= allowed_q_goal


def test_q_mcp_not_rewritten_for_goal():
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0")
    assert "agentsec.goal" not in authz
    assert "unauthorized_task_expansion" not in authz


def test_no_goal_studio():
    if VIEWS.is_dir():
        names = {path.name for path in VIEWS.glob("*goal*")}
        assert names <= {"ws_lab_agent_goal_integrity.xml"}
        assert "ws_lab_goal.xml" not in names
    lab = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001"
    assert not list(lab.glob("DET-*"))


def test_schema_19_has_goal_and_keeps_identity():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "goal_integrity" in schema
    assert "CTRL-GOAL-INTEGRITY-001" in schema
    assert "GOAL-001" in schema
    assert "agent.task.contract" in schema
    assert "untrusted_instruction" in schema
    assert "identity_claim_trust" in schema
    assert "memory_context_trust" in schema
    assert '"trusted_instruction"' not in schema
    assert '"agentsec.session.id"' not in schema
    assert "access_token" not in schema


def test_mcp_authorize_is_not_a_goal_pdp():
    text = AUTHZ_PY.read_text(encoding="utf-8")
    assert "CTRL-GOAL-INTEGRITY" not in text
    assert "unauthorized_task_expansion" not in text
    assert "extract_full_policy" not in text
