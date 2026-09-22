"""Phase 12B must not create SPL, detectors, Studio, or live A2A transport."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"


def test_no_det_a2a_and_det_mcp_001_unchanged():
    text = DET.read_text(encoding="utf-8")
    assert text.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "sequence>deny_sequence" in text
    assert "CTRL-IDENTITY" not in text
    assert "A2A-001" not in text
    assert list((ROOT / "learning").rglob("DET-A2A*")) == []
    assert list((ROOT / "learning").rglob("DET-DELEGATION*")) == []
    assert list((ROOT / "learning").rglob("Q-A2A*")) == []
    assert list((ROOT / "learning").rglob("Q-DELEGATION*")) == []


def test_q_mcp_not_rewritten_for_identity():
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0")
    assert "agentsec.identity" not in authz
    assert "claimed_scope" not in authz


def test_no_identity_studio_or_live_a2a():
    if VIEWS.is_dir():
        names = {path.name for path in VIEWS.glob("*")}
        assert "ws_lab_a2a.xml" not in names
        assert "ws_lab_agent_delegation.xml" in names  # Phase 15E
    assert not (ROOT / "src" / "agentsec" / "a2a").exists()
    lab = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001"
    assert not (lab / "workshop.md").exists()
    assert not list(lab.glob("DET-*"))


def test_schema_18_has_identity_and_keeps_memory():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "identity_claim_trust" in schema
    assert "CTRL-IDENTITY-001" in schema
    assert "A2A-001" in schema
    assert "agent.identity.claim" in schema
    assert "untrusted_claim" in schema
    assert "memory_context_trust" in schema
    assert "rag_context_trust" in schema
    assert "trusted_identity" not in schema
    assert '"agentsec.session.id"' not in schema
    assert "access_token" not in schema
    assert "ambient_deputy" in schema
