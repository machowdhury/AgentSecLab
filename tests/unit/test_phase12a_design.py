"""Phase 12A identity / A2A / delegation design documents. No runtime."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
NOTE = DOCS / "learning-notes" / "agent-identity-delegation-101.md"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
AUTHZ = ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
PROTOCOL = ROOT / "src" / "agentsec" / "mcp" / "protocol.py"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
STATUS = DOCS / "IMPLEMENTATION_STATUS.md"
ROADMAP = DOCS / "AGENTSEC_ROADMAP_2026.md"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"

PHASE12A_DOCS = (
    DOCS / "IDENTITY_DELEGATION_PREDECESSOR_ANALYSIS.md",
    DOCS / "AGENT_IDENTITY_SECURITY_MODEL.md",
    DOCS / "AGENT_DELEGATION_THREAT_MODEL.md",
    DOCS / "A2A_TRUST_MODEL.md",
    DOCS / "DELEGATION_LAB_SPECIFICATION.md",
    DOCS / "DELEGATION_EVENT_MODEL_REVIEW.md",
    DOCS / "DELEGATION_DETECTION_MODEL.md",
    DOCS / "DELEGATION_EXTERNAL_TOOL_RESEARCH.md",
    NOTE,
)








def test_phase12a_schema_runtime_spl_and_studio_unchanged():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "A2A-001" in schema
    assert "CTRL-IDENTITY-001" in schema
    assert "identity_claim_trust" in schema
    authz = AUTHZ.read_text(encoding="utf-8")
    assert "CTRL-MCP-001" in authz
    assert (ROOT / "src" / "agentsec" / "identity").is_dir()
    assert not (ROOT / "src" / "agentsec" / "a2a").exists()
    assert not list((ROOT / "learning").rglob("DET-DELEGATION*"))
    assert not list((ROOT / "learning").rglob("DET-A2A*"))
    assert not list((ROOT / "learning").rglob("Q-A2A*"))
    lab = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001"
    assert not (lab / "workshop.md").exists()
    assert not list(lab.glob("DET-*"))
    assert (VIEWS / "ws_lab_agent_delegation.xml").exists()  # Phase 15E LIVE workshop
    assert not (VIEWS / "ws_lab_a2a.xml").exists()
    assert "list_changed" not in PROTOCOL.read_text(encoding="utf-8")
    det = DET.read_text(encoding="utf-8")
    assert det.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "CTRL-IDENTITY" not in det
    assert "A2A-001" not in det


