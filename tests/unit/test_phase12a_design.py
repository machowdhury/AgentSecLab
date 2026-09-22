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


def test_phase12a_design_docs_exist():
    for path in PHASE12A_DOCS:
        assert path.is_file(), path
    assert STATUS.is_file()
    assert ROADMAP.is_file()


def test_phase12a_is_design_only():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in PHASE12A_DOCS)
    assert "DESIGN" in blob
    assert "LAB-AGENT-DELEGATION-001" in blob
    assert "A2A-001" in blob
    assert "INV-001" in blob
    assert "No INV-009" in blob or "do **not** create INV-009" in blob
    assert "IDENTITY CLAIM" in blob and "VERIFIED IDENTITY" in blob
    assert "AUTHENTICATED" in blob and "AUTHORIZED" in blob
    assert "A2A REQUEST" in blob and "DELEGATED GRANT" in blob
    assert "CTRL-IDENTITY-001" in blob
    assert "CTRL-MCP-001" in blob
    assert "vulnerable_profile_fail_open:caller_identity_derived_authority" in blob
    assert "acme-agent-advisor-005" in blob
    assert "acme-agent-fulfillment-006" in blob
    assert "lookup_customer_tier" in blob
    assert "SCHEMA BUMP JUSTIFIED" in blob
    assert "1.8.0" in blob
    assert "REQUIRES REVALIDATION" in blob or "UNMAPPED" in blob
    spec = (DOCS / "DELEGATION_LAB_SPECIFICATION.md").read_text(encoding="utf-8")
    assert "SAME DELEGATION REQUEST" in spec
    assert "ATTACK" in spec and "RETEST" in spec
    events = (DOCS / "DELEGATION_EVENT_MODEL_REVIEW.md").read_text(encoding="utf-8")
    assert "REQUIRES NEW TELEMETRY" in events
    assert "SUPPORTED NOW" in events
    assert "access_token" in events.lower() or "JWT" in events
    det = (DOCS / "DELEGATION_DETECTION_MODEL.md").read_text(encoding="utf-8")
    assert "DET-MCP-001" in det
    assert "NO DETECTOR JUSTIFIED" in det
    assert "No DET-DELEGATION" in det or "No DET-A2A" in det
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")
    assert "Do not start Phase 12B" in blob or "Wait for explicit Phase 12B" in blob


def test_phase12a_separates_mcp006_and_refuses_new_invariant():
    pred = (DOCS / "IDENTITY_DELEGATION_PREDECESSOR_ANALYSIS.md").read_text(encoding="utf-8")
    assert "LAB-MCP-006" in pred
    assert "CTRL-DELEGATION-001" in pred
    assert "DO NOT REUSE" in pred or "DO NOT OVERLOAD" in pred
    assert "ambient" in pred.lower()
    assert "amplification" in pred.lower()
    threat = (DOCS / "AGENT_DELEGATION_THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "INV-009" in threat
    assert "confused deputy" in threat.lower()
    assert "WHO REQUESTED" in threat
    assert "ON WHOSE BEHALF" in threat
    assert "ASI03" in threat
    assert "AML.T0073" in threat
    assert "UNMAPPED" in threat


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


def test_phase12a_closed_chapters_remain():
    blob = STATUS.read_text(encoding="utf-8") + ROADMAP.read_text(encoding="utf-8")
    assert "11E" in blob
    assert "ws_lab_memory_security" in blob
    assert "ws_lab_rag_context" in blob
    learning = (DOCS / "AGENTSEC_LEARNING_ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "LAB-MCP-006" in learning
    catalog = json.loads(
        (
            ROOT
            / "learning"
            / "level_1"
            / "LAB-MEMORY-001"
            / "searches"
            / "catalog.json"
        ).read_text(encoding="utf-8")
    )
    assert "Q-MEMORY-CONTEXT-AUTHORITY" in json.dumps(catalog)
