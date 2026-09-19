"""Phase 8A design documents exist and remain research-only.

Does not execute scanners, SPL, or runtime. Does not prove integrations.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
NOTE = DOCS / "learning-notes" / "agent-security-ecosystem.md"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
RUNTIME = ROOT / "src" / "agentsec" / "mcp" / "delegation.py"
AUTHZ = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "Q-MCP-AUTHZ.spl"

PHASE8A_DOCS = (
    DOCS / "AGENTSEC_EXPANSION_ARCHITECTURE.md",
    DOCS / "AGENTSEC_OPEN_SOURCE_SECURITY_ECOSYSTEM.md",
    DOCS / "AGENTSEC_ATTACK_RESEARCH_PIPELINE.md",
    DOCS / "AGENTSEC_TELEMETRY_ROADMAP.md",
    DOCS / "AGENTSEC_ANALYTICS_ROADMAP.md",
    DOCS / "AGENTSEC_LEARNING_ARCHITECTURE.md",
    DOCS / "AGENTSEC_BUILD_VS_INTEGRATE.md",
    DOCS / "AGENTSEC_ROADMAP_2026.md",
    NOTE,
)


def test_phase8a_design_docs_exist():
    for path in PHASE8A_DOCS:
        assert path.is_file(), path


def test_phase8a_is_design_only():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in PHASE8A_DOCS)
    assert "DESIGN" in blob
    assert "Schema remains 1.4.0" in blob or "schema stays 1.4.0" in blob.lower()
    assert "Do not start Phase 8D" in (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(
        encoding="utf-8"
    )
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    assert "tool-description poisoning" in roadmap
    assert "MCP-007" in roadmap


def test_cisco_oss_names_are_cataloged_not_invented():
    text = (DOCS / "AGENTSEC_OPEN_SOURCE_SECURITY_ECOSYSTEM.md").read_text(encoding="utf-8")
    for name in (
        "mcp-scanner",
        "aibom",
        "defenseclaw",
        "skill-scanner",
        "a2a-scanner",
        "model-provenance-kit",
        "Foundation-Sec-8B",
        "Antares",
        "Garak",
        "PyRIT",
        "mcp-scan",
        "a2aproject/A2A",
        "CDTSM",
    ):
        assert name in text, name
    assert "DO NOT INTEGRATE" in text
    assert "CALL EXTERNALLY" in text


def test_phase8a_did_not_change_schema_runtime_or_validated_spl():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert "1.4.0" in schema
    assert "agentsec.a2a" not in schema
    runtime = RUNTIME.read_text(encoding="utf-8")
    assert "CTRL-DELEGATION-001" in runtime
    authz = AUTHZ.read_text(encoding="utf-8")
    assert authz.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0")
