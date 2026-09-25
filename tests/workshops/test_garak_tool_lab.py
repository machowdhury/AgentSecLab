"""Structure and honesty contracts for the bounded garak Tool Lab."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-EXTERNAL-EVALUATION-GARAK"
FILES = (
    LAB / "README.md",
    LAB / "workshop.md",
    LAB / "evidence.md",
    LAB / "knowledge-check.md",
    LAB / "searches" / "Q-GARAK-EVALUATION.spl",
    LAB / "searches" / "Q-EXTERNAL-EVIDENCE-PLANES.spl",
)


def test_tool_lab_files_and_learning_grammar():
    for path in FILES:
        assert path.is_file(), path
    workshop = (LAB / "workshop.md").read_text(encoding="utf-8")
    for stage in (
        "## WHY",
        "## WHAT",
        "## INSTALL / VERIFY",
        "## TARGET",
        "## PREDICT",
        "## RUN",
        "## READ NATIVE OUTPUT",
        "## NORMALIZE",
        "## INGEST",
        "## INVESTIGATE",
        "## CHALLENGE THE RESULT",
        "## THREAT MODEL",
        "## EXPLAIN",
    ):
        assert stage in workshop


def test_progressive_depth_and_security_fundamentals():
    text = "\n".join(path.read_text(encoding="utf-8") for path in FILES if path.suffix == ".md")
    flat_text = " ".join(text.split())
    for depth in ("GUIDED", "INVESTIGATE", "CHALLENGE"):
        assert depth in text
    for concept in (
        "Security testing",
        "negative testing",
        "Assurance",
        "Coverage",
        "False confidence",
        "Evidence quality",
        "Defense in depth",
    ):
        assert concept.lower() in text.lower()
    for discipline in (
        "penetration tests",
        "vulnerability scanners",
        "application-security tests",
        "fuzzers",
        "network assessments",
        "cloud-posture assessments",
    ):
        assert discipline in flat_text


def test_semantics_attribution_and_framework_honesty():
    text = "\n".join(path.read_text(encoding="utf-8") for path in FILES if path.suffix == ".md")
    for claim in (
        "PASSING EVALUATION != SAFE",
        "FAILED EVALUATION != EXPLOIT CONFIRMED",
        "MODEL RESPONSE != RUNTIME TOOL EXECUTION",
        "garak is not CTRL-MCP-001, Splunk, or AgentSec",
        "EDUCATIONAL MAPPING",
        "MITRE ATLAS",
        "MAESTRO",
        "NIST AI RMF",
        "NEEDS_EXTERNAL_VALIDATION",
    ):
        assert claim.lower() in text.lower()
    assert "https://github.com/NVIDIA/garak" in text
    assert "Apache-2.0" in text
    assert "compliance mappings" in text


def test_knowledge_check_covers_evidence_discipline_and_threat_model():
    text = (LAB / "knowledge-check.md").read_text(encoding="utf-8")
    for concept in (
        "Cisco mcp-scanner",
        "scanner severity HIGH",
        "zero scanner findings",
        "ALLOW",
        "execution start",
        "successful completion",
        "NO EVIDENCE FOUND",
        "ASSET",
        "ACTOR",
        "ENTRY POINT",
        "TRUST BOUNDARY",
        "CONTROL",
        "OBSERVABILITY",
        "RESIDUAL RISK",
    ):
        assert concept.lower() in text.lower()


def test_searches_preserve_evidence_planes():
    evaluation = (LAB / "searches" / "Q-GARAK-EVALUATION.spl").read_text(
        encoding="utf-8"
    )
    planes = (LAB / "searches" / "Q-EXTERNAL-EVIDENCE-PLANES.spl").read_text(
        encoding="utf-8"
    )
    assert "sourcetype=agentsec:external:evaluation" in evaluation
    assert "agentsec:scanner:finding" in planes
    assert "agentsec:external:evaluation" in planes
    assert "otel:agentic:json" in planes
    assert "CTRL-MCP-001" not in evaluation
