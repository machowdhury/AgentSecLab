"""Offline contracts for the component-provenance workshop."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "learning" / "level_1" / "LAB-COMPONENT-PROVENANCE" / "evidence.packet.json"


def test_unpinned_component_is_not_a_tool_grant():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    assert "NOT RESOLVED" in packet["ollama_pin"]
    modes = {row["mode"]: row for row in packet["modes"]}
    attack, retest, baseline = modes["ATTACK"], modes["RETEST"], modes["BASELINE"]
    for row in (attack, retest):
        assert row["component"] == "ollama/ollama:latest"
        assert row["requested_tool"] == "lookup_customer_tier"
        assert row["provenance"] == "UNPINNED"
    assert attack["ctrl_mcp_001_decision"] == "ALLOW"
    assert "known_component_treated_as_grant" in attack["ctrl_mcp_001_reason"]
    assert retest["ctrl_mcp_001_decision"] == "DENY"
    assert retest["ctrl_mcp_001_reason"] == "provenance_is_not_a_grant"
    assert "did not authorize" in baseline["note"]
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "ollama/ollama:latest" in compose
    assert "flask==3.0.3" in pyproject
    assert "pytest>=8.3.0" in pyproject
    authorize = (ROOT / "src" / "agentsec" / "mcp" / "authorize.py").read_text(encoding="utf-8")
    assert "provenance_is_not_a_grant" not in authorize
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    row = next(item for item in curriculum["checkpoints"] if item["id"] == "COMPONENT-PROVENANCE")
    assert row["lab_id"] not in known_lab_ids()
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
