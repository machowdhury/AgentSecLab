"""Offline contracts for the software-engineering agent scenario."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "learning" / "level_1" / "LAB-CODE-AGENT-BOUNDS" / "evidence.packet.json"


def test_install_request_is_not_a_read_grant():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    assert packet["not_github"] is True
    assert packet["delegation"]["delegated_operation"] == "read_repository"
    assert packet["approval"]["approved_operation"] == "read_repository"
    modes = {row["mode"]: row for row in packet["modes"]}
    attack, retest, baseline = modes["ATTACK"], modes["RETEST"], modes["BASELINE"]
    for row in (attack, retest):
        assert row["submitted_operation"] == "install_dependency"
        assert row["binding"] == "MISMATCH"
        assert row["pull_request"] == "NOT OPENED"
    assert attack["ctrl_mcp_001_decision"] == "ALLOW"
    assert "code_agent_scope_not_checked" in attack["ctrl_mcp_001_reason"]
    assert retest["ctrl_mcp_001_decision"] == "DENY"
    assert baseline["submitted_operation"] == "read_repository"
    assert "not authority to install" in baseline["note"]
    assert "ghp_" not in json.dumps(packet)
    authorize = (ROOT / "src" / "agentsec" / "mcp" / "authorize.py").read_text(encoding="utf-8")
    assert "operation_not_granted" not in authorize
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    row = next(item for item in curriculum["checkpoints"] if item["id"] == "CODE-AGENT-BOUNDS")
    assert row["lab_id"] not in known_lab_ids()
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
