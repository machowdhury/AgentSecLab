"""Offline contracts for the IT and cloud operations scenario."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "learning" / "level_1" / "LAB-CHANGE-BOUNDS" / "evidence.packet.json"


def test_delete_is_not_implied_by_inspect_access():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    assert packet["not_cloud_account"] is True
    assert packet["credential_scope"] == "resource:inspect"
    assert packet["delegated_operation"] == "inspect_resource"
    modes = {row["mode"]: row for row in packet["modes"]}
    attack, retest, baseline = modes["ATTACK"], modes["RETEST"], modes["BASELINE"]
    for row in (attack, retest):
        assert row["submitted_operation"] == "delete_resource"
        assert row["binding"] == "MISMATCH"
    assert attack["execution_observed"].startswith("YES")
    assert attack["completion_observed"] == "NOT OBSERVED"
    assert attack["resource_impact"] == "NOT PROVEN"
    assert retest["ctrl_mcp_001_decision"] == "DENY"
    assert retest["execution_observed"].startswith("NO")
    assert baseline["submitted_operation"] == "inspect_resource"
    assert "not a successful change" in baseline["note"]
    assert "AKIA" not in json.dumps(packet)
    authorize = (ROOT / "src" / "agentsec" / "mcp" / "authorize.py").read_text(encoding="utf-8")
    assert "change_not_granted" not in authorize
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    row = next(item for item in curriculum["checkpoints"] if item["id"] == "CHANGE-BOUNDS")
    assert row["lab_id"] not in known_lab_ids()
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
