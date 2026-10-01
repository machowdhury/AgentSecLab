"""Offline contracts for the bounded memory-ownership workshop."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.authorize import CONTROL_ID
from agentsec.memory.fixtures import MEMORY_ID_NORMAL
from agentsec.memory.trust import MEMORY_CONTROL_ID

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-RECALL-ISOLATION"
PACKET = LAB / "evidence.packet.json"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"


def test_cross_user_recall_is_shared_by_attack_and_retest():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    assert packet["memory_id"] == MEMORY_ID_NORMAL
    assert packet["owner"] == "user-a"
    assert packet["deletion_status"] == "NOT MEASURED"
    assert packet["ctrl_mcp_001"].startswith("NOT INVOKED")
    modes = {row["mode"]: row for row in packet["modes"]}
    attack, retest, baseline = modes["ATTACK"], modes["RETEST"], modes["BASELINE"]
    for row in (attack, retest):
        assert row["reader"] == "user-b"
        assert row["request_id"] == "sim-recall-request-001"
    assert attack["recall_result"] == "RETURNED"
    assert attack["isolation"] == "CROSSED"
    assert retest["recall_result"] == "ISOLATED"
    assert baseline["reader"] == "user-a"
    assert "not tool authorization" in baseline["note"]
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    matches = [row for row in curriculum["checkpoints"] if row["id"] == "RECALL-ISOLATION"]
    assert len(matches) == 1
    assert matches[0]["lab_id"] not in known_lab_ids()
    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_lab_purpose_authorization") < nav.index(
        "ws_lab_recall_isolation"
    ) < nav.index("ws_lab_multi_stage_incident")
    assert MEMORY_CONTROL_ID == "CTRL-MEMORY-CONTEXT-001"
    assert CONTROL_ID == "CTRL-MCP-001"
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    assert "cross_user_recall_denied" not in (
        ROOT / "src" / "agentsec" / "mcp" / "authorize.py"
    ).read_text(encoding="utf-8")
