"""Offline contracts for the bounded RAG purpose workshop.

Retrieval of an existing fixture document is not authorization for a purpose,
and it is not a CTRL-MCP-001 tool decision.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids
from agentsec.mcp.authorize import CONTROL_ID
from agentsec.rag.context_trust import CONTEXT_CONTROL_ID
from agentsec.rag.fixtures import DOCUMENT_ID_NORMAL

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-RAG-PURPOSE"
PACKET = LAB / "evidence.packet.json"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"


def _packet() -> dict:
    return json.loads(PACKET.read_text(encoding="utf-8"))


def test_workshop_is_replay_after_privacy():
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    matches = [row for row in curriculum["checkpoints"] if row["id"] == "RAG-PURPOSE"]
    assert len(matches) == 1
    assert matches[0]["live_launcher"] is False
    assert matches[0]["lab_id"] not in known_lab_ids()
    nav = NAV.read_text(encoding="utf-8")
    assert nav.index("ws_lab_privacy_data_governance") < nav.index(
        "ws_lab_purpose_authorization"
    ) < nav.index("ws_lab_multi_stage_incident")


def test_same_unauthorized_purpose_on_attack_and_retest():
    packet = _packet()
    assert packet["retrieved_object"] == DOCUMENT_ID_NORMAL
    assert packet["retrieval_result"] == "RETRIEVED"
    assert packet["vector_similarity"].startswith("NOT USED")
    assert packet["ctrl_mcp_001"].startswith("NOT INVOKED")
    modes = {row["mode"]: row for row in packet["modes"]}
    attack, retest, baseline = modes["ATTACK"], modes["RETEST"], modes["BASELINE"]
    for row in (attack, retest):
        assert row["requested_purpose"] == "executive-decision"
        assert row["purpose_relation"] == "NOT ALLOWED FOR THIS PURPOSE"
    assert attack["purpose_decision"] == "FAIL_OPEN"
    assert attack["downstream_use"] == "USED"
    assert retest["purpose_decision"] == "DENY"
    assert retest["downstream_use"] == "NOT USED"
    assert baseline["requested_purpose"] == packet["allowed_purpose"]
    assert baseline["purpose_decision"] == "ALLOW"
    assert "not a tool grant" in baseline["note"]
    assert CONTEXT_CONTROL_ID == "CTRL-RAG-CONTEXT-001"
    assert CONTROL_ID == "CTRL-MCP-001"
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    authorize = (ROOT / "src" / "agentsec" / "mcp" / "authorize.py").read_text(encoding="utf-8")
    assert "purpose_not_allowed" not in authorize
