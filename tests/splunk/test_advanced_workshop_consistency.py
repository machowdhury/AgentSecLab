"""Cross-check the advanced replay workshops against the security distinctions.

These tests read static packets. They do not prove runtime enforcement.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEVEL = ROOT / "learning" / "level_1"
AUTHORIZE = (ROOT / "src" / "agentsec" / "mcp" / "authorize.py").read_text(encoding="utf-8")


def _packet(lab: str, name: str) -> dict:
    return json.loads((LEVEL / lab / name).read_text(encoding="utf-8"))


def _modes(packet: dict) -> dict:
    return {row["mode"]: row for row in packet["modes"]}


def test_attack_and_retest_share_the_malicious_request():
    hitl = _modes(_packet("LAB-HITL-APPROVAL", "evidence.packet.json"))
    assert hitl["ATTACK"]["submitted_resource"] == hitl["RETEST"]["submitted_resource"]
    assert hitl["BASELINE"]["submitted_resource"] != hitl["ATTACK"]["submitted_resource"]

    cred = _modes(_packet("LAB-CREDENTIAL-LIFETIME", "evidence.packet.json"))
    assert cred["ATTACK"]["credential_reference"] == cred["RETEST"]["credential_reference"]
    assert cred["ATTACK"]["requested_tool"] == cred["RETEST"]["requested_tool"]
    assert cred["BASELINE"]["credential_reference"] != cred["ATTACK"]["credential_reference"]

    purpose = _modes(_packet("LAB-RAG-PURPOSE", "evidence.packet.json"))
    assert purpose["ATTACK"]["requested_purpose"] == purpose["RETEST"]["requested_purpose"]
    assert purpose["BASELINE"]["requested_purpose"] != purpose["ATTACK"]["requested_purpose"]

    recall = _modes(_packet("LAB-RECALL-ISOLATION", "evidence.packet.json"))
    assert recall["ATTACK"]["reader"] == recall["RETEST"]["reader"] == "user-b"
    assert recall["BASELINE"]["reader"] == "user-a"

    provenance = _modes(_packet("LAB-COMPONENT-PROVENANCE", "evidence.packet.json"))
    assert provenance["ATTACK"]["component"] == provenance["RETEST"]["component"]
    assert provenance["ATTACK"]["requested_tool"] == provenance["RETEST"]["requested_tool"]

    code = _modes(_packet("LAB-CODE-AGENT-BOUNDS", "evidence.packet.json"))
    assert code["ATTACK"]["submitted_operation"] == code["RETEST"]["submitted_operation"]
    assert code["BASELINE"]["submitted_operation"] != code["ATTACK"]["submitted_operation"]

    change = _modes(_packet("LAB-CHANGE-BOUNDS", "evidence.packet.json"))
    assert change["ATTACK"]["submitted_operation"] == change["RETEST"]["submitted_operation"]
    assert change["ATTACK"]["completion_observed"] == "NOT OBSERVED"
    assert change["BASELINE"]["completion_observed"] == "NOT OBSERVED"


def test_packets_do_not_become_runtime_reasons_or_trust():
    inventory = _packet("LAB-ASSET-INVENTORY", "inventory.packet.json")
    assert inventory["not_cisco_aibom"] is True
    assert all(row["trust"] != "TRUSTED" for row in inventory["components"])
    for reason in (
        "approval_binding_mismatch",
        "expired_credential",
        "purpose_not_allowed",
        "cross_user_recall_denied",
        "provenance_is_not_a_grant",
        "operation_not_granted",
        "change_not_granted",
    ):
        assert reason not in AUTHORIZE
