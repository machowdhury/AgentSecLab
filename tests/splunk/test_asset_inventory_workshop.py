"""Offline contracts for the educational asset-inventory workshop."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.launch_catalog import known_lab_ids

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-ASSET-INVENTORY"
PACKET = LAB / "inventory.packet.json"


def test_inventory_does_not_claim_cisco_aibom_or_trust():
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    assert packet["not_cisco_aibom"] is True
    assert "NOT CLAIMED" in packet["cisco_aibom_compatibility"]
    assert packet["evidence_classification"] == "DOCUMENTED"
    kinds = {row["kind"] for row in packet["components"]}
    assert {"model", "agent", "tool", "mcp_server", "framework", "runtime"} <= kinds
    assert all(row["trust"] != "TRUSTED" for row in packet["components"])
    assert any("unpinned" in row["version"] for row in packet["components"])
    curriculum = json.loads(
        (ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8")
    )
    matches = [row for row in curriculum["checkpoints"] if row["id"] == "ASSET-INVENTORY"]
    assert len(matches) == 1
    assert matches[0]["lab_id"] not in known_lab_ids()
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "ollama/ollama:latest" in compose
