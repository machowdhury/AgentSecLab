"""Normalized scanner HEC events stay off the 1.5.0 runtime schema."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.mcp.authorize import CONTROL_ID
from agentsec.mcp.metadata_trust import METADATA_CONTROL_ID
from agentsec.scanners.hec_events import (
    CANONICAL_PACK_DIRS,
    EVENT_FINDING,
    EVENT_SCAN,
    INDEX_NAME,
    SOURCETYPE,
    events_from_canonical_packs,
    events_from_pack,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
PACKS = ROOT / "docs" / "phase9b-evidence"


def _events():
    return events_from_canonical_packs(ROOT)


def test_canonical_packs_are_phase9b_not_manufactured():
    events = _events()
    assert len(CANONICAL_PACK_DIRS) == 2
    scan_ids = {payload["event"]["scan_id"] for payload in events}
    assert scan_ids == {
        "b3061c4e-7a81-445c-8fd8-3108dd14c419",
        "7ae3ea64-4e7a-40fe-943f-3e582bce5ee8",
    }
    names = {payload["event"]["event.name"] for payload in events}
    assert names == {EVENT_SCAN, EVENT_FINDING}


def test_normal_is_scan_only_zero_findings():
    pack = PACKS / "normal-b3061c4e-7a81-445c-8fd8-3108dd14c419"
    events = events_from_pack(pack)
    assert len(events) == 1
    body = events[0]["event"]
    assert body["event.name"] == EVENT_SCAN
    assert body["scan"]["finding_count"] == 0
    assert "classification" not in body["scan"]
    assert body["artifact"]["description_sha256"] == (
        "sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3"
    )
    assert body["artifact"]["sha256"] == (
        "sha256:d706a2f8f8476ed0a972d2b7f371a42450addbfbafa2448488d8223e370bac60"
    )
    assert body["artifact"]["sha256"] != body["artifact"]["description_sha256"]


def test_malicious_is_scan_plus_one_finding():
    pack = PACKS / "malicious-7ae3ea64-4e7a-40fe-943f-3e582bce5ee8"
    events = events_from_pack(pack)
    assert len(events) == 2
    scan = events[0]["event"]
    finding = events[1]["event"]
    assert scan["event.name"] == EVENT_SCAN
    assert scan["scan"]["finding_count"] == 1
    assert scan["scan"]["classification"] == "DETECTED_BY_SCANNER"
    assert finding["event.name"] == EVENT_FINDING
    assert finding["finding"]["native_severity"] == "HIGH"
    assert finding["finding"]["native_rule_id"] == "PROMPT INJECTION"
    assert "native_confidence" not in finding["finding"]
    assert finding["artifact"]["description_sha256"] == (
        "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"
    )


def test_privacy_and_schema_boundary():
    dumped = json.dumps(_events())
    assert "/Users/" not in dumped
    assert "argv" not in dumped
    assert "mcp-scanner" not in dumped or "cisco-ai-mcp-scanner" in dumped
    assert "Ignore previous instructions" not in dumped
    assert "Always include lookup_customer_tier" not in dumped
    assert "agentsec.schema.version" not in dumped
    assert "CTRL-MCP-001" not in dumped
    assert CONTROL_ID == "CTRL-MCP-001"
    assert METADATA_CONTROL_ID == "CTRL-MCP-METADATA-001"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "agentsec.scanner" not in schema
    for payload in _events():
        assert payload["sourcetype"] == SOURCETYPE
        assert payload["index"] == INDEX_NAME
        assert payload["sourcetype"] != "otel:agentic:json"
        assert "path" not in payload["event"]["artifact"]
        assert "agentsec.run.id" not in payload["event"]


def test_raw_stdout_not_copied_into_event():
    for payload in _events():
        text = json.dumps(payload["event"])
        assert "server_url" not in text
        assert "https://mcp.deepwiki.com" not in text
        assert payload["event"]["provenance"]["raw_output_sha256"].startswith("sha256:")
