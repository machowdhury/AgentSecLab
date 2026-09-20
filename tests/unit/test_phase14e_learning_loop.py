"""Phase 14E: reusable learning contracts + LAB-MCP-001 second reference lab."""

from __future__ import annotations

from pathlib import Path

from agentsec.events import content_hash
from agentsec.experiment_context import (
    LAB_MCP,
    attack_retest_fingerprint_pair,
    bind_experiment_for_mcp,
    lookup_experiment,
    mcp_canonical_payload,
)
from agentsec.lab_manifest import validate_lab_manifest
from agentsec.launch_catalog import lookup_launch
from agentsec.learning_contract import LEARNING_METADATA_NOT_AUTHORIZATION
from agentsec.mcp.fixtures import MCP_CUSTOMER_SCOPE, MCP_LOOKUP_TIER_ARGS
from agentsec.mcp.request_contract import parse_mcp_invoke_body

from tests.unit.test_phase14b_attack_service import _wired_app

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
NOTE = ROOT / "docs" / "learning-notes" / "tool-authorization-learning-loop.md"
IMPL = ROOT / "docs" / "PHASE14E_LEARNING_LOOP_GENERALIZATION.md"


def test_phase14e_docs_exist():
    assert IMPL.is_file()
    assert NOTE.is_file()
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")
    assert (ROOT / "docs" / "AGENTSEC_REUSABLE_LEARNING_ARCHITECTURE.md").is_file()
    assert (ROOT / "docs" / "PHASE14E_PI_VS_MCP_COMMON_COMPONENTS.md").is_file()


def test_schema_unchanged_and_no_new_detector():
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-MCP-NEW" not in saved
    assert "DET-LAUNCH" not in saved
    mcp_hunts = {
        path.name
        for path in (ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches").glob("Q-*.spl")
    }
    assert "Q-MCP-WHO.spl" in mcp_hunts
    assert not any(name.startswith("Q-MCP-14E") for name in mcp_hunts)


def test_learning_metadata_is_not_authorization():
    assert LEARNING_METADATA_NOT_AUTHORIZATION is True
    pi = validate_lab_manifest("LAB-PI-001")
    mcp = validate_lab_manifest("LAB-MCP-001")
    assert pi["not_authorization"] is True
    assert mcp["not_authorization"] is True
    assert mcp["control_id"] == "CTRL-MCP-001"


def test_mcp_attack_retest_fingerprint_is_measured():
    attack_fp, retest_fp = attack_retest_fingerprint_pair(LAB_MCP)
    canonical = mcp_canonical_payload(
        "lookup_customer_tier",
        dict(MCP_LOOKUP_TIER_ARGS),
        MCP_CUSTOMER_SCOPE,
    )
    assert attack_fp == retest_fp == content_hash(canonical)
    attack = lookup_experiment("LAB-MCP-001:ATTACK")
    retest = lookup_experiment("LAB-MCP-001:RETEST")
    assert attack is not None and retest is not None
    assert attack.payload == retest.payload
    assert attack.profile != retest.profile
    assert attack.tool == retest.tool == "lookup_customer_tier"


def test_mcp_launch_is_allowlisted():
    row = lookup_launch(
        lab_id="LAB-MCP-001",
        specimen_id="MCP-002",
        mode="ATTACK",
        execution="live",
    )
    assert row is not None
    assert row.runtime_route == "mcp_invoke"
    assert row.intentionally_vulnerable is True
    retest = lookup_launch(
        lab_id="LAB-MCP-001",
        specimen_id="MCP-002",
        mode="RETEST",
        execution="live",
    )
    assert retest is not None
    assert retest.profile == "defended"


def test_mcp_invoke_authority_fields_remain_unknown():
    parsed = parse_mcp_invoke_body(
        {
            "tool": "lookup_customer_tier",
            "requested_scope": "customer:read",
            "arguments": {"customer_id": "cust-001"},
            "experiment_id": "LAB-MCP-001:ATTACK",
            "profile": "vulnerable",
            "allowed_tools": ["lookup_customer_tier"],
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"


def test_mcp_experiment_mismatch_is_error_not_vulnerable():
    ctx, err = bind_experiment_for_mcp(
        experiment_id="LAB-MCP-001:ATTACK",
        tool="lookup_policy",
        requested_scope="customer:read",
        arguments=dict(MCP_LOOKUP_TIER_ARGS),
        user_id="applicant-web",
    )
    assert ctx is None
    assert err == "experiment_tool_mismatch"
    unknown, unknown_err = bind_experiment_for_mcp(
        experiment_id="LAB-MCP-001:PWN",
        tool="lookup_customer_tier",
        requested_scope="customer:read",
        arguments=dict(MCP_LOOKUP_TIER_ARGS),
        user_id="applicant-web",
    )
    assert unknown is None
    assert unknown_err == "unknown_experiment"


def test_live_mcp_attack_and_retest_via_attack_service(acme_client):
    client, calls = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-MCP-001",
            "specimen_id": "MCP-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    retest = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-MCP-001",
            "specimen_id": "MCP-002",
            "mode": "RETEST",
            "execution": "live",
        },
    )
    a = attack.get_json()
    r = retest.get_json()
    assert attack.status_code == 200
    assert retest.status_code == 200
    assert a["run_id"] != r["run_id"]
    assert a["runtime"]["profile"] == "vulnerable"
    assert r["runtime"]["profile"] == "defended"
    assert a["runtime"]["blocked"] is False
    assert r["runtime"]["blocked"] is True
    assert a["runtime"]["handler_invoke_count"] == 1
    assert r["runtime"]["handler_invoke_count"] == 0
    assert a["input_fingerprint"] == r["input_fingerprint"]
    assert a["runtime"]["experiment_id"] == "LAB-MCP-001:ATTACK"
    assert r["runtime"]["experiment_id"] == "LAB-MCP-001:RETEST"
    assert calls[0][0] == "/mcp/invoke"
    assert "profile" not in calls[0][1]
    assert "Q-MCP-AUTHZ" in a["search_handoff"]["reused_hunts"]


def test_mcp_browser_cannot_send_tool_on_launch(acme_client):
    client, calls = _wired_app(acme_client)
    response = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-MCP-001",
            "specimen_id": "MCP-002",
            "mode": "ATTACK",
            "execution": "live",
            "tool": "lookup_customer_tier",
        },
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "unknown_fields"
    assert calls == []


def test_mcp_attack_page_is_closed_launcher():
    from agentsec.attack_app import AcmeBankClient, create_app

    app = create_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/labs/LAB-MCP-001").get_data(as_text=True)
    assert "Tool Authorization" in html
    assert "Launch ATTACK (LIVE)" in html
    assert "Predict before ATTACK" in html
    assert "lab_id: \"LAB-MCP-001\"" in html
    assert "profile:" not in html or "profile: profile" not in html
    assert "MCP-002" in html


def test_direct_mcp_invoke_without_experiment_id_keeps_auto_mode(acme_client):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_customer_tier",
            "requested_scope": "customer:read",
            "arguments": {"customer_id": "cust-001"},
            "user_id": "applicant-web",
        },
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["testbed_mode"] == "ATTACK"
    assert body.get("experiment_id") in (None, "")
    assert body["profile"] == "defended"
    assert body["blocked"] is True
    assert body["handler_invoke_count"] == 0
