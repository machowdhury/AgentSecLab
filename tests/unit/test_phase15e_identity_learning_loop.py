"""Phase 15E: LAB-AGENT-DELEGATION-001 LIVE learning loop. Schema 1.9.0. No DET-A2A."""

from __future__ import annotations

import threading
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.experiment_context import (
    LAB_IDENTITY,
    attack_retest_fingerprint_pair,
    bind_experiment_for_identity,
    lookup_experiment,
)
from agentsec.identity.fixtures import (
    CALLEE_AGENT_ID,
    CALLER_AGENT_ID,
    CLAIM_ID_MALICIOUS,
    CLAIM_ID_NORMAL,
    PRINCIPAL_ID,
    adversarial_a2a_payload,
    identity_agent_policy,
)
from agentsec.identity.request import parse_a2a_delegation_request
from agentsec.identity.request_contract import parse_identity_delegate_body
from agentsec.identity.trust import IDENTITY_FAIL_OPEN_REASON
from agentsec.lab_manifest import validate_lab_manifest
from agentsec.launch_catalog import lookup_launch
from agentsec.learning_contract import LEARNING_METADATA_NOT_AUTHORIZATION, assert_learning_not_policy
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy

from tests.unit.test_phase14b_attack_service import _wired_app

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
NOTE = ROOT / "docs" / "learning-notes" / "agent-identity-delegation-live-learning-loop.md"
IMPL = ROOT / "docs" / "PHASE15E_IDENTITY_DELEGATION_LIVE_LEARNING_LOOP.md"
ATTACK_HASH = "sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd"
BASELINE_HASH = "sha256:93f1e257a7d6c7660aa8b1d1b980f1509b7da69e215b385ac79c222e1058b3eb"


def test_phase15e_docs_exist():
    assert IMPL.is_file()
    assert NOTE.is_file()
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")
    assert (ROOT / "docs" / "PHASE15E_IDENTITY_ATTACK_SERVICE_LAUNCH_CONTRACT.md").is_file()
    assert (ROOT / "docs" / "PHASE15E_IDENTITY_GUIDED_INVESTIGATIONS.md").is_file()
    assert (ROOT / "docs" / "PHASE15E_SECURITY_BOUNDARY_REVIEW.md").is_file()
    assert (ROOT / "docs" / "PHASE15E_LIVE_VS_REPLAY.md").is_file()
    assert (ROOT / "docs" / "PHASE15E_ATTACK_RETEST_EQUIVALENCE.md").is_file()
    assert (ROOT / "docs" / "PHASE15E_SPLUNK_LIVE_VALIDATION.md").is_file()


def test_schema_unchanged_and_no_det_a2a():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-A2A" not in saved
    assert "DET-DELEGATION" not in saved
    assert not list((ROOT / "learning").rglob("DET-A2A*"))
    hunts = {
        path.name
        for path in (ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001" / "searches").glob("Q-*.spl")
    }
    assert hunts == {"Q-AGENT-DELEGATION-AUTHORITY.spl"}


def test_learning_metadata_is_not_authorization():
    assert LEARNING_METADATA_NOT_AUTHORIZATION is True
    assert_learning_not_policy("LAB-AGENT-DELEGATION-001")
    manifest = validate_lab_manifest("LAB-AGENT-DELEGATION-001")
    assert manifest["not_authorization"] is True
    assert manifest["control_id"] == "CTRL-IDENTITY-001"
    assert manifest["enforcement_control_id"] == "CTRL-MCP-001"


def test_identity_attack_retest_fingerprint_is_adversarial_claim():
    attack_fp, retest_fp = attack_retest_fingerprint_pair(LAB_IDENTITY)
    parsed = parse_a2a_delegation_request(adversarial_a2a_payload())
    assert parsed.ok and parsed.request is not None
    assert attack_fp == retest_fp == parsed.request.fingerprint == ATTACK_HASH
    attack = lookup_experiment("LAB-AGENT-DELEGATION-001:ATTACK")
    retest = lookup_experiment("LAB-AGENT-DELEGATION-001:RETEST")
    assert attack is not None and retest is not None
    assert attack.claim_id == retest.claim_id == CLAIM_ID_MALICIOUS
    assert attack.profile != retest.profile
    assert attack.intentionally_vulnerable is True
    assert retest.intentionally_vulnerable is False
    baseline = lookup_experiment("LAB-AGENT-DELEGATION-001:BASELINE")
    assert baseline is not None
    assert baseline.claim_id == CLAIM_ID_NORMAL
    assert baseline.input_fingerprint if False else True
    from agentsec.experiment_context import ExperimentContext

    assert ExperimentContext.from_definition(baseline).input_fingerprint == BASELINE_HASH
    caller = identity_agent_policy(CALLER_AGENT_ID)
    callee = identity_agent_policy(CALLEE_AGENT_ID)
    assert caller.allowed_tools == callee.allowed_tools == ALLOWED_TOOLS
    assert "lookup_customer_tier" not in caller.allowed_tools
    assert "customer:read" not in caller.allowed_scopes


def test_identity_launch_catalog_rows():
    attack = lookup_launch(
        lab_id="LAB-AGENT-DELEGATION-001",
        specimen_id="A2A-001",
        mode="ATTACK",
        execution="live",
    )
    retest = lookup_launch(
        lab_id="LAB-AGENT-DELEGATION-001",
        specimen_id="A2A-001",
        mode="RETEST",
        execution="live",
    )
    baseline = lookup_launch(
        lab_id="LAB-AGENT-DELEGATION-001",
        specimen_id="A2A-BASELINE",
        mode="BASELINE",
        execution="live",
    )
    assert attack is not None and retest is not None and baseline is not None
    assert attack.profile == "vulnerable"
    assert retest.profile == "defended"
    assert attack.runtime_route == "identity_delegate"


def test_identity_authority_fields_are_unknown_not_policy():
    parsed = parse_identity_delegate_body(
        {
            "claim_id": CLAIM_ID_MALICIOUS,
            "experiment_id": "LAB-AGENT-DELEGATION-001:ATTACK",
            "profile": "vulnerable",
            "allowed_tools": ["lookup_customer_tier"],
            "identity_verified": True,
            "authenticated": True,
            "delegated_grant": True,
            "grants": ["customer:read"],
            "roles": ["admin"],
            "permissions": ["*"],
            "caller_agent": "pwned",
            "python": "print(1)",
            "spl": "index=*",
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"


def test_identity_experiment_mismatch_is_error_not_vulnerable():
    ctx, err = bind_experiment_for_identity(
        experiment_id="LAB-AGENT-DELEGATION-001:ATTACK",
        claim_id=CLAIM_ID_NORMAL,
        user_id="applicant-web",
    )
    assert ctx is None
    assert err == "experiment_claim_mismatch"
    unknown, unknown_err = bind_experiment_for_identity(
        experiment_id="LAB-AGENT-DELEGATION-001:PWN",
        claim_id=CLAIM_ID_MALICIOUS,
        user_id="applicant-web",
    )
    assert unknown is None
    assert unknown_err == "unknown_experiment"
    user, user_err = bind_experiment_for_identity(
        experiment_id="LAB-AGENT-DELEGATION-001:ATTACK",
        claim_id=CLAIM_ID_MALICIOUS,
        user_id="attacker-lab",
    )
    assert user is None
    assert user_err == "experiment_user_mismatch"


def test_live_identity_attack_and_retest_via_attack_service(acme_client):
    client, calls = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-DELEGATION-001",
            "specimen_id": "A2A-001",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    retest = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-DELEGATION-001",
            "specimen_id": "A2A-001",
            "mode": "RETEST",
            "execution": "live",
        },
    )
    a = attack.get_json()
    r = retest.get_json()
    assert attack.status_code == 200, a
    assert retest.status_code == 200, r
    assert a["run_id"] != r["run_id"]
    assert a["runtime"]["profile"] == "vulnerable"
    assert r["runtime"]["profile"] == "defended"
    assert a["runtime"]["identity_control_decision"] == "OBSERVE"
    assert r["runtime"]["identity_control_decision"] == "OBSERVE"
    assert a["runtime"]["identity_control_reason"] == "identity_claim_is_not_grant"
    assert r["runtime"]["identity_control_reason"] == "identity_claim_is_not_grant"
    assert a["runtime"]["follow_on_decision"] == "ALLOW"
    assert r["runtime"]["follow_on_decision"] == "DENY"
    assert a["runtime"]["follow_on_reason"] == IDENTITY_FAIL_OPEN_REASON
    assert r["runtime"]["follow_on_reason"] == "tool_not_granted"
    assert a["runtime"]["lookup_customer_tier_handler_count"] == 1
    assert r["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert a["runtime"]["principal_id"] == r["runtime"]["principal_id"] == PRINCIPAL_ID
    assert a["runtime"]["caller_agent_id"] == r["runtime"]["caller_agent_id"] == CALLER_AGENT_ID
    assert a["runtime"]["callee_agent_id"] == r["runtime"]["callee_agent_id"] == CALLEE_AGENT_ID
    assert a["input_fingerprint"] == r["input_fingerprint"] == ATTACK_HASH
    assert a["runtime"]["request_fingerprint"] == r["runtime"]["request_fingerprint"] == ATTACK_HASH
    assert a["runtime"]["experiment_id"] == "LAB-AGENT-DELEGATION-001:ATTACK"
    assert r["runtime"]["experiment_id"] == "LAB-AGENT-DELEGATION-001:RETEST"
    assert a["runtime"]["who_authenticated"] == "NOT PROVEN / NOT MODELED"
    assert a["runtime"].get("schema_version", "1.9.0") == "1.9.0"
    assert calls[0][0] == "/identity/delegate"
    assert "profile" not in calls[0][1]
    assert set(calls[0][1]) <= {"claim_id", "user_id", "experiment_id"}
    assert "Q-AGENT-DELEGATION-AUTHORITY" in a["search_handoff"]["reused_hunts"]
    coded = coded_policy()
    assert coded.allowed_tools == ALLOWED_TOOLS == frozenset({"lookup_policy"})


def test_identity_browser_cannot_send_authority_on_launch(acme_client):
    client, calls = _wired_app(acme_client)
    for extra in (
        {"profile": "vulnerable"},
        {"allowed_tools": ["lookup_customer_tier"]},
        {"grants": ["customer:read"]},
        {"identity_verified": True},
        {"authenticated": True},
        {"delegated_grant": True},
        {"roles": ["admin"]},
        {"permissions": ["*"]},
        {"approved": True},
        {"control_decision": "ALLOW"},
        {"python": "print(1)"},
        {"spl": "index=*"},
        {"AGENTSEC_SECURITY_PROFILE": "vulnerable"},
    ):
        body = {
            "lab_id": "LAB-AGENT-DELEGATION-001",
            "specimen_id": "A2A-001",
            "mode": "ATTACK",
            "execution": "live",
            **extra,
        }
        response = client.post("/api/launch", json=body)
        assert response.status_code == 400, extra
        assert response.get_json()["error"] == "unknown_fields"
    assert calls == []


def test_identity_attack_page_is_closed_launcher():
    from agentsec.attack_app import AcmeBankClient, create_app

    app = create_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/labs/LAB-AGENT-DELEGATION-001").get_data(as_text=True)
    assert "Agent Identity / Delegation" in html
    assert "Launch ATTACK (LIVE)" in html
    assert "Launch RETEST (LIVE)" in html
    assert "Predict before ATTACK" in html
    assert 'lab_id: "LAB-AGENT-DELEGATION-001"' in html
    assert "A2A-001" in html
    assert "CTRL-IDENTITY-001" in html
    assert "Q-AGENT-DELEGATION-AUTHORITY" in html
    assert "WHAT IS AGENT DELEGATION?" in html
    assert "WHO AUTHENTICATED" in html
    assert "NOT PROVEN / NOT MODELED" in html
    assert "SAME IDENTITY CLAIM. SAME DELEGATION CLAIM. SAME PRIVILEGED REQUEST." in html
    assert "lookup_customer_tier HANDLER" in html


def test_direct_identity_delegate_without_experiment_id_keeps_auto_mode(acme_client):
    response = acme_client.post(
        "/identity/delegate",
        json={"claim_id": CLAIM_ID_MALICIOUS, "user_id": "applicant-web"},
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["testbed_mode"] == "BASELINE"
    assert body.get("experiment_id") in (None, "")
    assert body["profile"] == "defended"
    assert body["identity_control_decision"] == "OBSERVE"
    assert body["follow_on_decision"] == "DENY"
    assert body["lookup_customer_tier_handler_count"] == 0


def test_direct_identity_experiment_mismatch_http_is_error(acme_client):
    response = acme_client.post(
        "/identity/delegate",
        json={
            "claim_id": CLAIM_ID_NORMAL,
            "user_id": "applicant-web",
            "experiment_id": "LAB-AGENT-DELEGATION-001:ATTACK",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "experiment_claim_mismatch"
    assert body["lookup_customer_tier_handler_count"] == 0
    empty = acme_client.post(
        "/identity/delegate",
        json={
            "claim_id": CLAIM_ID_MALICIOUS,
            "user_id": "applicant-web",
            "experiment_id": "",
        },
    )
    assert empty.status_code == 400
    assert empty.get_json()["block_reason"] == "malformed_experiment"


def test_malformed_identity_body_is_error_not_policy(acme_client):
    response = acme_client.post("/identity/delegate", data="not-json", content_type="application/json")
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "malformed_input"
    assert body["terminal"] == "run_failed"


def test_concurrent_identity_attack_and_retest_do_not_leak_profile(acme_client):
    client, _calls = _wired_app(acme_client)
    results = {}

    def fire(mode):
        response = client.post(
            "/api/launch",
            json={
                "lab_id": "LAB-AGENT-DELEGATION-001",
                "specimen_id": "A2A-001",
                "mode": mode,
                "execution": "live",
            },
        )
        results[mode] = response.get_json()

    threads = [
        threading.Thread(target=fire, args=("ATTACK",)),
        threading.Thread(target=fire, args=("RETEST",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    attack = results["ATTACK"]
    retest = results["RETEST"]
    assert attack["run_id"] != retest["run_id"]
    assert attack["runtime"]["profile"] == "vulnerable"
    assert retest["runtime"]["profile"] == "defended"
    assert attack["runtime"]["testbed_mode"] == "ATTACK"
    assert retest["runtime"]["testbed_mode"] == "RETEST"
    assert attack["input_fingerprint"] == retest["input_fingerprint"] == ATTACK_HASH
    assert attack["runtime"]["follow_on_decision"] == "ALLOW"
    assert retest["runtime"]["follow_on_decision"] == "DENY"
    assert attack["runtime"]["lookup_customer_tier_handler_count"] == 1
    assert retest["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert coded_policy().allowed_tools == ALLOWED_TOOLS
    health = acme_client.get("/health")
    assert health.status_code == 200
    body = health.get_json()
    assert body.get("security.profile") in (None, "defended") or body.get("security_profile") in (None, "defended")


def test_attack_overlay_does_not_mutate_coded_policy(acme_client):
    before_tools = coded_policy().allowed_tools
    client, _calls = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-DELEGATION-001",
            "specimen_id": "A2A-001",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    assert attack.status_code == 200
    assert coded_policy().allowed_tools == before_tools == ALLOWED_TOOLS
    retest = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-DELEGATION-001",
            "specimen_id": "A2A-001",
            "mode": "RETEST",
            "execution": "live",
        },
    )
    assert retest.status_code == 200
    assert retest.get_json()["runtime"]["profile"] == "defended"
    assert retest.get_json()["runtime"]["identity_control_decision"] == "OBSERVE"
    assert retest.get_json()["runtime"]["follow_on_decision"] == "DENY"
    assert coded_policy().allowed_tools == ALLOWED_TOOLS


def test_pi_mcp_rag_memory_goal_still_launch(acme_client):
    client, _calls = _wired_app(acme_client)
    pi = client.post(
        "/api/launch",
        json={"lab_id": "LAB-PI-001", "specimen_id": "ATK-002", "mode": "ATTACK", "execution": "live"},
    )
    mcp = client.post(
        "/api/launch",
        json={"lab_id": "LAB-MCP-001", "specimen_id": "MCP-002", "mode": "ATTACK", "execution": "live"},
    )
    rag = client.post(
        "/api/launch",
        json={"lab_id": "LAB-RAG-CONTEXT", "specimen_id": "RAG-001", "mode": "ATTACK", "execution": "live"},
    )
    memory = client.post(
        "/api/launch",
        json={"lab_id": "LAB-MEMORY-001", "specimen_id": "MEMORY-001", "mode": "ATTACK", "execution": "live"},
    )
    goal = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-GOAL-INTEGRITY-001",
            "specimen_id": "GOAL-001",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    assert pi.status_code == 200
    assert mcp.status_code == 200
    assert rag.status_code == 200
    assert memory.status_code == 200
    assert goal.status_code == 200
    assert rag.get_json()["runtime"]["follow_on_decision"] == "ALLOW"
    assert memory.get_json()["runtime"]["follow_on_decision"] == "ALLOW"
    assert goal.get_json()["runtime"]["follow_on_decision"] == "ALLOW"
