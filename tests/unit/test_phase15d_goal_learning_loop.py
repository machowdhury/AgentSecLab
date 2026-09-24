"""Phase 15D: LAB-AGENT-GOAL-INTEGRITY-001 LIVE learning loop. Schema 1.9.0. No DET-GOAL."""

from __future__ import annotations

import threading
from pathlib import Path

from agentsec.events import content_hash
from agentsec.experiment import SCHEMA_VERSION
from agentsec.experiment_context import (
    LAB_GOAL,
    attack_retest_fingerprint_pair,
    bind_experiment_for_goal,
    lookup_experiment,
)
from agentsec.goal.fixtures import (
    INSTRUCTION_ID_MALICIOUS,
    INSTRUCTION_ID_NORMAL,
    MALICIOUS_NOTE,
    NORMAL_NOTE,
)
from agentsec.goal.request_contract import parse_goal_evaluate_body
from agentsec.goal.task import authoritative_task_contract
from agentsec.goal.trust import GOAL_FAIL_OPEN_REASON
from agentsec.lab_manifest import validate_lab_manifest
from agentsec.launch_catalog import lookup_launch
from agentsec.learning_contract import LEARNING_METADATA_NOT_AUTHORIZATION, assert_learning_not_policy
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy

from tests.unit.test_phase14b_attack_service import _wired_app

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
NOTE = ROOT / "docs" / "learning-notes" / "goal-integrity-live-learning-loop.md"
IMPL = ROOT / "docs" / "PHASE15D_GOAL_INTEGRITY_LIVE_LEARNING_LOOP.md"
INSTRUCTION_HASH = "sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2"
TASK_HASH = "sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c"
PROPOSED_HASH = "sha256:6326e3be47ecf73831a06be2b718f42219e0c950d4c989de23aa558bfdc01b34"


def test_phase15d_docs_exist():
    assert IMPL.is_file()
    assert NOTE.is_file()
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")
    assert (ROOT / "docs" / "PHASE15D_GOAL_ATTACK_SERVICE_LAUNCH_CONTRACT.md").is_file()
    assert (ROOT / "docs" / "PHASE15D_GOAL_GUIDED_INVESTIGATIONS.md").is_file()
    assert (ROOT / "docs" / "PHASE15D_SECURITY_BOUNDARY_REVIEW.md").is_file()
    assert (ROOT / "docs" / "PHASE15D_LIVE_VS_REPLAY.md").is_file()
    assert (ROOT / "docs" / "PHASE15D_ATTACK_RETEST_EQUIVALENCE.md").is_file()
    assert (ROOT / "docs" / "PHASE15D_SPLUNK_LIVE_VALIDATION.md").is_file()


def test_schema_unchanged_and_no_det_goal():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-GOAL" not in saved
    assert not list((ROOT / "learning").rglob("DET-GOAL*"))
    hunts = {
        path.name
        for path in (ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001" / "searches").glob("Q-*.spl")
    }
    assert hunts == {"Q-GOAL-INTEGRITY-AUTHORITY.spl"}


def test_learning_metadata_is_not_authorization():
    assert LEARNING_METADATA_NOT_AUTHORIZATION is True
    assert_learning_not_policy("LAB-AGENT-GOAL-INTEGRITY-001")
    manifest = validate_lab_manifest("LAB-AGENT-GOAL-INTEGRITY-001")
    assert manifest["not_authorization"] is True
    assert manifest["control_id"] == "CTRL-GOAL-INTEGRITY-001"
    assert manifest["enforcement_control_id"] == "CTRL-MCP-001"


def test_goal_attack_retest_fingerprint_is_malicious_instruction():
    attack_fp, retest_fp = attack_retest_fingerprint_pair(LAB_GOAL)
    assert attack_fp == retest_fp == content_hash(MALICIOUS_NOTE) == INSTRUCTION_HASH
    attack = lookup_experiment("LAB-AGENT-GOAL-INTEGRITY-001:ATTACK")
    retest = lookup_experiment("LAB-AGENT-GOAL-INTEGRITY-001:RETEST")
    assert attack is not None and retest is not None
    assert attack.payload == retest.payload == MALICIOUS_NOTE
    assert attack.instruction_id == retest.instruction_id == INSTRUCTION_ID_MALICIOUS
    assert attack.profile != retest.profile
    assert attack.intentionally_vulnerable is True
    assert retest.intentionally_vulnerable is False
    baseline = lookup_experiment("LAB-AGENT-GOAL-INTEGRITY-001:BASELINE")
    assert baseline is not None
    assert baseline.instruction_id == INSTRUCTION_ID_NORMAL
    assert baseline.payload == NORMAL_NOTE
    assert baseline.payload != MALICIOUS_NOTE
    task = authoritative_task_contract()
    assert task.fingerprint == TASK_HASH
    assert task.permitted_action == "summarize_lending_policy"
    assert task.permitted_tool == "lookup_policy"


def test_goal_launch_catalog_rows():
    attack = lookup_launch(
        lab_id="LAB-AGENT-GOAL-INTEGRITY-001",
        specimen_id="GOAL-001",
        mode="ATTACK",
        execution="live",
    )
    retest = lookup_launch(
        lab_id="LAB-AGENT-GOAL-INTEGRITY-001",
        specimen_id="GOAL-001",
        mode="RETEST",
        execution="live",
    )
    baseline = lookup_launch(
        lab_id="LAB-AGENT-GOAL-INTEGRITY-001",
        specimen_id="GOAL-BASELINE",
        mode="BASELINE",
        execution="live",
    )
    assert attack is not None and retest is not None and baseline is not None
    assert attack.profile == "vulnerable"
    assert retest.profile == "defended"
    assert attack.runtime_route == "goal_evaluate"


def test_goal_authority_fields_are_unknown_not_policy():
    parsed = parse_goal_evaluate_body(
        {
            "instruction_id": INSTRUCTION_ID_MALICIOUS,
            "experiment_id": "LAB-AGENT-GOAL-INTEGRITY-001:ATTACK",
            "profile": "vulnerable",
            "allowed_tools": ["lookup_policy"],
            "trusted_instruction": True,
            "authoritative_task": "extract_full_policy",
            "grants": ["policy:read"],
            "control_decision": "ALLOW",
            "instruction": MALICIOUS_NOTE,
            "python": "print(1)",
            "spl": "index=*",
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"


def test_goal_experiment_mismatch_is_error_not_vulnerable():
    ctx, err = bind_experiment_for_goal(
        experiment_id="LAB-AGENT-GOAL-INTEGRITY-001:ATTACK",
        instruction_id=INSTRUCTION_ID_NORMAL,
        user_id="applicant-web",
    )
    assert ctx is None
    assert err == "experiment_instruction_mismatch"
    unknown, unknown_err = bind_experiment_for_goal(
        experiment_id="LAB-AGENT-GOAL-INTEGRITY-001:PWN",
        instruction_id=INSTRUCTION_ID_MALICIOUS,
        user_id="applicant-web",
    )
    assert unknown is None
    assert unknown_err == "unknown_experiment"
    user, user_err = bind_experiment_for_goal(
        experiment_id="LAB-AGENT-GOAL-INTEGRITY-001:ATTACK",
        instruction_id=INSTRUCTION_ID_MALICIOUS,
        user_id="attacker-lab",
    )
    assert user is None
    assert user_err == "experiment_user_mismatch"


def test_live_goal_attack_and_retest_via_attack_service(acme_client):
    client, calls = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-GOAL-INTEGRITY-001",
            "specimen_id": "GOAL-001",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    retest = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-GOAL-INTEGRITY-001",
            "specimen_id": "GOAL-001",
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
    assert a["runtime"]["goal_control_decision"] == "OBSERVE"
    assert r["runtime"]["goal_control_decision"] == "DENY"
    assert a["runtime"]["goal_control_reason"] == GOAL_FAIL_OPEN_REASON
    assert r["runtime"]["goal_control_reason"] == "unauthorized_task_expansion"
    assert a["runtime"]["follow_on_decision"] == "ALLOW"
    assert r["runtime"]["follow_on_decision"] == "ALLOW"
    assert a["runtime"]["follow_on_reason"] == "tool_granted"
    assert r["runtime"]["follow_on_reason"] == "tool_granted"
    assert a["runtime"]["proposed_action"] == r["runtime"]["proposed_action"] == "extract_full_policy"
    assert a["runtime"]["effective_action"] == "extract_full_policy"
    assert r["runtime"]["effective_action"] == "summarize_lending_policy"
    assert a["runtime"]["wrong_goal_lookup_policy_count"] == 1
    assert r["runtime"]["wrong_goal_lookup_policy_count"] == 0
    assert a["runtime"]["in_task_lookup_policy_count"] == 0
    assert r["runtime"]["in_task_lookup_policy_count"] == 1
    assert a["runtime"]["lookup_policy_handler_count"] == 1
    assert r["runtime"]["lookup_policy_handler_count"] == 1
    assert a["input_fingerprint"] == r["input_fingerprint"] == INSTRUCTION_HASH
    assert a["runtime"]["instruction_hash"] == r["runtime"]["instruction_hash"] == INSTRUCTION_HASH
    assert a["runtime"]["task_fingerprint"] == r["runtime"]["task_fingerprint"] == TASK_HASH
    assert a["runtime"]["proposed_fingerprint"] == r["runtime"]["proposed_fingerprint"] == PROPOSED_HASH
    assert a["runtime"]["experiment_id"] == "LAB-AGENT-GOAL-INTEGRITY-001:ATTACK"
    assert r["runtime"]["experiment_id"] == "LAB-AGENT-GOAL-INTEGRITY-001:RETEST"
    assert a["runtime"].get("schema_version", "1.9.0") == "1.9.0"
    assert calls[0][0] == "/goal/evaluate"
    assert "profile" not in calls[0][1]
    assert "instruction" not in calls[0][1]
    assert set(calls[0][1]) <= {"instruction_id", "user_id", "experiment_id"}
    assert "Q-GOAL-INTEGRITY-AUTHORITY" in a["search_handoff"]["reused_hunts"]
    coded = coded_policy()
    assert coded.allowed_tools == ALLOWED_TOOLS == frozenset({"lookup_policy"})


def test_goal_browser_cannot_send_authority_on_launch(acme_client):
    client, calls = _wired_app(acme_client)
    for extra in (
        {"profile": "vulnerable"},
        {"allowed_tools": ["lookup_policy"]},
        {"grants": ["policy:read"]},
        {"trusted_instruction": True},
        {"authoritative_task": "extract_full_policy"},
        {"control_decision": "ALLOW"},
        {"python": "print(1)"},
        {"spl": "index=*"},
        {"instruction": MALICIOUS_NOTE},
        {"AGENTSEC_SECURITY_PROFILE": "vulnerable"},
    ):
        body = {
            "lab_id": "LAB-AGENT-GOAL-INTEGRITY-001",
            "specimen_id": "GOAL-001",
            "mode": "ATTACK",
            "execution": "live",
            **extra,
        }
        response = client.post("/api/launch", json=body)
        assert response.status_code == 400, extra
        assert response.get_json()["error"] == "unknown_fields"
    assert calls == []


def test_goal_attack_page_is_closed_launcher():
    from agentsec.attack_app import AcmeBankClient, create_app

    app = create_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/labs/LAB-AGENT-GOAL-INTEGRITY-001").get_data(as_text=True)
    assert "Goal / Instruction Integrity" in html
    assert "Launch ATTACK (LIVE)" in html
    assert "Launch RETEST (LIVE)" in html
    assert "Prediction and falsification" in html
    assert 'const labId = "LAB-AGENT-GOAL-INTEGRITY-001"' in html
    assert "GOAL-001" in html
    assert "CTRL-GOAL-INTEGRITY-001" in html
    assert "Q-GOAL-INTEGRITY-AUTHORITY" in html
    assert "GOAL / INSTRUCTION ≠ AUTHORITY" in html
    assert "AUTHORIZED TOOL ≠ AUTHORIZED GOAL" in html
    assert "Supporting action" in html
    assert "Prohibited objective" in html


def test_direct_goal_evaluate_without_experiment_id_keeps_auto_mode(acme_client):
    response = acme_client.post(
        "/goal/evaluate",
        json={"instruction_id": INSTRUCTION_ID_MALICIOUS, "user_id": "applicant-web"},
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["testbed_mode"] == "BASELINE"
    assert body.get("experiment_id") in (None, "")
    assert body["profile"] == "defended"
    assert body["goal_control_decision"] == "DENY"
    assert body["follow_on_decision"] == "ALLOW"
    assert body["wrong_goal_lookup_policy_count"] == 0
    assert body["in_task_lookup_policy_count"] == 1


def test_direct_goal_experiment_mismatch_http_is_error(acme_client):
    response = acme_client.post(
        "/goal/evaluate",
        json={
            "instruction_id": INSTRUCTION_ID_NORMAL,
            "user_id": "applicant-web",
            "experiment_id": "LAB-AGENT-GOAL-INTEGRITY-001:ATTACK",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "experiment_instruction_mismatch"
    assert body["lookup_policy_handler_count"] == 0
    empty = acme_client.post(
        "/goal/evaluate",
        json={
            "instruction_id": INSTRUCTION_ID_MALICIOUS,
            "user_id": "applicant-web",
            "experiment_id": "",
        },
    )
    assert empty.status_code == 400
    assert empty.get_json()["block_reason"] == "malformed_experiment"


def test_malformed_goal_body_is_error_not_policy(acme_client):
    response = acme_client.post("/goal/evaluate", data="not-json", content_type="application/json")
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "malformed_input"
    assert body["terminal"] == "run_failed"


def test_concurrent_goal_attack_and_retest_do_not_leak_profile(acme_client):
    client, _calls = _wired_app(acme_client)
    results = {}

    def fire(mode):
        response = client.post(
            "/api/launch",
            json={
                "lab_id": "LAB-AGENT-GOAL-INTEGRITY-001",
                "specimen_id": "GOAL-001",
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
    assert attack["input_fingerprint"] == retest["input_fingerprint"] == INSTRUCTION_HASH
    assert attack["runtime"]["follow_on_decision"] == "ALLOW"
    assert retest["runtime"]["follow_on_decision"] == "ALLOW"
    assert attack["runtime"]["wrong_goal_lookup_policy_count"] == 1
    assert retest["runtime"]["wrong_goal_lookup_policy_count"] == 0
    assert coded_policy().allowed_tools == ALLOWED_TOOLS


def test_attack_overlay_does_not_mutate_coded_policy_or_task_contract(acme_client):
    before_tools = coded_policy().allowed_tools
    before_task = authoritative_task_contract().fingerprint
    client, _calls = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-GOAL-INTEGRITY-001",
            "specimen_id": "GOAL-001",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    assert attack.status_code == 200
    assert coded_policy().allowed_tools == before_tools == ALLOWED_TOOLS
    assert authoritative_task_contract().fingerprint == before_task == TASK_HASH
    retest = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENT-GOAL-INTEGRITY-001",
            "specimen_id": "GOAL-001",
            "mode": "RETEST",
            "execution": "live",
        },
    )
    assert retest.status_code == 200
    assert retest.get_json()["runtime"]["profile"] == "defended"
    assert retest.get_json()["runtime"]["goal_control_decision"] == "DENY"
    assert coded_policy().allowed_tools == ALLOWED_TOOLS


def test_pi_mcp_rag_memory_still_launch(acme_client):
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
    assert pi.status_code == 200
    assert mcp.status_code == 200
    assert rag.status_code == 200
    assert memory.status_code == 200
    assert rag.get_json()["runtime"]["follow_on_decision"] == "ALLOW"
    assert memory.get_json()["runtime"]["follow_on_decision"] == "ALLOW"
