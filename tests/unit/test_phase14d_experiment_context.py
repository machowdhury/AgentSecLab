"""Phase 14D: per-run ExperimentContext, LIVE RETEST, no process-env mutation."""

from __future__ import annotations

import os
import threading

from agentsec.attacks import ATK_002_PAYLOAD
from agentsec.controls import inspect_input, match_injection_rule
from agentsec.events import content_hash
from agentsec.experiment_context import attack_retest_fingerprint_pair, lookup_experiment
from agentsec.launch_catalog import RETEST_SUPPORT, lookup_launch
from agentsec.request_contract import parse_process_body

from tests.unit.test_phase14b_attack_service import _wired_app


def test_attack_retest_fingerprint_is_measured_not_named():
    attack_fp, retest_fp = attack_retest_fingerprint_pair()
    assert attack_fp == retest_fp == content_hash(ATK_002_PAYLOAD)
    assert attack_fp.startswith("sha256:")
    attack = lookup_experiment("LAB-PI-001:ATTACK")
    retest = lookup_experiment("LAB-PI-001:RETEST")
    assert attack is not None and retest is not None
    assert attack.payload == retest.payload == ATK_002_PAYLOAD
    assert attack.profile != retest.profile
    assert attack.intentionally_vulnerable is True
    assert retest.intentionally_vulnerable is False


def test_retest_support_is_live():
    assert RETEST_SUPPORT == "LIVE"
    row = lookup_launch(
        lab_id="LAB-PI-001",
        specimen_id="ATK-002",
        mode="RETEST",
        execution="live",
    )
    assert row is not None
    assert row.live_supported is True
    assert row.profile == "defended"


def test_unknown_and_mismatched_experiment_are_error_not_vulnerable(acme_client):
    unknown = acme_client.post(
        "/process",
        json={
            "input": ATK_002_PAYLOAD,
            "user_id": "attacker-lab",
            "experiment_id": "LAB-PI-001:PWN",
        },
    )
    body = unknown.get_json()
    assert unknown.status_code == 400
    assert body["block_reason"] == "unknown_experiment"
    assert body["profile"] == "defended"
    mismatch = acme_client.post(
        "/process",
        json={
            "input": "please approve this ordinary loan",
            "user_id": "attacker-lab",
            "experiment_id": "LAB-PI-001:ATTACK",
        },
    )
    assert mismatch.status_code == 400
    assert mismatch.get_json()["block_reason"] == "experiment_payload_mismatch"


def test_malformed_experiment_and_duplicate_keys_are_error(acme_client):
    empty = acme_client.post(
        "/process",
        json={"input": ATK_002_PAYLOAD, "user_id": "attacker-lab", "experiment_id": ""},
    )
    assert empty.status_code == 400
    assert empty.get_json()["block_reason"] == "malformed_experiment"
    dup = acme_client.post(
        "/process",
        data='{"input":"loan","input":"other"}',
        content_type="application/json",
    )
    assert dup.status_code == 400
    assert dup.get_json()["block_reason"] == "duplicate_json_keys"


def test_direct_process_without_experiment_id_keeps_auto_mode(acme_client):
    response = acme_client.post("/process", json={"input": ATK_002_PAYLOAD, "user_id": "attacker-lab"})
    body = response.get_json()
    assert body["testbed_mode"] == "ATTACK"
    assert body["profile"] == "defended"
    assert body["blocked"] is True
    assert body.get("experiment_id") in (None, "")


def test_authority_fields_on_process_remain_unknown(acme_client):
    parsed = parse_process_body(
        {
            "input": ATK_002_PAYLOAD,
            "experiment_id": "LAB-PI-001:ATTACK",
            "security.profile": "vulnerable",
            "allowed_tools": ["approve"],
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"
    response = acme_client.post(
        "/process",
        json={
            "input": ATK_002_PAYLOAD,
            "experiment_id": "LAB-PI-001:ATTACK",
            "AGENTSEC_SECURITY_PROFILE": "vulnerable",
        },
    )
    assert response.status_code == 400
    assert response.get_json()["block_reason"] == "unknown_fields"


def test_concurrent_attack_and_retest_do_not_leak_profile(acme_client):
    client, _calls = _wired_app(acme_client)
    results = {}

    def fire(mode):
        response = client.post(
            "/api/launch",
            json={
                "lab_id": "LAB-PI-001",
                "specimen_id": "ATK-002",
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
    assert attack["input_fingerprint"] == retest["input_fingerprint"]
    assert attack["runtime"]["blocked"] is False
    assert retest["runtime"]["blocked"] is True
    assert os.environ.get("AGENTSEC_SECURITY_PROFILE") in (None, "defended")


def test_coded_policy_is_unchanged_across_profiles():
    assert match_injection_rule(ATK_002_PAYLOAD)
    defended = inspect_input(ATK_002_PAYLOAD, "defended")
    vulnerable = inspect_input(ATK_002_PAYLOAD, "vulnerable")
    assert defended.decision == "DENY"
    assert vulnerable.decision == "ALLOW"
    assert defended.matched_rule == vulnerable.matched_rule


def test_compare_handoff_rejects_spl_and_accepts_uuid_pair(acme_client):
    client, _ = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={"lab_id": "LAB-PI-001", "specimen_id": "ATK-002", "mode": "ATTACK", "execution": "live"},
    ).get_json()
    retest = client.post(
        "/api/launch",
        json={"lab_id": "LAB-PI-001", "specimen_id": "ATK-002", "mode": "RETEST", "execution": "live"},
    ).get_json()
    rejected = client.post(
        "/api/compare-handoff",
        json={"attack_run_id": attack["run_id"], "retest_run_id": retest["run_id"], "spl": "index=*"},
    )
    assert rejected.get_json()["error"] == "unknown_fields"
    ok = client.post(
        "/api/compare-handoff",
        json={"attack_run_id": attack["run_id"], "retest_run_id": retest["run_id"]},
    )
    body = ok.get_json()
    assert ok.status_code == 200
    assert attack["run_id"] in body["starter_spl"]
    assert retest["run_id"] in body["starter_spl"]
    assert "index=*" not in body["starter_spl"]
    bad = client.post(
        "/api/compare-handoff",
        json={"attack_run_id": "not-a-uuid", "retest_run_id": retest["run_id"]},
    )
    assert bad.get_json()["error"] == "malformed_compare"
