"""Phase 14B Attack Service: allowlist, lifecycle, process-env safety."""

from __future__ import annotations

import os
import threading

from agentsec.attack_app import AcmeBankClient, create_app
from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.bank_app import LabRuntime, create_app as create_bank
from agentsec.experiment import SCHEMA_VERSION
from agentsec.mcp.registry import default_registry
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import FanoutSink


def _wired_app(acme_client, probe_fn=None):
    process_calls = []

    def post_fn(path, payload):
        process_calls.append((path, payload))
        response = acme_client.post(path, json=payload)
        return response.status_code, response.get_json()

    def get_fn(path):
        response = acme_client.get(path)
        return response.status_code, response.get_json()

    attack_app = create_app(
        AcmeBankClient("http://acmebank-unused", post_fn=post_fn, get_fn=get_fn),
        launch_kwargs={"probe_fn": probe_fn} if probe_fn is not None else None,
    )
    attack_app.config["TESTING"] = True
    return attack_app.test_client(), process_calls


def test_legacy_atk002_endpoint_still_posts_catalog_payload(acme_client, counting_llm):
    client, _calls = _wired_app(acme_client)
    fired = client.post("/api/attacks/ATK-002", json={})
    assert fired.status_code == 200
    body = fired.get_json()
    assert body["attack_id"] == "ATK-002"
    assert body["blocked"] is True
    assert body["testbed_mode"] == "ATTACK"
    assert counting_llm.calls == []


def test_live_baseline_and_attack_mint_fresh_run_ids(acme_client, counting_llm):
    client, calls = _wired_app(acme_client)
    baseline = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-001",
            "mode": "BASELINE",
            "execution": "live",
        },
    )
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    b = baseline.get_json()
    a = attack.get_json()
    assert baseline.status_code == 200
    assert attack.status_code == 200
    assert b["run_id"]
    assert a["run_id"]
    assert b["run_id"] != a["run_id"]
    assert b["mode"] == "BASELINE"
    assert a["mode"] == "ATTACK"
    assert b["execution_mode"] == "LIVE"
    assert a["execution_mode"] == "LIVE"
    assert b["evidence_state"] == "WAITING_FOR_EVIDENCE"
    assert a["evidence_state"] == "WAITING_FOR_EVIDENCE"
    assert b["splunk_verified"] is False
    assert a["splunk_verified"] is False
    assert b["runtime"]["testbed_mode"] == "BASELINE"
    assert a["runtime"]["testbed_mode"] == "ATTACK"
    assert a["runtime"]["blocked"] is False
    assert a["runtime"]["profile"] == "vulnerable"
    assert a["intentionally_vulnerable"] is True
    assert a["profile"] == "vulnerable"
    assert b["profile"] == "defended"
    assert calls[1][1]["experiment_id"] == "LAB-PI-001:ATTACK"
    assert a["runtime"]["schema_version"] == SCHEMA_VERSION
    assert calls[0][1]["input"] == BENIGN_LOAN
    assert calls[1][1]["input"] == ATK_002_PAYLOAD
    assert "prediction" in a
    assert "attack_objective" in a["prediction"]
    assert a["search_handoff"]["copy_run_id"] == a["run_id"]
    assert a["run_id"] in a["search_handoff"]["starter_spl"]
    assert "Q-RUN-EVENTS" in a["search_handoff"]["reused_hunts"]


def test_retest_is_live_and_defended(acme_client, counting_llm):
    client, calls = _wired_app(acme_client)
    response = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "RETEST",
            "execution": "live",
        },
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["mode"] == "RETEST"
    assert body["profile"] == "defended"
    assert body["runtime"]["blocked"] is True
    assert body["runtime"]["testbed_mode"] == "RETEST"
    assert body["intentionally_vulnerable"] is False
    assert calls[0][1]["input"] == ATK_002_PAYLOAD
    assert calls[0][1]["experiment_id"] == "LAB-PI-001:RETEST"
    assert counting_llm.calls == []


def test_unknown_lab_specimen_and_not_allowlisted(acme_client):
    client, calls = _wired_app(acme_client)
    unknown_lab = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-ZZZ-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    unknown_specimen = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-999",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    combo = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-001",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    assert unknown_lab.get_json()["error"] == "unknown_lab"
    assert unknown_specimen.get_json()["error"] == "unknown_specimen"
    assert combo.get_json()["error"] == "not_allowlisted"
    assert calls == []


def test_browser_profile_is_unknown_fields(acme_client):
    client, calls = _wired_app(acme_client)
    response = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "profile": "vulnerable",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["error"] == "unknown_fields"
    assert "profile" in body["extra_fields"]
    assert body["error_class"] == "ERROR"
    assert calls == []


def test_grant_field_does_not_switch_to_vulnerable(acme_client, counting_llm):
    client, calls = _wired_app(acme_client)
    response = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
            "grant": "admin",
            "authorization": "ALLOW",
        },
    )
    body = response.get_json()
    assert body["error"] == "unknown_fields"
    assert calls == []
    assert counting_llm.calls == []


def test_launch_does_not_mutate_process_env(acme_client):
    client, _calls = _wired_app(acme_client)
    before_profile = os.environ.get("AGENTSEC_SECURITY_PROFILE")
    before_mode = os.environ.get("AGENTSEC_TESTBED_MODE")
    client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    assert os.environ.get("AGENTSEC_SECURITY_PROFILE") == before_profile
    assert os.environ.get("AGENTSEC_TESTBED_MODE") == before_mode


def test_serialized_concurrent_launches_get_distinct_run_ids(acme_client):
    client, _calls = _wired_app(acme_client)
    results = []

    def fire():
        response = client.post(
            "/api/launch",
            json={
                "lab_id": "LAB-PI-001",
                "specimen_id": "ATK-002",
                "mode": "ATTACK",
                "execution": "live",
            },
        )
        results.append(response.get_json()["run_id"])

    threads = [threading.Thread(target=fire), threading.Thread(target=fire)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 2
    assert results[0] != results[1]


def test_evidence_probe_ready_and_timeout(acme_client):
    ready_client, _ = _wired_app(
        acme_client,
        probe_fn=lambda _rid: {
            "splunk_attempted": True,
            "splunk_ok": True,
            "splunk_count": 6,
            "error": None,
        },
    )
    launched = ready_client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    run_id = launched.get_json()["run_id"]
    ready = ready_client.get(f"/api/launches/{run_id}/evidence?timeout_seconds=0")
    body = ready.get_json()
    assert ready.status_code == 200
    assert body["evidence_state"] == "EVIDENCE_READY"
    assert body["splunk_verified"] is True

    zero_client, _ = _wired_app(
        acme_client,
        probe_fn=lambda _rid: {
            "splunk_attempted": True,
            "splunk_ok": True,
            "splunk_count": 0,
            "error": None,
        },
    )
    launched2 = zero_client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    run2 = launched2.get_json()["run_id"]
    waiting = zero_client.get(f"/api/launches/{run2}/evidence?timeout_seconds=0")
    wait_body = waiting.get_json()
    assert wait_body["evidence_state"] == "WAITING_FOR_EVIDENCE"
    assert wait_body["splunk_verified"] is False
    assert wait_body.get("error") not in {"FAILED ATTACK", "BLOCKED", "SAFE", "PREVENTED"}


def test_experiment_id_ignores_process_testbed_override(tmp_path, monkeypatch, counting_llm, memory):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "defended")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("AGENTSEC_TESTBED_MODE", "RETEST")
    reset_settings_cache()
    from agentsec.settings import get_settings

    settings = get_settings()
    runtime = LabRuntime(
        settings=settings,
        llm=counting_llm,
        memory=memory,
        sink=FanoutSink([memory]),
        mcp_registry=default_registry(),
    )
    bank = create_bank(runtime)
    bank.config["TESTING"] = True
    acme = bank.test_client()
    client, calls = _wired_app(acme)
    response = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["runtime"]["testbed_mode"] == "ATTACK"
    assert body["runtime"]["profile"] == "vulnerable"
    assert calls[0][1]["experiment_id"] == "LAB-PI-001:ATTACK"
    assert os.environ.get("AGENTSEC_TESTBED_MODE") == "RETEST"
    reset_settings_cache()


def test_runtime_unreachable_is_error(acme_client):
    def post_fn(_path, _payload):
        return 503, {"error": "cannot reach AcmeBank: down"}

    def get_fn(_path):
        return 503, {"error": "cannot reach AcmeBank: down"}

    app = create_app(AcmeBankClient("http://unused", post_fn=post_fn, get_fn=get_fn))
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    body = response.get_json()
    assert response.status_code == 503
    assert body["error"] == "runtime_unreachable"
    assert body["error_class"] == "ERROR"
