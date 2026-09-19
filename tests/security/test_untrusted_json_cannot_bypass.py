from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.bank_app import LabRuntime, create_app
from agentsec.llm import CountingLLM, StubLLM
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink
from agentsec.mcp.registry import default_registry
from tests.helpers import assert_all_schema_valid, control_events, event_names


def test_http_cannot_skip_control_or_set_closed_fields(acme_client, counting_llm):
    response = acme_client.post(
        "/process",
        json={
            "input": ATK_002_PAYLOAD,
            "skip_control": True,
            "unguarded": True,
            "security.profile": "vulnerable",
            "security_profile": "vulnerable",
            "agentsec.control.decision": "ALLOW",
            "testbed.mode": "BASELINE",
            "execution.mode": "SIMULATED",
            "telemetry.fidelity": "SYNTHETIC",
            "run.id": "00000000-0000-0000-0000-000000000099",
            "agentsec.run.id": "00000000-0000-0000-0000-000000000099",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["terminal"] == "run_failed"
    assert body["profile"] == "defended"
    assert body["run_id"] != "00000000-0000-0000-0000-000000000099"
    assert body["llm_call_count"] == 0
    assert counting_llm.calls == []
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    assert_all_schema_valid(stored["events"])
    for event in stored["events"]:
        assert event["agentsec.security.profile"] == "defended"
        assert event["agentsec.testbed.mode"] != "BASELINE" or event["agentsec.attack.id"] == "ATK-002"
        # Client BASELINE was rejected; server classified ATK-002 as ATTACK (or RETEST if overridden).
        assert event["agentsec.testbed.mode"] in ("ATTACK", "RETEST")
        assert event["agentsec.execution.mode"] == "LIVE"
        assert event["agentsec.telemetry.fidelity"] == "OBSERVED"
        assert event["agentsec.run.id"] == body["run_id"]
        assert event["agentsec.incident.id"] == body["run_id"]
    assert "agentsec.llm.started" not in event_names(stored["events"])


def test_clean_atk002_is_denied_in_defended(acme_client, counting_llm):
    response = acme_client.post("/process", json={"input": ATK_002_PAYLOAD, "user_id": "attacker-lab"})
    body = response.get_json()
    assert response.status_code == 200
    assert body["blocked"] is True
    assert body["profile"] == "defended"
    assert body["testbed_mode"] == "ATTACK"
    assert body["hops"][0]["control.decision"] == "DENY"
    assert body["hops"][0]["operation.attempted"] is False
    assert body["hops"][0]["operation.executed"] is False
    assert body["hops"][0]["operation.outcome"] == "prevented"
    assert counting_llm.call_count == 0


def test_benign_http_is_baseline_and_server_mints_run_id(acme_client, counting_llm):
    response = acme_client.post("/process", json={"input": BENIGN_LOAN})
    body = response.get_json()
    assert response.status_code == 200
    assert body["testbed_mode"] == "BASELINE"
    assert body["execution_mode"] == "LIVE"
    assert body["telemetry_fidelity"] == "OBSERVED"
    assert body["run_id"] == body["incident_id"]
    assert counting_llm.call_count == 4


def test_vulnerable_profile_fail_open_is_labeled(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    settings = get_settings()
    llm = CountingLLM(StubLLM())
    memory = MemorySink()
    runtime = LabRuntime(
        settings=settings,
        llm=llm,
        memory=memory,
        sink=FanoutSink([memory]),
        mcp_registry=default_registry(),
    )
    app = create_app(runtime)
    client = app.test_client()
    response = client.post("/process", json={"input": ATK_002_PAYLOAD, "user_id": "attacker-lab"})
    body = response.get_json()
    assert body["profile"] == "vulnerable"
    assert body["blocked"] is False
    assert body["testbed_mode"] == "ATTACK"
    assert body["llm_call_count"] == 4
    assert llm.call_count == 4
    reasons = {event["agentsec.control.reason"] for event in control_events(memory.events)}
    assert any("vulnerable_profile_fail_open:" in reason for reason in reasons)
    assert any("reference control" in reason for reason in reasons)
    reset_settings_cache()


def test_retest_label_is_server_owned(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "defended")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("AGENTSEC_TESTBED_MODE", "RETEST")
    reset_settings_cache()
    from agentsec.settings import get_settings

    settings = get_settings()
    llm = CountingLLM(StubLLM())
    memory = MemorySink()
    runtime = LabRuntime(
        settings=settings,
        llm=llm,
        memory=memory,
        sink=FanoutSink([memory]),
        mcp_registry=default_registry(),
    )
    client = create_app(runtime).test_client()
    response = client.post("/process", json={"input": ATK_002_PAYLOAD, "user_id": "attacker-lab"})
    body = response.get_json()
    assert body["testbed_mode"] == "RETEST"
    assert body["hops"][0]["control.decision"] == "DENY"
    assert llm.call_count == 0
    modes = {event["agentsec.testbed.mode"] for event in memory.events}
    assert modes == {"RETEST"}
    reset_settings_cache()


def test_client_cannot_set_security_profile_via_valid_body(acme_client, counting_llm):
    response = acme_client.post(
        "/process",
        json={"input": ATK_002_PAYLOAD, "user_id": "attacker-lab"},
    )
    body = response.get_json()
    assert body["profile"] == "defended"
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    profiles = {event["agentsec.security.profile"] for event in stored["events"]}
    assert profiles == {"defended"}
