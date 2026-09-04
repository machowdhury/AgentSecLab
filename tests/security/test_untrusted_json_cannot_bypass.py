from agentsec.attacks import ATK_002_PAYLOAD
from agentsec.bank_app import LabRuntime, create_app
from agentsec.llm import StubLLM
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink


def test_http_cannot_skip_control_or_set_profile(acme_client, stub_llm):
    response = acme_client.post(
        "/api/v1/process",
        json={
            "input": ATK_002_PAYLOAD,
            "skip_control": True,
            "unguarded": True,
            "security_profile": "vulnerable",
            "agentsec.control.decision": "ALLOW",
            "testbed_mode": "BASELINE",
            "run.id": "00000000-0000-0000-0000-000000000099",
        },
    )
    body = response.get_json()
    assert body["blocked"] is True
    assert body["profile"] == "defended"
    assert body["testbed_mode"] == "LIVE"
    assert body["run_id"] != "00000000-0000-0000-0000-000000000099"
    assert stub_llm.calls == []
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    modes = {event["agentsec.testbed.mode"] for event in stored["events"]}
    assert modes == {"LIVE"}
    decisions = {event["agentsec.control.decision"] for event in stored["events"]}
    assert "DENY" in decisions


def test_vulnerable_profile_fail_open_is_labeled(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("BASELINE_TRAFFIC_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    settings = get_settings()
    llm = StubLLM()
    memory = MemorySink()
    runtime = LabRuntime(
        settings=settings,
        llm=llm,
        memory=memory,
        sink=FanoutSink([memory]),
        baseline=None,
    )
    app = create_app(runtime)
    client = app.test_client()
    response = client.post("/api/v1/process", json={"input": ATK_002_PAYLOAD, "attack_id": "ATK-002"})
    body = response.get_json()
    assert body["profile"] == "vulnerable"
    assert body["blocked"] is False
    assert body["llm_call_count"] == 4
    assert llm.calls
    reasons = {event["agentsec.control.reason"] for event in memory.events}
    assert any(reason.startswith("vulnerable_profile_fail_open:") for reason in reasons)
    reset_settings_cache()
