"""Ollama unavailable uses the real client path. Invocation started, then failed — not DENY."""

from agentsec.attacks import BENIGN_LOAN
from agentsec.events import EVENT_CONTROL_DECISION, EVENT_LLM_COMPLETED, EVENT_LLM_FAILED, EVENT_LLM_STARTED
from agentsec.llm import CountingLLM, OllamaClient
from agentsec.pipeline import run_loan_pipeline
from agentsec.settings import reset_settings_cache
from tests.helpers import control_events, events_named


def test_ollama_unavailable_is_error_after_invocation(tmp_path, monkeypatch, memory):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "defended")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:1")
    reset_settings_cache()
    from agentsec.settings import get_settings

    settings = get_settings()
    llm = CountingLLM(OllamaClient(settings))
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert llm.call_count == 1
    assert result.terminal == "run_failed"
    assert result.error_stage == "llm_invocation"
    control = control_events(result.events)[0]
    assert control["agentsec.control.decision"] == "ALLOW"
    started = events_named(result.events, EVENT_LLM_STARTED)
    failed = events_named(result.events, EVENT_LLM_FAILED)
    assert started
    assert failed
    assert events_named(result.events, EVENT_LLM_COMPLETED) == []
    assert started[0]["agentsec.operation.attempted"] is True
    assert started[0]["agentsec.operation.executed"] is True
    assert "agentsec.operation.outcome" not in started[0]
    assert failed[0]["agentsec.operation.attempted"] is True
    assert failed[0]["agentsec.operation.executed"] is True
    assert failed[0]["agentsec.operation.outcome"] == "error"
    assert result.hops[0].control_decision != "DENY"
    assert result.hops[0].operation_outcome == "error"
    reset_settings_cache()


def test_stub_llm_error_matches_started_then_failed_contract(settings, memory):
    from agentsec.llm import StubLLM

    llm = CountingLLM(StubLLM(error_type="connection_error", error_message="ollama down"))
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert llm.call_count == 1
    assert events_named(result.events, EVENT_LLM_STARTED)
    assert events_named(result.events, EVENT_LLM_FAILED)
    assert result.hops[0].operation_attempted is True
    assert result.hops[0].operation_executed is True
    assert result.hops[0].operation_outcome == "error"
