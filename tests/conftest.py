"""Shared Phase 2A test runtime: stub LLM spy, no OTLP, temp artifacts."""

from __future__ import annotations

import pytest

from agentsec.bank_app import LabRuntime, create_app
from agentsec.llm import CountingLLM, StubLLM
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import FanoutSink, MemorySink
from agentsec.mcp.registry import default_registry


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "defended")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("AGENTSEC_LAB_ID", "agentsec-local")
    monkeypatch.delenv("AGENTSEC_TESTBED_MODE", raising=False)
    reset_settings_cache()
    from agentsec.settings import get_settings

    yield get_settings()
    reset_settings_cache()


@pytest.fixture
def stub_llm():
    return StubLLM()


@pytest.fixture
def counting_llm(stub_llm):
    return CountingLLM(stub_llm)


@pytest.fixture
def memory():
    return MemorySink()


@pytest.fixture
def runtime(settings, counting_llm, memory):
    return LabRuntime(
        settings=settings,
        llm=counting_llm,
        memory=memory,
        sink=FanoutSink([memory]),
        mcp_registry=default_registry(),
    )


@pytest.fixture
def acme_client(runtime):
    app = create_app(runtime)
    app.config["TESTING"] = True
    return app.test_client()
