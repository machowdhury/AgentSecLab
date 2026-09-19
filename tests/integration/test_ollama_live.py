"""LIVE Ollama validation. Skips when the configured local model is not reachable.

This is separated from stub tests. A skip is not a fake success.
"""

from __future__ import annotations

import pytest

from agentsec.attacks import BENIGN_LOAN
from agentsec.events import EVENT_LLM_COMPLETED, EVENT_LLM_STARTED
from agentsec.llm import CountingLLM, OllamaClient
from agentsec.pipeline import run_loan_pipeline
from tests.helpers import events_named


@pytest.mark.live_ollama
def test_live_ollama_benign_baseline_when_available(settings, memory):
    client = OllamaClient(settings)
    if not client.health():
        pytest.skip("local Ollama with the configured model is not reachable")
    llm = CountingLLM(client)
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert llm.call_count == 4
    assert result.blocked is False
    assert result.terminal == "completed_allowed"
    assert events_named(result.events, EVENT_LLM_STARTED)
    assert events_named(result.events, EVENT_LLM_COMPLETED)
    assert all(hop.operation_executed is True for hop in result.hops)
