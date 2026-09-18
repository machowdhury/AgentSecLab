"""Shared assertions for Phase 2A runtime tests."""

from __future__ import annotations

from agentsec.events import (
    EVENT_CONTROL_DECISION,
    EVENT_LLM_COMPLETED,
    EVENT_LLM_FAILED,
    EVENT_LLM_STARTED,
)
from agentsec.schema import validate_event

PREDECESSOR_EVENT_NAMES = {
    "agentsec.normal_request",
    "agentsec.prompt_attack",
    "agentsec.agent_handoff",
    "agentsec.control_decision",
}


def event_names(events: list[dict]) -> list[str]:
    return [event["event.name"] for event in events]


def events_named(events: list[dict], name: str) -> list[dict]:
    return [event for event in events if event["event.name"] == name]


def hop_events(events: list[dict], hop_index: int) -> list[dict]:
    return [event for event in events if event.get("agentsec.hop.index") == hop_index]


def llm_events_for_hop(events: list[dict], hop_index: int) -> list[dict]:
    names = {EVENT_LLM_STARTED, EVENT_LLM_COMPLETED, EVENT_LLM_FAILED}
    return [
        event
        for event in hop_events(events, hop_index)
        if event["event.name"] in names
    ]


def control_events(events: list[dict]) -> list[dict]:
    return events_named(events, EVENT_CONTROL_DECISION)


def assert_all_schema_valid(events: list[dict]) -> None:
    assert events, "expected emitted events"
    for event in events:
        validate_event(event)
        assert event["agentsec.schema.name"] == "agentsec.security_event"
        assert event["agentsec.schema.version"] == "1.7.0"
        assert event["event.name"] not in PREDECESSOR_EVENT_NAMES


def assert_correlation(
    events: list[dict],
    run_id: str,
    *,
    workflow_entry: str = "/process",
) -> None:
    assert events
    traces = {event["trace_id"] for event in events}
    assert traces == {events[0]["trace_id"]}
    for event in events:
        assert event["agentsec.run.id"] == run_id
        assert event["agentsec.incident.id"] == run_id
        assert event["agentsec.execution.mode"] == "LIVE"
        assert event["agentsec.telemetry.fidelity"] == "OBSERVED"
        assert event["agentsec.workflow.entry"] == workflow_entry


def assert_sequence_ordering(events: list[dict]) -> None:
    sequences = [event["agentsec.sequence"] for event in events]
    assert sequences == list(range(1, len(events) + 1))
    assert len(set(sequences)) == len(sequences)


def assert_no_llm_for_hop(events: list[dict], hop_index: int) -> None:
    assert llm_events_for_hop(events, hop_index) == []
