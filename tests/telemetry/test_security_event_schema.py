"""Validate AgentSec security event fixtures against the closed JSON schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "security_event.schema.json"
QUESTIONS_PATH = ROOT / "schemas" / "splunk_investigation_fields.json"
EVENTS_DIR = ROOT / "telemetry" / "events"

EXPECTED_EVENTS = {
    "normal_request.json",
    "agent_handoff.json",
    "prompt_attack.json",
    "tool_request.json",
    "tool_denied.json",
    "a2a_delegation.json",
    "memory_write.json",
    "memory_read.json",
    "rag_retrieval.json",
    "control_decision.json",
    "attack_chain_step.json",
}


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def schema() -> dict:
    return load_json(SCHEMA_PATH)


@pytest.fixture(scope="module")
def validator(schema: dict) -> Draft202012Validator:
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture(scope="module")
def questions() -> dict:
    return load_json(QUESTIONS_PATH)


@pytest.fixture(scope="module")
def events() -> dict[str, dict]:
    loaded = {}
    for path in sorted(EVENTS_DIR.glob("*.json")):
        loaded[path.name] = load_json(path)
    return loaded


def test_expected_representative_events_exist(events: dict[str, dict]) -> None:
    assert set(events) == EXPECTED_EVENTS


def test_all_representative_events_match_schema(
    validator: Draft202012Validator, events: dict[str, dict]
) -> None:
    failures = []
    for name, event in events.items():
        errors = sorted(validator.iter_errors(event), key=lambda e: e.path)
        if errors:
            failures.append(f"{name}: {errors[0].message}")
    assert failures == [], "schema errors:\n" + "\n".join(failures)


def test_splunk_questions_map_to_schema_properties(
    schema: dict, questions: dict
) -> None:
    allowed = set(schema["properties"])
    missing = []
    for question, fields in questions.items():
        for field in fields:
            if field not in allowed:
                missing.append(f"{question} -> {field}")
    assert missing == [], "unmapped fields:\n" + "\n".join(missing)


def test_fixture_set_can_answer_every_splunk_question(
    events: dict[str, dict], questions: dict
) -> None:
    """Across representative events, each investigation question has at least one value."""
    unanswered = []
    for question, fields in questions.items():
        found = False
        for event in events.values():
            if any(event.get(field) not in (None, "", []) for field in fields):
                found = True
                break
        if not found:
            unanswered.append(question)
    assert unanswered == [], "no fixture answers:\n" + "\n".join(unanswered)


def test_unknown_field_is_rejected(validator: Draft202012Validator, events: dict) -> None:
    event = dict(events["normal_request.json"])
    event["control.decision"] = "DENY"
    errors = list(validator.iter_errors(event))
    assert errors, "expected additionalProperties failure"


def test_missing_run_id_is_rejected(validator: Draft202012Validator, events: dict) -> None:
    event = dict(events["normal_request.json"])
    del event["agentsec.run.id"]
    errors = list(validator.iter_errors(event))
    assert errors, "expected required agentsec.run.id"


def test_deny_cannot_claim_operation_executed(
    validator: Draft202012Validator, events: dict
) -> None:
    event = dict(events["prompt_attack.json"])
    event["agentsec.operation.executed"] = True
    errors = list(validator.iter_errors(event))
    assert errors, "DENY with operation.executed=true must fail"


def test_tool_denied_requires_scope_fields(
    validator: Draft202012Validator, events: dict
) -> None:
    event = dict(events["tool_denied.json"])
    del event["agentsec.scope.requested"]
    errors = list(validator.iter_errors(event))
    assert errors


def test_prompt_attack_requires_technique(
    validator: Draft202012Validator, events: dict
) -> None:
    event = dict(events["prompt_attack.json"])
    del event["agentsec.technique.id"]
    errors = list(validator.iter_errors(event))
    assert errors


def test_a2a_requires_delegator(validator: Draft202012Validator, events: dict) -> None:
    event = dict(events["a2a_delegation.json"])
    del event["agentsec.delegator.agent.id"]
    errors = list(validator.iter_errors(event))
    assert errors


def test_deny_events_have_executed_false(events: dict[str, dict]) -> None:
    denies = [
        e for e in events.values() if e["agentsec.control.decision"] == "DENY"
    ]
    assert denies, "expected at least one DENY fixture"
    for event in denies:
        assert event["agentsec.operation.executed"] is False


def test_normal_and_handoff_share_run_and_trace(events: dict[str, dict]) -> None:
    normal = events["normal_request.json"]
    handoff = events["agent_handoff.json"]
    assert normal["agentsec.run.id"] == handoff["agentsec.run.id"]
    assert normal["trace_id"] == handoff["trace_id"]
    assert handoff["parent_span_id"] == normal["span_id"]


def test_tool_allow_and_deny_show_scope_delta(events: dict[str, dict]) -> None:
    denied = events["tool_denied.json"]
    assert denied["agentsec.scope.requested"] != denied["agentsec.scope.allowed"]
    assert denied["gen_ai.tool.name"] == "execute_shell_command"


def test_memory_read_does_not_treat_untrusted_as_instruction(
    events: dict[str, dict]
) -> None:
    read = events["memory_read.json"]
    assert read["agentsec.memory.trust_level"] == "untrusted"
    assert read["agentsec.scope.allowed"] == "memory.read.as_data"
    assert read["agentsec.control.decision"] == "OBSERVE"
