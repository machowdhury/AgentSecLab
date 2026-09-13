"""Validate schema 1.0.0 itself and every first-lab emitted event."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.pipeline import run_loan_pipeline
from tests.helpers import PREDECESSOR_EVENT_NAMES, assert_all_schema_valid

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "security_event.schema.json"
QUESTIONS_PATH = ROOT / "schemas" / "splunk_investigation_fields.json"


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


def test_schema_identity(schema: dict) -> None:
    assert schema["properties"]["agentsec.schema.version"]["const"] == "1.2.0"
    assert schema["properties"]["agentsec.schema.name"]["const"] == "agentsec.security_event"
    names = set(schema["properties"]["event.name"]["enum"])
    assert names.isdisjoint(PREDECESSOR_EVENT_NAMES)
    assert "agentsec.control.decision" in names
    assert "agentsec.llm.started" in names
    assert "agentsec.mcp.started" in names
    assert "agentsec.mcp.completed" in names
    assert "agentsec.mcp.failed" in names
    assert "MCP-004" in schema["properties"]["agentsec.attack.id"]["enum"]
    assert "agentsec.mcp.resource.id" in schema["properties"]
    assert "agentsec.mcp.allowed_resource.ids" in schema["properties"]
    assert "effective_resource" not in schema["properties"]


def test_splunk_questions_map_to_schema_properties(schema: dict, questions: dict) -> None:
    allowed = set(schema["properties"])
    missing = []
    for item in questions["questions"]:
        for field in item["fields"]:
            if field not in allowed:
                missing.append(f"{item['id']} -> {field}")
    assert missing == [], "unmapped fields:\n" + "\n".join(missing)


def test_unknown_field_is_rejected(validator: Draft202012Validator, settings, counting_llm, memory) -> None:
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    event = dict(result.events[0])
    event["control.decision"] = "DENY"
    errors = list(validator.iter_errors(event))
    assert errors, "expected additionalProperties failure"


def test_deny_cannot_claim_operation_executed(settings, counting_llm, memory, validator) -> None:
    result = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="ATK-002",
    )
    deny = next(event for event in result.events if event.get("agentsec.control.decision") == "DENY")
    mutated = dict(deny)
    mutated["agentsec.operation.executed"] = True
    errors = list(validator.iter_errors(mutated))
    assert errors, "DENY with operation.executed=true must fail"


def test_predecessor_event_name_is_rejected(validator: Draft202012Validator, settings, counting_llm, memory) -> None:
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    event = dict(result.events[0])
    event["event.name"] = "agentsec.prompt_attack"
    errors = list(validator.iter_errors(event))
    assert errors


def test_every_emitted_event_matches_schema(settings, counting_llm, memory) -> None:
    benign = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert_all_schema_valid(benign.events)
    from agentsec.telemetry import MemorySink
    from agentsec.llm import StubLLM

    attack_memory = MemorySink()
    attack = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=StubLLM(),
        sink=attack_memory,
        memory=attack_memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="ATK-002",
    )
    assert_all_schema_valid(attack.events)
