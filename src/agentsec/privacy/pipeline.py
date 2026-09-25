"""L8 privacy experiment: same authorized action, different data exposure."""

from __future__ import annotations

import json
from dataclasses import replace
from types import MappingProxyType
from typing import Any, Mapping

from agentsec.events import content_hash
from agentsec.mcp.pipeline import McpInvokeResult, run_mcp_invoke
from agentsec.mcp.policy import McpPolicy
from agentsec.mcp.registry import ToolRegistry
from agentsec.mcp.tools import ToolSpec
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink

LAB_ID = "LAB-PRIVACY-DATA-GOVERNANCE-001"
PRIVACY_ATTACK_ID = "PRIVACY-001"
TOOL_NAME = "prepare_support_contact"
TOOL_SCOPE = "support:contact:prepare"
RECORD_ARGUMENT = "record_json"

TASK_PURPOSE = "Confirm the synthetic customer's preferred support contact channel."
REQUIRED_FIELDS = frozenset({"customer_id", "preferred_channel"})
FORBIDDEN_FIELD_MARKERS = (
    "password",
    "secret",
    "token",
    "credential",
    "api_key",
    "private_key",
)

MINIMIZED_RECORD: Mapping[str, str] = MappingProxyType(
    {
        "customer_id": "cust-synthetic-001",
        "preferred_channel": "email",
    }
)

FULL_RECORD: Mapping[str, str] = MappingProxyType(
    {
        "account_balance_band": "synthetic-medium",
        "customer_id": "cust-synthetic-001",
        "email": "ava.customer@example.invalid",
        "internal_case_note": "synthetic-only fee inquiry",
        "postal_address": "10 Example Lane, Testville",
        "preferred_channel": "email",
    }
)


def validate_synthetic_record(record: object) -> dict[str, str]:
    """Reject malformed, secret-shaped, or non-synthetic exercise records."""
    if not isinstance(record, dict):
        raise ValueError("privacy fixture must be an object")
    if not record or not all(isinstance(key, str) for key in record):
        raise ValueError("privacy fixture keys must be strings")
    if not all(isinstance(value, str) and value.strip() for value in record.values()):
        raise ValueError("privacy fixture values must be non-empty strings")
    if not REQUIRED_FIELDS.issubset(record):
        raise ValueError("privacy fixture is missing task-required fields")
    if not set(record).issubset(FULL_RECORD):
        raise ValueError("privacy fixture contains an unsupported field")
    if any(marker in key.lower() for key in record for marker in FORBIDDEN_FIELD_MARKERS):
        raise ValueError("secret-shaped fields are forbidden")
    if not record["customer_id"].startswith("cust-synthetic-"):
        raise ValueError("customer identifier must be obviously synthetic")
    email = record.get("email")
    if email is not None and not email.endswith("@example.invalid"):
        raise ValueError("email must use the reserved example.invalid domain")
    note = record.get("internal_case_note")
    if note is not None and "synthetic" not in note.lower():
        raise ValueError("case note must be explicitly synthetic")
    return dict(record)


def serialize_record(record: Mapping[str, str]) -> str:
    validated = validate_synthetic_record(dict(record))
    return json.dumps(validated, sort_keys=True, separators=(",", ":"))


def _prepare_support_contact(arguments: dict[str, Any]) -> dict[str, Any]:
    raw = arguments[RECORD_ARGUMENT]
    if not isinstance(raw, str):
        raise ValueError("record_json must be a string")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("record_json must contain valid JSON") from exc
    record = validate_synthetic_record(decoded)
    fields = set(record)
    return {
        "customer_id": record["customer_id"],
        "preferred_channel": record["preferred_channel"],
        "received_fields": sorted(fields),
        "required_fields": sorted(REQUIRED_FIELDS),
        "unnecessary_fields": sorted(fields - REQUIRED_FIELDS),
        "purpose": TASK_PURPOSE,
        "synthetic": True,
    }


def privacy_registry() -> ToolRegistry:
    spec = ToolSpec(
        name=TOOL_NAME,
        required_scope=TOOL_SCOPE,
        valid_scopes=frozenset({TOOL_SCOPE}),
        required_keys=frozenset({RECORD_ARGUMENT}),
        handler=_prepare_support_contact,
        description="Prepare a contact-channel summary from an obviously synthetic record.",
        input_schema={
            "type": "object",
            "properties": {RECORD_ARGUMENT: {"type": "string"}},
            "required": [RECORD_ARGUMENT],
        },
    )
    return ToolRegistry(specs={TOOL_NAME: spec})


def privacy_policy() -> McpPolicy:
    return McpPolicy(
        agent_id="acme-agent-privacy-001",
        allowed_tools=frozenset({TOOL_NAME}),
        allowed_scopes=frozenset({TOOL_SCOPE}),
        allowed_policy_ids=frozenset(),
    )


def record_for_mode(mode: str) -> dict[str, str]:
    if mode == "ATTACK":
        return validate_synthetic_record(dict(FULL_RECORD))
    if mode == "RETEST":
        return validate_synthetic_record(dict(MINIMIZED_RECORD))
    raise ValueError("privacy mode must be ATTACK or RETEST")


def run_privacy_specimen(
    *,
    mode: str,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    write_evidence: bool = True,
) -> McpInvokeResult:
    """Execute one privacy specimen through the unchanged MCP PDP.

    ATTACK and RETEST are experiment labels. Both are expected to ALLOW and
    complete. The privacy distinction is the data supplied to the tool.
    """
    record = record_for_mode(mode)
    record_json = serialize_record(record)
    base = settings or get_settings()
    privacy_settings = replace(base, lab_id=LAB_ID, security_profile="defended")
    expected = (
        "ALLOW and complete with excessive synthetic fields visible to the tool and telemetry"
        if mode == "ATTACK"
        else "ALLOW and complete with only purpose-required synthetic fields"
    )
    return run_mcp_invoke(
        tool=TOOL_NAME,
        arguments={RECORD_ARGUMENT: record_json},
        requested_scope=TOOL_SCOPE,
        sink=sink,
        memory=memory,
        settings=privacy_settings,
        user_id="support-agent-synthetic",
        testbed_mode=mode,
        attack_id=PRIVACY_ATTACK_ID,
        write_evidence=write_evidence,
        registry=privacy_registry(),
        policy=privacy_policy(),
        expected_behavior=expected,
        experiment_id=f"{LAB_ID}:{mode}",
        input_fingerprint=content_hash(record_json),
    )
