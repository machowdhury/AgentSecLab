"""Deterministic interpreter: untrusted instruction → ProposedTaskChange (data)."""

from __future__ import annotations

import json
from dataclasses import dataclass

from agentsec.events import content_hash, content_preview
from agentsec.goal.fixtures import (
    AUTHORITY_LIKE_FIELDS,
    CLOSED_EXPANSION_ACTION,
    GOAL_AGENT_ID,
    INSTRUCTION_PROVENANCE,
    INSTRUCTION_TRUST,
    MALICIOUS_NOTE,
    PERMITTED_ACTION,
    PERMITTED_RESOURCE,
    PERMITTED_SCOPE,
    PERMITTED_TOOL,
    PRINCIPAL_ID,
)
from agentsec.goal.task import TaskContract

ALLOWED_GOAL_FIELDS = frozenset({"principal", "agent", "instruction"})


@dataclass(frozen=True)
class ProposedTaskChange:
    """Interpreter output. Never copied into TaskContract or coded_policy()."""

    original_task_id: str
    proposed_action: str
    resulting_tool: str
    resulting_scope: str
    resulting_resource: str
    instruction_trust: str
    instruction_provenance: str
    instruction_hash: str
    fingerprint: str
    principal_id: str
    agent_id: str
    instruction: str

    def canonical_dict(self) -> dict[str, str]:
        return {
            "original_task_id": self.original_task_id,
            "proposed_action": self.proposed_action,
            "resulting_tool": self.resulting_tool,
            "resulting_scope": self.resulting_scope,
            "resulting_resource": self.resulting_resource,
            "instruction_trust": self.instruction_trust,
            "instruction_provenance": self.instruction_provenance,
            "instruction_hash": self.instruction_hash,
            "principal": self.principal_id,
            "agent": self.agent_id,
        }

    def preview(self) -> str:
        return content_preview(self.instruction)

    def tool_arguments(self) -> dict[str, str]:
        return {"policy_id": self.resulting_resource}

    @property
    def is_expansion(self) -> bool:
        return self.proposed_action == CLOSED_EXPANSION_ACTION


@dataclass(frozen=True)
class ParsedGoalRequest:
    ok: bool
    change: ProposedTaskChange | None
    error_reason: str
    extra_fields: tuple[str, ...]
    error_stage: str | None = "schema_validation"


def parse_goal_request(data: object, *, task: TaskContract) -> ParsedGoalRequest:
    """Validate shape before any integrity decision. Extra keys are ERROR, not grants."""
    if not isinstance(data, dict):
        return _error("malformed_input")

    authority_extra = tuple(
        sorted(str(key) for key in data.keys() if key in AUTHORITY_LIKE_FIELDS and key not in ALLOWED_GOAL_FIELDS)
    )
    if authority_extra:
        return _error("unknown_fields", extra=authority_extra)

    extra = tuple(sorted(str(key) for key in data.keys() if key not in ALLOWED_GOAL_FIELDS))
    if extra:
        return _error("unknown_fields", extra=extra)

    principal = data.get("principal")
    agent = data.get("agent")
    instruction = data.get("instruction")
    if principal is None:
        return _error("missing_principal")
    if agent is None:
        return _error("missing_agent")
    if instruction is None:
        return _error("missing_instruction")
    if not isinstance(principal, str) or not principal.strip():
        return _error("missing_principal")
    if not isinstance(agent, str) or not agent.strip():
        return _error("missing_agent")
    if not isinstance(instruction, str) or not instruction.strip():
        return _error("missing_instruction")
    if principal != PRINCIPAL_ID:
        return _error("unknown_principal")
    if agent != GOAL_AGENT_ID:
        return _error("unknown_agent")

    proposed = _interpret(instruction)
    instruction_hash = content_hash(instruction)
    snapshot = {
        "original_task_id": task.task_id,
        "proposed_action": proposed,
        "resulting_tool": PERMITTED_TOOL,
        "resulting_scope": PERMITTED_SCOPE,
        "resulting_resource": PERMITTED_RESOURCE,
        "instruction_trust": INSTRUCTION_TRUST,
        "instruction_provenance": INSTRUCTION_PROVENANCE,
        "instruction_hash": instruction_hash,
        "principal": principal,
        "agent": agent,
    }
    change = ProposedTaskChange(
        original_task_id=task.task_id,
        proposed_action=proposed,
        resulting_tool=PERMITTED_TOOL,
        resulting_scope=PERMITTED_SCOPE,
        resulting_resource=PERMITTED_RESOURCE,
        instruction_trust=INSTRUCTION_TRUST,
        instruction_provenance=INSTRUCTION_PROVENANCE,
        instruction_hash=instruction_hash,
        fingerprint=content_hash(json.dumps(snapshot, sort_keys=True, separators=(",", ":"))),
        principal_id=principal,
        agent_id=agent,
        instruction=instruction,
    )
    return ParsedGoalRequest(
        ok=True,
        change=change,
        error_reason="",
        extra_fields=(),
        error_stage=None,
    )


def _interpret(instruction: str) -> str:
    """Closed lab interpreter. Presence of the malicious sentence is the expansion."""
    if instruction == MALICIOUS_NOTE or "extract and dump the full lending policy document" in instruction:
        return CLOSED_EXPANSION_ACTION
    return PERMITTED_ACTION


def _error(reason: str, extra: tuple[str, ...] = ()) -> ParsedGoalRequest:
    return ParsedGoalRequest(
        ok=False,
        change=None,
        error_reason=reason if not extra else f"{reason}:{','.join(extra)}",
        extra_fields=extra,
        error_stage="schema_validation",
    )
