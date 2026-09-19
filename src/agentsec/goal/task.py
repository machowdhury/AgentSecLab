"""Frozen server-owned TaskContract. Untrusted input cannot construct this object."""

from __future__ import annotations

import json
from dataclasses import dataclass

from agentsec.events import content_hash, content_preview
from agentsec.goal.fixtures import (
    PERMITTED_ACTION,
    PERMITTED_RESOURCE,
    PERMITTED_SCOPE,
    PERMITTED_TOOL,
    TASK_ID,
    TASK_OBJECTIVE,
    TASK_PROVENANCE,
)


@dataclass(frozen=True)
class TaskContract:
    """Immutable orchestrator task. Fingerprint excludes run.id / profile / time."""

    task_id: str
    objective: str
    permitted_action: str
    permitted_tool: str
    permitted_scope: str
    permitted_resource: str
    provenance: str
    fingerprint: str

    def canonical_dict(self) -> dict[str, str]:
        return {
            "task_id": self.task_id,
            "objective": self.objective,
            "permitted_action": self.permitted_action,
            "permitted_tool": self.permitted_tool,
            "permitted_scope": self.permitted_scope,
            "permitted_resource": self.permitted_resource,
            "provenance": self.provenance,
        }

    def preview(self) -> str:
        return content_preview(self.objective)

    def permits(self, action: str) -> bool:
        return action == self.permitted_action

    def tool_arguments(self) -> dict[str, str]:
        return {"policy_id": self.permitted_resource}


def authoritative_task_contract() -> TaskContract:
    """Server-owned fixture. Never derived from instruction text."""
    snapshot = {
        "task_id": TASK_ID,
        "objective": TASK_OBJECTIVE,
        "permitted_action": PERMITTED_ACTION,
        "permitted_tool": PERMITTED_TOOL,
        "permitted_scope": PERMITTED_SCOPE,
        "permitted_resource": PERMITTED_RESOURCE,
        "provenance": TASK_PROVENANCE,
    }
    return TaskContract(
        task_id=TASK_ID,
        objective=TASK_OBJECTIVE,
        permitted_action=PERMITTED_ACTION,
        permitted_tool=PERMITTED_TOOL,
        permitted_scope=PERMITTED_SCOPE,
        permitted_resource=PERMITTED_RESOURCE,
        provenance=TASK_PROVENANCE,
        fingerprint=content_hash(json.dumps(snapshot, sort_keys=True, separators=(",", ":"))),
    )
