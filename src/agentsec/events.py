"""Build closed AgentSec security events. Callers never copy attacker JSON into control fields."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from agentsec.schema import validate_event
from agentsec.settings import get_settings

CONTENT_PREVIEW_MAX = 200


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_trace_id() -> str:
    return secrets.token_hex(16)


def new_span_id() -> str:
    return secrets.token_hex(8)


def content_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def content_preview(text: str) -> str:
    cleaned = text.replace("\r", " ").replace("\n", " ").strip()
    return cleaned[:CONTENT_PREVIEW_MAX]


@dataclass
class RunContext:
    run_id: UUID
    trace_id: str
    user_id: str
    testbed_mode: str
    conversation_id: str
    technique_id: str | None = None
    incident_id: str | None = None
    parent_span_id: str | None = None
    last_span_id: str | None = None
    last_agent_id: str | None = None
    last_agent_name: str | None = None

    @classmethod
    def mint(
        cls,
        *,
        user_id: str,
        testbed_mode: str,
        technique_id: str | None = None,
    ) -> "RunContext":
        run_id = uuid4()
        incident = None
        if testbed_mode == "LIVE" and technique_id:
            incident = f"INC-{run_id.hex[:8]}"
        return cls(
            run_id=run_id,
            trace_id=new_trace_id(),
            user_id=user_id,
            testbed_mode=testbed_mode,
            conversation_id=str(uuid4()),
            technique_id=technique_id,
            incident_id=incident,
        )


@dataclass
class EventBuilder:
    ctx: RunContext
    settings: Any = field(default_factory=get_settings)

    def build(
        self,
        *,
        event_name: str,
        agent_id: str,
        agent_name: str,
        agent_description: str,
        operation_name: str,
        trust_boundary: str,
        invariant_ids: list[str],
        control_id: str,
        decision: str,
        reason: str,
        operation_executed: bool,
        span_id: str,
        agent_role: str | None = None,
        parent_span_id: str | None = None,
        scope_requested: str | None = None,
        scope_allowed: str | None = None,
        influence_kind: str | None = None,
        origin_type: str | None = None,
        origin_id: str | None = None,
        content_text: str | None = None,
        delegator_agent_id: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        response_model: str | None = None,
        error_type: str | None = None,
    ) -> dict:
        event: dict[str, Any] = {
            "event.name": event_name,
            "timestamp": utc_now(),
            "service.name": self.settings.service_name,
            "service.version": self.settings.version,
            "deployment.environment": self.settings.deployment_environment,
            "user.id": self.ctx.user_id,
            "trace_id": self.ctx.trace_id,
            "span_id": span_id,
            "gen_ai.provider.name": "ollama",
            "gen_ai.request.model": self.settings.ollama_model,
            "gen_ai.operation.name": operation_name,
            "gen_ai.agent.id": agent_id,
            "gen_ai.agent.name": agent_name,
            "gen_ai.agent.description": agent_description,
            "gen_ai.conversation.id": self.ctx.conversation_id,
            "gen_ai.workflow.name": "loan_pipeline",
            "agentsec.run.id": str(self.ctx.run_id),
            "agentsec.lab.id": self.settings.lab_id,
            "agentsec.security.profile": self.settings.security_profile,
            "agentsec.testbed.mode": self.ctx.testbed_mode,
            "agentsec.principal.id": self.ctx.user_id,
            "agentsec.principal.type": "user",
            "agentsec.trust_boundary": trust_boundary,
            "agentsec.invariant.id": invariant_ids,
            "agentsec.control.id": control_id,
            "agentsec.control.decision": decision,
            "agentsec.control.reason": reason,
            "agentsec.operation.executed": operation_executed,
        }
        if agent_role:
            event["agentsec.agent.role"] = agent_role
        if parent_span_id:
            event["parent_span_id"] = parent_span_id
        if self.ctx.incident_id:
            event["agentsec.incident.id"] = self.ctx.incident_id
        if self.ctx.technique_id:
            event["agentsec.technique.id"] = self.ctx.technique_id
        if scope_requested is not None:
            event["agentsec.scope.requested"] = scope_requested
        if scope_allowed is not None:
            event["agentsec.scope.allowed"] = scope_allowed
        if influence_kind:
            event["agentsec.content.influence.kind"] = influence_kind
        if origin_type:
            event["agentsec.content.origin.type"] = origin_type
        if origin_id:
            event["agentsec.content.origin.id"] = origin_id
        if content_text is not None:
            event["agentsec.content.preview"] = content_preview(content_text)
            event["agentsec.content.hash"] = content_hash(content_text)
        if delegator_agent_id:
            event["agentsec.delegator.agent.id"] = delegator_agent_id
        if input_tokens is not None:
            event["gen_ai.usage.input_tokens"] = input_tokens
        if output_tokens is not None:
            event["gen_ai.usage.output_tokens"] = output_tokens
        if response_model:
            event["gen_ai.response.model"] = response_model
        if error_type:
            event["error.type"] = error_type
        if decision == "DENY":
            event["agentsec.operation.executed"] = False

        validate_event(event)
        return event
