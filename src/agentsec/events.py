"""Build schema 1.9.0 AgentSec security events. Attackers never copy JSON into control fields."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import UUID, uuid4

from agentsec.experiment import (
    EXECUTION_MODE,
    LOAN_WORKFLOW_ENTRY,
    LOAN_WORKFLOW_NAME,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    TELEMETRY_FIDELITY,
    technique_id_for,
)
from agentsec.schema import validate_event
from agentsec.settings import Settings, get_settings

CONTENT_PREVIEW_MAX = 200

EVENT_RUN_STARTED = "agentsec.run.started"
EVENT_RUN_COMPLETED = "agentsec.run.completed"
EVENT_RUN_FAILED = "agentsec.run.failed"
EVENT_HOP_STARTED = "agentsec.hop.started"
EVENT_HOP_COMPLETED = "agentsec.hop.completed"
EVENT_CONTROL_DECISION = "agentsec.control.decision"
EVENT_LLM_STARTED = "agentsec.llm.started"
EVENT_LLM_COMPLETED = "agentsec.llm.completed"
EVENT_LLM_FAILED = "agentsec.llm.failed"
EVENT_MCP_STARTED = "agentsec.mcp.started"
EVENT_MCP_COMPLETED = "agentsec.mcp.completed"
EVENT_MCP_FAILED = "agentsec.mcp.failed"
EVENT_PIPELINE_STOPPED = "agentsec.pipeline.stopped"
EVENT_MEMORY_WRITTEN = "agentsec.memory.written"
EVENT_MEMORY_RECALLED = "agentsec.memory.recalled"

# Closed 1.9.0 enum. Unknown catalog ids (RAG-BASELINE, CAPSTONE-001, …) are omitted,
# not invented into a schema bump.
SCHEMA_ATTACK_IDS = frozenset(
    {
        "ATK-001",
        "ATK-002",
        "MCP-001",
        "MCP-002",
        "MCP-003",
        "MCP-004",
        "MCP-005",
        "MCP-006",
        "MCP-CATALOG-001",
        "RAG-001",
        "MEMORY-001",
        "A2A-001",
        "GOAL-001",
    }
)


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
    incident_id: str
    trace_id: str
    pipeline_span_id: str
    user_id: str
    testbed_mode: str
    attack_id: str
    technique_id: str | None = None
    sequence: int = 0
    last_agent_id: str | None = None
    last_agent_name: str | None = None
    last_hop_span_id: str | None = None
    workflow_entry: str = LOAN_WORKFLOW_ENTRY
    workflow_name: str = LOAN_WORKFLOW_NAME

    @classmethod
    def mint(
        cls,
        *,
        user_id: str,
        testbed_mode: str,
        attack_id: str,
        workflow_entry: str = LOAN_WORKFLOW_ENTRY,
        workflow_name: str = LOAN_WORKFLOW_NAME,
    ) -> "RunContext":
        run_id = uuid4()
        return cls(
            run_id=run_id,
            incident_id=str(run_id),
            trace_id=new_trace_id(),
            pipeline_span_id=new_span_id(),
            user_id=user_id,
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            technique_id=technique_id_for(attack_id),
            workflow_entry=workflow_entry,
            workflow_name=workflow_name,
        )

    def next_sequence(self) -> int:
        self.sequence += 1
        return self.sequence


def _base_event(ctx: RunContext, settings: Settings, span_id: str) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": utc_now(),
        "service.name": settings.service_name,
        "service.version": settings.version,
        "deployment.environment": settings.deployment_environment,
        "user.id": ctx.user_id,
        "trace_id": ctx.trace_id,
        "span_id": span_id,
        "agentsec.schema.name": SCHEMA_NAME,
        "agentsec.schema.version": SCHEMA_VERSION,
        "agentsec.run.id": str(ctx.run_id),
        "agentsec.incident.id": ctx.incident_id,
        "agentsec.lab.id": settings.lab_id,
        "agentsec.security.profile": settings.security_profile,
        "agentsec.testbed.mode": ctx.testbed_mode,
        "agentsec.execution.mode": EXECUTION_MODE,
        "agentsec.telemetry.fidelity": TELEMETRY_FIDELITY,
        "agentsec.sequence": ctx.next_sequence(),
        "agentsec.principal.id": ctx.user_id,
        "agentsec.principal.type": "user",
        "agentsec.workflow.entry": ctx.workflow_entry,
        "gen_ai.workflow.name": ctx.workflow_name,
    }
    if ctx.attack_id in SCHEMA_ATTACK_IDS:
        event["agentsec.attack.id"] = ctx.attack_id
    if ctx.technique_id:
        event["agentsec.technique.id"] = ctx.technique_id
    return event


def _with_hop_identity(
    event: dict[str, Any],
    *,
    hop_index: int,
    agent_id: str,
    agent_name: str | None = None,
    delegator_agent_id: str | None = None,
) -> None:
    event["agentsec.hop.index"] = hop_index
    event["gen_ai.agent.id"] = agent_id
    if agent_name:
        event["gen_ai.agent.name"] = agent_name
    if hop_index >= 1:
        if not delegator_agent_id:
            raise ValueError("hop.index >= 1 requires delegator.agent.id")
        event["agentsec.delegator.agent.id"] = delegator_agent_id


@dataclass
class EventEmitter:
    ctx: RunContext
    sink: Callable[[dict], None]
    settings: Settings = field(default_factory=get_settings)

    def _emit(self, event: dict[str, Any]) -> dict[str, Any]:
        validate_event(event)
        self.sink(event)
        return event

    def run_started(self) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, self.ctx.pipeline_span_id)
        event["event.name"] = EVENT_RUN_STARTED
        event["agentsec.operation.type"] = "pipeline"
        event["agentsec.span.kind"] = "pipeline"
        event["agentsec.trust_boundary"] = "acmebank.http_api"
        return self._emit(event)

    def run_completed(self, *, outcome: str, duration_ms: int) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, self.ctx.pipeline_span_id)
        event["event.name"] = EVENT_RUN_COMPLETED
        event["agentsec.operation.type"] = "pipeline"
        event["agentsec.span.kind"] = "pipeline"
        event["agentsec.outcome"] = outcome
        event["agentsec.duration_ms"] = duration_ms
        return self._emit(event)

    def run_failed(self, *, error_type: str, error_stage: str, error_message: str) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, self.ctx.pipeline_span_id)
        event["event.name"] = EVENT_RUN_FAILED
        event["agentsec.operation.type"] = "pipeline"
        event["agentsec.span.kind"] = "pipeline"
        event["error.type"] = error_type
        event["agentsec.error.stage"] = error_stage
        event["agentsec.error.message"] = error_message[:500]
        return self._emit(event)

    def hop_started(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, hop_span_id)
        event["event.name"] = EVENT_HOP_STARTED
        event["parent_span_id"] = self.ctx.pipeline_span_id
        event["agentsec.operation.type"] = "agent_hop"
        event["agentsec.span.kind"] = "hop"
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def hop_completed(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        outcome: str,
        duration_ms: int,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, hop_span_id)
        event["event.name"] = EVENT_HOP_COMPLETED
        event["parent_span_id"] = self.ctx.pipeline_span_id
        event["agentsec.operation.type"] = "agent_hop"
        event["agentsec.span.kind"] = "hop"
        event["agentsec.outcome"] = outcome
        event["agentsec.duration_ms"] = duration_ms
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def control_decision(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        control_id: str,
        control_type: str,
        decision: str,
        reason: str,
        trust_boundary: str,
        invariant_ids: list[str],
        content_text: str,
        origin_type: str,
        origin_id: str,
        influence_kind: str,
        delegator_agent_id: str | None,
        error_stage: str | None = None,
        tool_name: str | None = None,
        mcp_method: str | None = None,
        requested_scope: str | None = None,
        allowed_scope: str | None = None,
        resource_id: str | None = None,
        allowed_resource_ids: str | None = None,
        authority_source: str | None = None,
        metadata_trust: str | None = None,
        metadata_provenance: str | None = None,
        rag_context_trust: str | None = None,
        rag_context_provenance: str | None = None,
        rag_document_id: str | None = None,
        memory_id: str | None = None,
        memory_trust: str | None = None,
        memory_provenance: str | None = None,
        memory_source_run_id: str | None = None,
        identity_caller_agent_id: str | None = None,
        identity_callee_agent_id: str | None = None,
        identity_claim_trust: str | None = None,
        claimed_scope: str | None = None,
        task_id: str | None = None,
        task_hash: str | None = None,
        task_preview: str | None = None,
        task_provenance: str | None = None,
        instruction_trust: str | None = None,
        instruction_provenance: str | None = None,
        goal_proposed: str | None = None,
        goal_decision: str | None = None,
        goal_reason: str | None = None,
    ) -> dict[str, Any]:
        span_id = new_span_id()
        event = _base_event(self.ctx, self.settings, span_id)
        event["event.name"] = EVENT_CONTROL_DECISION
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "control_evaluation"
        event["agentsec.span.kind"] = "control_evaluation"
        event["agentsec.control.id"] = control_id
        event["agentsec.control.type"] = control_type
        event["agentsec.control.decision"] = decision
        event["agentsec.control.reason"] = reason
        event["agentsec.trust_boundary"] = trust_boundary
        event["agentsec.invariant.id"] = invariant_ids
        event["agentsec.operation.attempted"] = False
        event["agentsec.operation.executed"] = False
        if decision in ("DENY", "ERROR"):
            event["agentsec.operation.outcome"] = "prevented"
        event["agentsec.content.preview"] = content_preview(content_text)
        event["agentsec.content.hash"] = content_hash(content_text)
        event["agentsec.content.origin.type"] = origin_type
        event["agentsec.content.origin.id"] = origin_id
        event["agentsec.content.influence.kind"] = influence_kind
        if error_stage:
            event["agentsec.error.stage"] = error_stage
        if tool_name is not None:
            event["gen_ai.tool.name"] = tool_name
        if mcp_method is not None:
            event["mcp.method.name"] = mcp_method
        if requested_scope is not None:
            event["agentsec.mcp.requested_scope"] = requested_scope
        if allowed_scope is not None:
            event["agentsec.mcp.allowed_scope"] = allowed_scope
        if resource_id is not None:
            event["agentsec.mcp.resource.id"] = resource_id
        if allowed_resource_ids is not None:
            event["agentsec.mcp.allowed_resource.ids"] = allowed_resource_ids
        if authority_source is not None:
            event["agentsec.delegation.authority.source"] = authority_source
        if metadata_trust is not None:
            event["agentsec.mcp.metadata.trust"] = metadata_trust
        if metadata_provenance is not None:
            event["agentsec.mcp.metadata.provenance"] = metadata_provenance
        if rag_context_trust is not None:
            event["agentsec.rag.context.trust"] = rag_context_trust
        if rag_context_provenance is not None:
            event["agentsec.rag.context.provenance"] = rag_context_provenance
        if rag_document_id is not None:
            event["agentsec.rag.context.document.id"] = rag_document_id
        if memory_id is not None:
            event["agentsec.memory.id"] = memory_id
        if memory_trust is not None:
            event["agentsec.memory.trust"] = memory_trust
        if memory_provenance is not None:
            event["agentsec.memory.provenance"] = memory_provenance
        if memory_source_run_id is not None:
            event["agentsec.memory.source_run_id"] = memory_source_run_id
        if identity_caller_agent_id is not None:
            event["agentsec.identity.caller_agent_id"] = identity_caller_agent_id
        if identity_callee_agent_id is not None:
            event["agentsec.identity.callee_agent_id"] = identity_callee_agent_id
        if identity_claim_trust is not None:
            event["agentsec.identity.claim.trust"] = identity_claim_trust
        if claimed_scope is not None:
            event["agentsec.delegation.claimed_scope"] = claimed_scope
        if task_id is not None:
            event["agentsec.task.id"] = task_id
        if task_hash is not None:
            event["agentsec.task.hash"] = task_hash
        if task_preview is not None:
            event["agentsec.task.preview"] = task_preview
        if task_provenance is not None:
            event["agentsec.task.provenance"] = task_provenance
        if instruction_trust is not None:
            event["agentsec.instruction.trust"] = instruction_trust
        if instruction_provenance is not None:
            event["agentsec.instruction.provenance"] = instruction_provenance
        if goal_proposed is not None:
            event["agentsec.goal.proposed"] = goal_proposed
        if goal_decision is not None:
            event["agentsec.goal.decision"] = goal_decision
        if goal_reason is not None:
            event["agentsec.goal.reason"] = goal_reason
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def llm_started(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        llm_span_id: str,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, llm_span_id)
        event["event.name"] = EVENT_LLM_STARTED
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "llm_inference"
        event["agentsec.span.kind"] = "llm_inference"
        event["gen_ai.operation.name"] = "chat"
        event["gen_ai.provider.name"] = "ollama"
        event["gen_ai.request.model"] = self.settings.ollama_model
        event["agentsec.operation.attempted"] = True
        event["agentsec.operation.executed"] = True
        event["agentsec.trust_boundary"] = "acmebank.llm_call"
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def llm_completed(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        llm_span_id: str,
        duration_ms: int,
        input_tokens: int,
        output_tokens: int,
        response_model: str,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, llm_span_id)
        event["event.name"] = EVENT_LLM_COMPLETED
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "llm_inference"
        event["agentsec.span.kind"] = "llm_inference"
        event["gen_ai.operation.name"] = "chat"
        event["gen_ai.provider.name"] = "ollama"
        event["gen_ai.request.model"] = self.settings.ollama_model
        event["gen_ai.response.model"] = response_model
        event["gen_ai.usage.input_tokens"] = input_tokens
        event["gen_ai.usage.output_tokens"] = output_tokens
        event["agentsec.operation.attempted"] = True
        event["agentsec.operation.executed"] = True
        event["agentsec.operation.outcome"] = "success"
        event["agentsec.duration_ms"] = duration_ms
        event["agentsec.trust_boundary"] = "acmebank.llm_call"
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def llm_failed(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        llm_span_id: str,
        error_type: str,
        error_message: str,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, llm_span_id)
        event["event.name"] = EVENT_LLM_FAILED
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "llm_inference"
        event["agentsec.span.kind"] = "llm_inference"
        event["gen_ai.operation.name"] = "chat"
        event["gen_ai.provider.name"] = "ollama"
        event["gen_ai.request.model"] = self.settings.ollama_model
        event["agentsec.operation.attempted"] = True
        event["agentsec.operation.executed"] = True
        event["agentsec.operation.outcome"] = "error"
        event["error.type"] = error_type
        event["agentsec.error.stage"] = "llm_invocation"
        event["agentsec.error.message"] = error_message[:500]
        event["agentsec.trust_boundary"] = "acmebank.llm_call"
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def mcp_started(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        mcp_span_id: str,
        tool_name: str,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, mcp_span_id)
        event["event.name"] = EVENT_MCP_STARTED
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "mcp_tool_invoke"
        event["agentsec.span.kind"] = "mcp_tool_invoke"
        event["gen_ai.operation.name"] = "execute_tool"
        event["gen_ai.tool.name"] = tool_name
        event["mcp.method.name"] = "tools/call"
        event["agentsec.operation.attempted"] = True
        event["agentsec.operation.executed"] = True
        event["agentsec.trust_boundary"] = "mcp.tool.execute"
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def mcp_completed(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        mcp_span_id: str,
        tool_name: str,
        duration_ms: int,
        result_text: str,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, mcp_span_id)
        event["event.name"] = EVENT_MCP_COMPLETED
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "mcp_tool_invoke"
        event["agentsec.span.kind"] = "mcp_tool_invoke"
        event["gen_ai.operation.name"] = "execute_tool"
        event["gen_ai.tool.name"] = tool_name
        event["mcp.method.name"] = "tools/call"
        event["agentsec.operation.attempted"] = True
        event["agentsec.operation.executed"] = True
        event["agentsec.operation.outcome"] = "success"
        event["agentsec.duration_ms"] = duration_ms
        event["agentsec.trust_boundary"] = "mcp.tool.result"
        event["agentsec.mcp.result.trust"] = "untrusted_data"
        event["agentsec.mcp.result.provenance"] = "mcp.tool.handler"
        event["agentsec.content.preview"] = content_preview(result_text)
        event["agentsec.content.hash"] = content_hash(result_text)
        event["agentsec.content.origin.type"] = "agent"
        event["agentsec.content.origin.id"] = agent_id
        event["agentsec.content.influence.kind"] = "tool_request"
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def mcp_failed(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        mcp_span_id: str,
        tool_name: str,
        error_type: str,
        error_message: str,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, mcp_span_id)
        event["event.name"] = EVENT_MCP_FAILED
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "mcp_tool_invoke"
        event["agentsec.span.kind"] = "mcp_tool_invoke"
        event["gen_ai.operation.name"] = "execute_tool"
        event["gen_ai.tool.name"] = tool_name
        event["mcp.method.name"] = "tools/call"
        event["agentsec.operation.attempted"] = True
        event["agentsec.operation.executed"] = True
        event["agentsec.operation.outcome"] = "error"
        event["error.type"] = error_type
        event["agentsec.error.stage"] = "mcp_invocation"
        event["agentsec.error.message"] = error_message[:500]
        event["agentsec.trust_boundary"] = "mcp.tool.execute"
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def pipeline_stopped(
        self,
        *,
        hop_index: int,
        agent_id: str,
        stop_reason: str,
        delegator_agent_id: str | None,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, new_span_id())
        event["event.name"] = EVENT_PIPELINE_STOPPED
        event["parent_span_id"] = self.ctx.pipeline_span_id
        event["agentsec.operation.type"] = "pipeline_stop"
        event["agentsec.span.kind"] = "pipeline"
        event["agentsec.stop.reason"] = stop_reason
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            delegator_agent_id=delegator_agent_id,
        )
        return self._emit(event)

    def memory_written(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        memory_id: str,
        provenance: str,
        source_run_id: str,
        content_text: str,
        writer_agent_id: str,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, new_span_id())
        event["event.name"] = EVENT_MEMORY_WRITTEN
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "agent_hop"
        event["agentsec.span.kind"] = "hop"
        event["agentsec.trust_boundary"] = "agent.memory.store"
        event["agentsec.memory.id"] = memory_id
        event["agentsec.memory.provenance"] = provenance
        event["agentsec.memory.source_run_id"] = source_run_id
        event["agentsec.content.hash"] = content_hash(content_text)
        event["agentsec.content.preview"] = content_preview(content_text)
        event["agentsec.content.origin.type"] = "agent"
        event["agentsec.content.origin.id"] = writer_agent_id
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=None,
        )
        return self._emit(event)

    def memory_recalled(
        self,
        *,
        hop_index: int,
        agent_id: str,
        agent_name: str,
        hop_span_id: str,
        memory_id: str,
        provenance: str,
        trust: str,
        source_run_id: str,
        content_text: str,
        reader_agent_id: str,
    ) -> dict[str, Any]:
        event = _base_event(self.ctx, self.settings, new_span_id())
        event["event.name"] = EVENT_MEMORY_RECALLED
        event["parent_span_id"] = hop_span_id
        event["agentsec.operation.type"] = "agent_hop"
        event["agentsec.span.kind"] = "hop"
        event["agentsec.trust_boundary"] = "agent.memory.store"
        event["agentsec.memory.id"] = memory_id
        event["agentsec.memory.provenance"] = provenance
        event["agentsec.memory.trust"] = trust
        event["agentsec.memory.source_run_id"] = source_run_id
        event["agentsec.content.hash"] = content_hash(content_text)
        event["agentsec.content.preview"] = content_preview(content_text)
        event["agentsec.content.origin.type"] = "agent"
        event["agentsec.content.origin.id"] = reader_agent_id
        event["agentsec.content.influence.kind"] = "recalled_memory"
        _with_hop_identity(
            event,
            hop_index=hop_index,
            agent_id=agent_id,
            agent_name=agent_name,
            delegator_agent_id=None,
        )
        return self._emit(event)
