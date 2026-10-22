"""Loan Desk event emitter (schemas/loan_desk_event.schema.json). Every event is validated before it is sunk."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from uuid import UUID, uuid4

from agentsec.events import content_hash, content_preview, new_span_id, new_trace_id, utc_now
from agentsec.schema import validate_event
from agentsec.settings import Settings

AGENT_ID = "acme-agent-loandesk-001"
AGENT_NAME = "Loan Desk Agent"
CONTROL_ID = "CTRL-LOANDESK-001"
WORKFLOW_ENTRY = "/api/v1/loan-desk/applications"


@dataclass
class LoanDeskEmitter:
    sink: Callable[[dict], None]
    settings: Settings
    model: str
    user_id: str
    run_id: UUID = field(default_factory=uuid4)
    trace_id: str = field(default_factory=new_trace_id)
    run_span: str = field(default_factory=new_span_id)
    seq: int = 0
    events: list[dict] = field(default_factory=list)

    def _base(self, name: str, op: str, span: str, step: int | None = None) -> dict[str, Any]:
        self.seq += 1
        e: dict[str, Any] = {
            "event.name": name, "timestamp": utc_now(), "service.name": self.settings.service_name,
            "service.version": self.settings.version, "deployment.environment": self.settings.deployment_environment,
            "user.id": self.user_id, "trace_id": self.trace_id, "span_id": span,
            "agentsec.schema.name": "agentsec.loan_desk_event", "agentsec.schema.version": "1.0.0",
            "agentsec.run.id": str(self.run_id), "agentsec.incident.id": str(self.run_id),
            "agentsec.lab.id": self.settings.lab_id, "agentsec.security.profile": self.settings.security_profile,
            "agentsec.testbed.mode": "BASELINE", "agentsec.execution.mode": "LIVE",
            "agentsec.telemetry.fidelity": "OBSERVED", "agentsec.sequence": self.seq,
            "agentsec.operation.type": op, "agentsec.span.kind": op,
            "agentsec.principal.id": self.user_id, "agentsec.principal.type": "user",
            "agentsec.workflow.entry": WORKFLOW_ENTRY, "gen_ai.workflow.name": "loan_desk_agent",
        }
        if span != self.run_span:
            e["parent_span_id"] = self.run_span
        if step is not None:
            e["gen_ai.agent.id"], e["gen_ai.agent.name"], e["agentsec.agent.step"] = AGENT_ID, AGENT_NAME, step
        return e

    def _emit(self, e: dict) -> dict:
        validate_event(e)
        self.sink(e)
        self.events.append(e)
        return e

    def run_started(self):
        e = self._base("agentsec.run.started", "pipeline", self.run_span)
        e["agentsec.trust_boundary"] = "acmebank.http_api"
        return self._emit(e)

    def run_completed(self, *, outcome, duration_ms, stop_reason, executed, denied):
        e = self._base("agentsec.run.completed", "pipeline", self.run_span)
        e.update({"agentsec.outcome": outcome, "agentsec.duration_ms": duration_ms,
                  "agentsec.agent.stop_reason": stop_reason, "agentsec.tools.executed": executed,
                  "agentsec.tools.denied": denied})
        return self._emit(e)

    def run_failed(self, *, error_type, message, stop_reason):
        e = self._base("agentsec.run.failed", "pipeline", self.run_span)
        e.update({"error.type": error_type, "agentsec.error.stage": "pipeline",
                  "agentsec.error.message": message[:500], "agentsec.agent.stop_reason": stop_reason})
        return self._emit(e)

    def llm_started(self, step: int) -> str:
        span = new_span_id()
        e = self._base("agentsec.llm.started", "llm_inference", span, step)
        e.update({"gen_ai.operation.name": "chat", "gen_ai.provider.name": "ollama", "gen_ai.request.model": self.model,
                  "agentsec.operation.attempted": True, "agentsec.operation.executed": True,
                  "agentsec.trust_boundary": "acmebank.llm_call"})
        self._emit(e)
        return span

    def llm_completed(self, step, span, *, duration_ms, tokens_in, tokens_out, response_model):
        e = self._base("agentsec.llm.completed", "llm_inference", span, step)
        e.update({"gen_ai.operation.name": "chat", "gen_ai.provider.name": "ollama", "gen_ai.request.model": self.model,
                  "gen_ai.response.model": response_model or self.model, "gen_ai.usage.input_tokens": tokens_in,
                  "gen_ai.usage.output_tokens": tokens_out, "agentsec.operation.attempted": True,
                  "agentsec.operation.executed": True, "agentsec.operation.outcome": "success",
                  "agentsec.duration_ms": duration_ms, "agentsec.trust_boundary": "acmebank.llm_call"})
        return self._emit(e)

    def llm_failed(self, step, span, *, error_type, message):
        e = self._base("agentsec.llm.failed", "llm_inference", span, step)
        e.update({"gen_ai.operation.name": "chat", "gen_ai.provider.name": "ollama", "gen_ai.request.model": self.model,
                  "agentsec.operation.attempted": True, "agentsec.operation.executed": True,
                  "agentsec.operation.outcome": "error", "error.type": error_type,
                  "agentsec.error.stage": "llm_invocation", "agentsec.error.message": message[:500],
                  "agentsec.trust_boundary": "acmebank.llm_call"})
        return self._emit(e)

    def proposed(self, step, *, tool, content, source):
        e = self._base("agentsec.agent.action.proposed", "agent_action_proposal", new_span_id(), step)
        e.update({"gen_ai.tool.name": tool, "agentsec.agent.proposal.source": source,
                  "agentsec.content.hash": content_hash(content), "agentsec.content.preview": content_preview(content),
                  "agentsec.content.origin.type": "agent", "agentsec.content.origin.id": AGENT_ID,
                  "agentsec.content.influence.kind": "tool_request",
                  "agentsec.operation.attempted": False, "agentsec.operation.executed": False,
                  "agentsec.trust_boundary": "agent.action.proposal"})
        return self._emit(e)

    def decision(self, step, *, tool, decision, reason, requested_scope, allowed_scope, resource_id, allowed_resources, content):
        e = self._base("agentsec.control.decision", "control_evaluation", new_span_id(), step)
        e.update({"agentsec.control.id": CONTROL_ID, "agentsec.control.type": "agent_action_authorization",
                  "agentsec.control.decision": decision, "agentsec.control.reason": reason,
                  "gen_ai.tool.name": tool, "mcp.method.name": "tools/call",
                  "agentsec.mcp.requested_scope": requested_scope, "agentsec.mcp.allowed_scope": allowed_scope,
                  "agentsec.mcp.allowed_resource.ids": allowed_resources,
                  "agentsec.invariant.id": ["INV-001", "INV-008", "INV-007"] if decision == "DENY" else ["INV-001", "INV-004", "INV-007"],
                  "agentsec.trust_boundary": "acmebank.mcp.authorize",
                  "agentsec.operation.attempted": False, "agentsec.operation.executed": False,
                  "agentsec.content.preview": content_preview(content), "agentsec.content.hash": content_hash(content),
                  "agentsec.content.origin.type": "agent", "agentsec.content.origin.id": AGENT_ID,
                  "agentsec.content.influence.kind": "tool_request"})
        if resource_id:
            e["agentsec.mcp.resource.id"] = resource_id
        if decision == "DENY":
            e["agentsec.operation.outcome"] = "prevented"
        return self._emit(e)

    def mcp_started(self, step, tool) -> str:
        span = new_span_id()
        e = self._base("agentsec.mcp.started", "mcp_tool_invoke", span, step)
        e.update({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool, "mcp.method.name": "tools/call",
                  "agentsec.operation.attempted": True, "agentsec.operation.executed": True,
                  "agentsec.trust_boundary": "mcp.tool.execute"})
        self._emit(e)
        return span

    def mcp_completed(self, step, span, tool, *, duration_ms, result_text):
        e = self._base("agentsec.mcp.completed", "mcp_tool_invoke", span, step)
        e.update({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool, "mcp.method.name": "tools/call",
                  "agentsec.operation.attempted": True, "agentsec.operation.executed": True,
                  "agentsec.operation.outcome": "success", "agentsec.duration_ms": duration_ms,
                  "agentsec.trust_boundary": "mcp.tool.result", "agentsec.mcp.result.trust": "untrusted_data",
                  "agentsec.mcp.result.provenance": "mcp.tool.handler",
                  "agentsec.content.preview": content_preview(result_text), "agentsec.content.hash": content_hash(result_text),
                  "agentsec.content.origin.type": "agent", "agentsec.content.origin.id": AGENT_ID,
                  "agentsec.content.influence.kind": "tool_request"})
        return self._emit(e)

    def mcp_failed(self, step, span, tool, *, error_type, message):
        e = self._base("agentsec.mcp.failed", "mcp_tool_invoke", span, step)
        e.update({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool, "mcp.method.name": "tools/call",
                  "agentsec.operation.attempted": True, "agentsec.operation.executed": True,
                  "agentsec.operation.outcome": "error", "error.type": error_type,
                  "agentsec.error.stage": "mcp_invocation", "agentsec.error.message": message[:500],
                  "agentsec.trust_boundary": "mcp.tool.execute"})
        return self._emit(e)
