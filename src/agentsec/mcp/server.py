"""In-process MCP server. Authorization is authoritative and runs before the handler."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from agentsec.mcp.authorize import McpControlResult, authorize_resource, evaluate_mcp_control
from agentsec.mcp.metadata_trust import MetadataDerivedOverlay
from agentsec.mcp.policy import McpPolicy, coded_policy
from agentsec.mcp.protocol import ToolsCallRequest, decode_tools_call
from agentsec.mcp.registry import ToolRegistry, default_registry
from agentsec.mcp.result_trust import ResultDerivedOverlay
from agentsec.mcp.tools import ToolSpec
from agentsec.rag.context_trust import ContextDerivedOverlay

AuthorizeFn = Callable[..., McpControlResult]


@dataclass(frozen=True)
class AllowTicket:
    """Opaque capability minted only after ALLOW. Cannot be supplied by HTTP."""

    tool_name: str
    arguments: dict[str, Any]
    request_id: int | str
    token: str
    resource_id: str | None = None


@dataclass
class ServerDecision:
    control: McpControlResult
    ticket: AllowTicket | None
    rpc_error: str | None = None
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    request_id: int | str = 1


@dataclass
class ServerExecution:
    ok: bool
    began: bool
    payload: dict[str, Any] | None
    error_type: str | None = None
    error_message: str | None = None


class McpServer:
    def __init__(
        self,
        *,
        registry: ToolRegistry | None = None,
        policy: McpPolicy | None = None,
        authorize_fn: AuthorizeFn | None = None,
    ) -> None:
        self.registry = registry or default_registry()
        self.policy = policy or coded_policy()
        self._authorize_fn = authorize_fn
        self._tickets: dict[str, AllowTicket] = {}
        self.result_derived_overlay: ResultDerivedOverlay | None = None
        self.metadata_derived_overlay: MetadataDerivedOverlay | None = None
        self.context_derived_overlay: ContextDerivedOverlay | None = None

    def authorize(
        self,
        rpc_message: object,
        *,
        profile: str,
        requested_scope: str,
        coded_agent_id: str,
        result_derived_overlay: ResultDerivedOverlay | None = None,
        metadata_derived_overlay: MetadataDerivedOverlay | None = None,
        context_derived_overlay: ContextDerivedOverlay | None = None,
    ) -> ServerDecision:
        """Resolve coded policy, validate tool/scope/args/resource, then decide. Never starts a handler."""
        del coded_agent_id  # identity is policy.agent_id; parameter documents the trust rule
        overlay = result_derived_overlay if result_derived_overlay is not None else self.result_derived_overlay
        meta_overlay = (
            metadata_derived_overlay
            if metadata_derived_overlay is not None
            else self.metadata_derived_overlay
        )
        ctx_overlay = (
            context_derived_overlay
            if context_derived_overlay is not None
            else self.context_derived_overlay
        )
        parsed, rpc_error = decode_tools_call(rpc_message)
        if parsed is None:
            stage = "argument_validation" if rpc_error == "malformed_arguments" else "schema_validation"
            dummy_name = "unknown"
            dummy_scope = requested_scope if requested_scope.strip() else "unspecified"
            control = evaluate_mcp_control(
                tool_name=dummy_name,
                requested_scope=dummy_scope,
                profile=profile,
                policy=self.policy,
                tool_registered=False,
                authorize_fn=self._authorize_or_default,
                result_derived_overlay=overlay,
                metadata_derived_overlay=meta_overlay,
                context_derived_overlay=ctx_overlay,
            )
            # RPC envelope failures are ERROR even if authorize_fn would ALLOW an unknown name.
            control = McpControlResult(
                control_id=control.control_id,
                control_type=control.control_type,
                decision="ERROR",
                reason=rpc_error or "malformed_rpc",
                profile=profile,
                tool_name=dummy_name,
                requested_scope=dummy_scope,
                allowed_scope=self.policy.allowed_scope_wire(),
                error_stage=stage,
            )
            return ServerDecision(control=control, ticket=None, rpc_error=rpc_error, tool_name=dummy_name)

        tool_name = parsed.name
        arguments = dict(parsed.arguments)
        # Exact token. Do not strip or lowercase: whitespace/case change meaning.
        if not isinstance(requested_scope, str) or not requested_scope.strip():
            control = McpControlResult(
                control_id="CTRL-MCP-001",
                control_type="mcp_allowlist",
                decision="ERROR",
                reason="missing_requested_scope",
                profile=profile,
                tool_name=tool_name,
                requested_scope="unspecified",
                allowed_scope=self.policy.allowed_scope_wire(),
                error_stage="argument_validation",
            )
            return ServerDecision(
                control=control,
                ticket=None,
                tool_name=tool_name,
                arguments=arguments,
                request_id=parsed.id,
            )
        scope = requested_scope

        registered = self.registry.known(tool_name)
        if not registered:
            control = evaluate_mcp_control(
                tool_name=tool_name,
                requested_scope=scope,
                profile=profile,
                policy=self.policy,
                tool_registered=False,
                valid_scopes=frozenset(),
                authorize_fn=self._authorize_or_default,
                result_derived_overlay=overlay,
                metadata_derived_overlay=meta_overlay,
                context_derived_overlay=ctx_overlay,
            )
            return ServerDecision(
                control=control,
                ticket=None,
                tool_name=tool_name,
                arguments=arguments,
                request_id=parsed.id,
            )

        spec = self.registry.spec(tool_name)
        control = evaluate_mcp_control(
            tool_name=tool_name,
            requested_scope=scope,
            profile=profile,
            policy=self.policy,
            tool_registered=True,
            valid_scopes=spec.valid_scopes,
            authorize_fn=self._authorize_or_default,
            result_derived_overlay=overlay,
            metadata_derived_overlay=meta_overlay,
            context_derived_overlay=ctx_overlay,
        )
        if control.blocks_tool:
            return ServerDecision(
                control=_attach_resource_telemetry(control, spec, arguments, self.policy),
                ticket=None,
                tool_name=tool_name,
                arguments=arguments,
                request_id=parsed.id,
            )

        arg_error = _argument_error(spec.required_keys, arguments)
        if arg_error:
            control = McpControlResult(
                control_id="CTRL-MCP-001",
                control_type="mcp_allowlist",
                decision="ERROR",
                reason=arg_error,
                profile=profile,
                tool_name=tool_name,
                requested_scope=scope,
                allowed_scope=self.policy.allowed_scope_wire(),
                error_stage="argument_validation",
            )
            return ServerDecision(
                control=_attach_resource_telemetry(control, spec, arguments, self.policy),
                ticket=None,
                tool_name=tool_name,
                arguments=arguments,
                request_id=parsed.id,
            )

        resource_id = _extract_resource_id(spec, arguments)
        if spec.resource_key is not None:
            if resource_id is None:
                control = McpControlResult(
                    control_id="CTRL-MCP-001",
                    control_type="mcp_allowlist",
                    decision="ERROR",
                    reason="malformed_arguments",
                    profile=profile,
                    tool_name=tool_name,
                    requested_scope=scope,
                    allowed_scope=self.policy.allowed_scope_wire(),
                    error_stage="argument_validation",
                    allowed_resource_ids=self.policy.allowed_policy_ids_wire(),
                )
                return ServerDecision(
                    control=control,
                    ticket=None,
                    tool_name=tool_name,
                    arguments=arguments,
                    request_id=parsed.id,
                )
            resource_decision, resource_reason, resource_stage = authorize_resource(
                profile=profile,
                policy=self.policy,
                resource_id=resource_id,
                valid_resources=spec.valid_resources,
            )
            wire = self.policy.allowed_policy_ids_wire()
            if resource_decision != "ALLOW":
                control = McpControlResult(
                    control_id="CTRL-MCP-001",
                    control_type="mcp_allowlist",
                    decision=resource_decision,
                    reason=resource_reason,
                    profile=profile,
                    tool_name=tool_name,
                    requested_scope=scope,
                    allowed_scope=self.policy.allowed_scope_wire(),
                    error_stage=resource_stage,
                    resource_id=resource_id,
                    allowed_resource_ids=wire,
                )
                return ServerDecision(
                    control=control,
                    ticket=None,
                    tool_name=tool_name,
                    arguments=arguments,
                    request_id=parsed.id,
                )
            if control.reason.startswith("vulnerable_profile_fail_open:"):
                control = replace(
                    control,
                    resource_id=resource_id,
                    allowed_resource_ids=wire,
                )
            else:
                control = McpControlResult(
                    control_id="CTRL-MCP-001",
                    control_type="mcp_allowlist",
                    decision="ALLOW",
                    reason=resource_reason,
                    profile=profile,
                    tool_name=tool_name,
                    requested_scope=scope,
                    allowed_scope=self.policy.allowed_scope_wire(),
                    resource_id=resource_id,
                    allowed_resource_ids=wire,
                )

        ticket = AllowTicket(
            tool_name=tool_name,
            arguments=dict(arguments),
            request_id=parsed.id,
            token=secrets.token_hex(16),
            resource_id=resource_id,
        )
        self._tickets[ticket.token] = ticket
        return ServerDecision(
            control=_attach_resource_telemetry(control, spec, arguments, self.policy, resource_id=resource_id),
            ticket=ticket,
            tool_name=tool_name,
            arguments=arguments,
            request_id=parsed.id,
        )

    def execute(self, ticket: AllowTicket | None) -> ServerExecution:
        """Begin the handler only with a ticket minted by authorize() after ALLOW."""
        if ticket is None or ticket.token not in self._tickets:
            return ServerExecution(
                ok=False,
                began=False,
                payload=None,
                error_type="missing_allow_ticket",
                error_message="execute requires an ALLOW ticket from this server",
            )
        stored = self._tickets.pop(ticket.token)
        handler_args = _handler_arguments(self.registry.spec(stored.tool_name), stored)
        try:
            payload = self.registry.call_handler(stored.tool_name, handler_args)
        except Exception as exc:
            return ServerExecution(
                ok=False,
                began=True,
                payload=None,
                error_type=type(exc).__name__,
                error_message=str(exc)[:500] or type(exc).__name__,
            )
        return ServerExecution(ok=True, began=True, payload=payload)

    def _authorize_or_default(self, **kwargs: Any) -> McpControlResult:
        if self._authorize_fn is not None:
            return self._authorize_fn(**kwargs)
        from agentsec.mcp.authorize import authorize_tool

        return authorize_tool(**kwargs)


def _extract_resource_id(spec: ToolSpec, arguments: dict[str, Any]) -> str | None:
    if spec.resource_key is None:
        return None
    value = arguments.get(spec.resource_key)
    if isinstance(value, str) and value:
        return value
    return None


def _attach_resource_telemetry(
    control: McpControlResult,
    spec: ToolSpec,
    arguments: dict[str, Any],
    policy: McpPolicy,
    resource_id: str | None = None,
) -> McpControlResult:
    if spec.resource_key is None:
        return control
    extracted = resource_id if resource_id is not None else _extract_resource_id(spec, arguments)
    return replace(
        control,
        resource_id=extracted if extracted is not None else control.resource_id,
        allowed_resource_ids=policy.allowed_policy_ids_wire(),
    )


def _handler_arguments(spec: ToolSpec, ticket: AllowTicket) -> dict[str, Any]:
    """Handler sees the authorized resource id, not a later mutation of the request dict."""
    if spec.resource_key is None or ticket.resource_id is None:
        return dict(ticket.arguments)
    return {spec.resource_key: ticket.resource_id}


def _argument_error(required_keys: frozenset[str], arguments: dict[str, Any]) -> str:
    if set(arguments.keys()) != set(required_keys):
        return "malformed_arguments"
    for key in required_keys:
        value = arguments.get(key)
        if not isinstance(value, str) or not value.strip():
            return "malformed_arguments"
    return ""
