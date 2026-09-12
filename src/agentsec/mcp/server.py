"""In-process MCP server. Authorization is authoritative and runs before the handler."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

from agentsec.mcp.authorize import McpControlResult, evaluate_mcp_control
from agentsec.mcp.policy import McpPolicy, coded_policy
from agentsec.mcp.protocol import ToolsCallRequest, decode_tools_call
from agentsec.mcp.registry import ToolRegistry, default_registry

AuthorizeFn = Callable[..., McpControlResult]


@dataclass(frozen=True)
class AllowTicket:
    """Opaque capability minted only after ALLOW. Cannot be supplied by HTTP."""

    tool_name: str
    arguments: dict[str, Any]
    request_id: int | str
    token: str


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

    def authorize(
        self,
        rpc_message: object,
        *,
        profile: str,
        requested_scope: str,
        coded_agent_id: str,
    ) -> ServerDecision:
        """Resolve coded policy, validate tool/args, then decide. Never starts a handler."""
        del coded_agent_id  # identity is policy.agent_id; parameter documents the trust rule
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
        scope = requested_scope.strip() if isinstance(requested_scope, str) else ""
        if not scope:
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

        registered = self.registry.known(tool_name)
        if not registered:
            control = evaluate_mcp_control(
                tool_name=tool_name,
                requested_scope=scope,
                profile=profile,
                policy=self.policy,
                tool_registered=False,
                authorize_fn=self._authorize_or_default,
            )
            return ServerDecision(
                control=control,
                ticket=None,
                tool_name=tool_name,
                arguments=arguments,
                request_id=parsed.id,
            )

        arg_error = _argument_error(self.registry.spec(tool_name).required_keys, arguments)
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
                control=control,
                ticket=None,
                tool_name=tool_name,
                arguments=arguments,
                request_id=parsed.id,
            )

        control = evaluate_mcp_control(
            tool_name=tool_name,
            requested_scope=scope,
            profile=profile,
            policy=self.policy,
            tool_registered=True,
            authorize_fn=self._authorize_or_default,
        )
        ticket = None
        if control.decision == "ALLOW":
            ticket = AllowTicket(
                tool_name=tool_name,
                arguments=arguments,
                request_id=parsed.id,
                token=secrets.token_hex(16),
            )
            self._tickets[ticket.token] = ticket
        return ServerDecision(
            control=control,
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
        try:
            payload = self.registry.call_handler(stored.tool_name, stored.arguments)
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


def _argument_error(required_keys: frozenset[str], arguments: dict[str, Any]) -> str:
    if set(arguments.keys()) != set(required_keys):
        return "malformed_arguments"
    for key in required_keys:
        value = arguments.get(key)
        if not isinstance(value, str) or not value.strip():
            return "malformed_arguments"
    return ""
