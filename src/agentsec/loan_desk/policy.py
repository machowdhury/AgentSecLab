"""Policy decision point for Loan Desk agent actions.

Independent of the model: it sees only a parsed proposal plus server-owned facts (grants, the
applicant the server bound to this run, the loop budget). Nothing the model, the applicant's
notes or a tool result says can change a grant. The model proposes; this module decides.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.loan_desk.tools import TOOLS, validate_arguments

# Server-owned. Not configurable from a request. issue_loan_offer (offer:issue) is deliberately absent.
GRANTED_SCOPES = frozenset({"applicant:read", "credit:read", "policy:read", "calc:run", "review:submit"})
MAX_TOOL_CALLS = 4


@dataclass(frozen=True)
class Decision:
    decision: str  # ALLOW | DENY
    reason: str
    tool: str
    requested_scope: str
    resource_id: str | None

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


def allowed_scope_wire() -> str:
    return ",".join(sorted(GRANTED_SCOPES))


def decide(tool: str, arguments: dict, *, bound_applicant: str, executed_so_far: int, seen: set[str]) -> Decision:
    spec = TOOLS.get(tool)
    if spec is None:  # callers only pass registered tools; kept so the PDP is safe on its own
        return Decision("DENY", "unknown_tool", tool, "unspecified", None)
    resource = arguments.get(spec.resource_arg) if spec.resource_arg and isinstance(arguments, dict) else None
    resource = resource if isinstance(resource, str) else None

    def deny(reason: str) -> Decision:
        return Decision("DENY", reason, tool, spec.scope, resource)

    bad = validate_arguments(tool, arguments)
    if bad:
        return deny(f"invalid_arguments:{bad}")
    if spec.scope not in GRANTED_SCOPES:
        return deny("scope_not_granted")
    if spec.resource_arg and resource != bound_applicant:
        return deny("resource_not_bound_to_run")
    if executed_so_far >= MAX_TOOL_CALLS:
        return deny("tool_budget_exhausted")
    key = tool + repr(sorted(arguments.items()))
    if key in seen:
        return deny("duplicate_call")
    return Decision("ALLOW", "granted_scope_and_bound_resource", tool, spec.scope, resource)
