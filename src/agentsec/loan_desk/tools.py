"""Loan Desk tool catalogue. Handlers are bounded, in-process and synthetic-data only.

A tool is code the agent may ask for. Whether it may run is decided elsewhere (policy.py);
nothing here consults the model or the prompt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

APPLICANT_ID = re.compile(r"^APP-\d{4}$")
POSTURES = ("baseline", "hardened")  # baseline = free-text review notes (lab weakness); hardened = reason codes only
REVIEW_CODES = ("READY_FOR_REVIEW", "NEEDS_DOCUMENTS", "CREDIT_CONCERN", "INCOME_CONCERN")


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    scope: str
    schema: dict[str, Any]
    # Argument that names the applicant record this call touches (resource binding), if any.
    resource_arg: str | None = None


def _obj(props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


_APP = {"type": "string", "description": "Applicant id such as APP-1001"}

TOOLS: dict[str, Tool] = {
    t.name: t
    for t in (
        Tool("get_applicant_profile", "Read the applicant's submitted profile.", "applicant:read",
             _obj({"applicant_id": _APP}, ["applicant_id"]), "applicant_id"),
        Tool("get_credit_summary", "Read the applicant's synthetic credit summary.", "credit:read",
             _obj({"applicant_id": _APP}, ["applicant_id"]), "applicant_id"),
        Tool("lookup_lending_policy", "Read an AcmeBank lending policy topic: dti, ltv or basics.", "policy:read",
             _obj({"topic": {"type": "string", "enum": ["dti", "ltv", "basics"]}}, ["topic"])),
        Tool("calculate_payment", "Compute a monthly mortgage payment.", "calc:run",
             _obj({"principal": {"type": "number"}, "annual_rate_pct": {"type": "number"},
                   "years": {"type": "integer"}}, ["principal", "annual_rate_pct", "years"])),
        Tool("submit_for_underwriter_review", "Queue the case for a human underwriter with a short note.",
             "review:submit", _obj({"applicant_id": _APP, "note": {"type": "string"}}, ["applicant_id", "note"]),
             "applicant_id"),
        Tool("issue_loan_offer", "Issue a binding loan offer. Reserved for human underwriters.", "offer:issue",
             _obj({"applicant_id": _APP, "amount": {"type": "number"}}, ["applicant_id", "amount"]), "applicant_id"),
    )
}

# Numeric sanity bounds; wider values are rejected as invalid arguments, not clamped.
_RANGES = {"principal": (1_000, 5_000_000), "annual_rate_pct": (0.1, 25.0), "years": (1, 40), "amount": (1, 5_000_000)}


def validate_arguments(name: str, arguments: Any) -> str | None:
    """Return None when arguments satisfy the tool schema, else a short machine reason."""
    tool = TOOLS.get(name)
    if tool is None:
        return "unknown_tool"
    if not isinstance(arguments, dict):
        return "arguments_not_object"
    props = tool.schema["properties"]
    if set(arguments) - set(props):
        return "unexpected_argument"
    for key in tool.schema["required"]:
        if key not in arguments:
            return f"missing_argument:{key}"
    for key, value in arguments.items():
        want = props[key]["type"]
        if want == "string":
            if not isinstance(value, str) or len(value) > 500:
                return f"bad_type:{key}"
            if "enum" in props[key] and value not in props[key]["enum"]:
                return f"bad_value:{key}"
            if key == "applicant_id" and not APPLICANT_ID.match(value):
                return f"bad_value:{key}"
        elif want == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                return f"bad_type:{key}"
        elif want == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return f"bad_type:{key}"
        if key in _RANGES and not (_RANGES[key][0] <= value <= _RANGES[key][1]):
            return f"out_of_range:{key}"
    return None


_NUM = re.compile(r"^-?\d+(\.\d+)?$")


def coerce_arguments(name: str, arguments: Any) -> tuple[Any, list[str]]:
    """Parse-layer normalisation: clean numeric strings become numbers. Returns (arguments, coerced keys).

    Small models often emit "420000" for a number. This is a lossless reading of the model's
    output, done before policy; the policy still sees the coerced keys and validates the result.
    """
    tool = TOOLS.get(name)
    if tool is None or not isinstance(arguments, dict):
        return arguments, []
    out, changed = dict(arguments), []
    for key, value in arguments.items():
        want = tool.schema["properties"].get(key, {}).get("type")
        if want in ("number", "integer") and isinstance(value, str) and _NUM.match(value.strip()):
            num = float(value)
            out[key] = int(num) if want == "integer" and num == int(num) else num
            changed.append(key)
    return out, changed


Handler = Callable[[dict[str, Any]], dict[str, Any]]
