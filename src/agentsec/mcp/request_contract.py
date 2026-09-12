"""Closed HTTP contract for POST /mcp/invoke. Unknown fields are ERROR, not policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ALLOWED_MCP_INVOKE_FIELDS = frozenset({"tool", "arguments", "requested_scope", "user_id"})


@dataclass(frozen=True)
class ParsedMcpInvokeRequest:
    ok: bool
    tool: str | None
    arguments: dict[str, Any]
    requested_scope: str
    user_id: str
    error_reason: str
    extra_fields: tuple[str, ...]


def parse_mcp_invoke_body(data: object) -> ParsedMcpInvokeRequest:
    if not isinstance(data, dict):
        return ParsedMcpInvokeRequest(
            ok=False,
            tool=None,
            arguments={},
            requested_scope="",
            user_id="unknown",
            error_reason="malformed_input",
            extra_fields=(),
        )

    extra = tuple(sorted(str(key) for key in data.keys() if key not in ALLOWED_MCP_INVOKE_FIELDS))
    if extra:
        tool = data.get("tool") if isinstance(data.get("tool"), str) else None
        return ParsedMcpInvokeRequest(
            ok=False,
            tool=tool,
            arguments=_as_dict(data.get("arguments")),
            requested_scope=_as_scope(data.get("requested_scope")),
            user_id=_label_user_id(data.get("user_id")),
            error_reason="unknown_fields",
            extra_fields=extra,
        )

    tool = data.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        return ParsedMcpInvokeRequest(
            ok=False,
            tool=None,
            arguments=_as_dict(data.get("arguments")),
            requested_scope=_as_scope(data.get("requested_scope")),
            user_id=_label_user_id(data.get("user_id")),
            error_reason="missing_tool",
            extra_fields=(),
        )

    arguments = data.get("arguments", {})
    if not isinstance(arguments, dict):
        return ParsedMcpInvokeRequest(
            ok=False,
            tool=tool.strip(),
            arguments={},
            requested_scope=_as_scope(data.get("requested_scope")),
            user_id=_label_user_id(data.get("user_id")),
            error_reason="malformed_arguments",
            extra_fields=(),
        )

    requested_scope = data.get("requested_scope")
    if not isinstance(requested_scope, str) or not requested_scope.strip():
        return ParsedMcpInvokeRequest(
            ok=False,
            tool=tool.strip(),
            arguments=dict(arguments),
            requested_scope="",
            user_id=_label_user_id(data.get("user_id")),
            error_reason="missing_requested_scope",
            extra_fields=(),
        )

    user_id = data.get("user_id", "applicant-web")
    if "user_id" in data and (not isinstance(user_id, str) or not user_id.strip()):
        return ParsedMcpInvokeRequest(
            ok=False,
            tool=tool.strip(),
            arguments=dict(arguments),
            requested_scope=requested_scope.strip(),
            user_id="unknown",
            error_reason="malformed_input",
            extra_fields=(),
        )

    return ParsedMcpInvokeRequest(
        ok=True,
        tool=tool.strip(),
        arguments=dict(arguments),
        requested_scope=requested_scope.strip(),
        user_id=_label_user_id(user_id),
        error_reason="",
        extra_fields=(),
    )


def _as_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _as_scope(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _label_user_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        return "applicant-web"
    return value.strip()[:64]
