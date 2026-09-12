"""Minimal MCP JSON-RPC 2.0 tools/call messages. Not a full initialize handshake."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MCP_METHOD_TOOLS_CALL = "tools/call"


@dataclass(frozen=True)
class ToolsCallRequest:
    jsonrpc: str
    id: int | str
    method: str
    name: str
    arguments: dict[str, Any]
    raw_params: dict[str, Any]


def encode_tools_call(*, name: str, arguments: dict[str, Any], request_id: int | str = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": MCP_METHOD_TOOLS_CALL,
        "params": {"name": name, "arguments": arguments},
    }


def decode_tools_call(message: object) -> tuple[ToolsCallRequest | None, str]:
    if not isinstance(message, dict):
        return None, "malformed_rpc"
    if message.get("jsonrpc") != "2.0":
        return None, "malformed_rpc"
    if message.get("method") != MCP_METHOD_TOOLS_CALL:
        return None, "malformed_rpc"
    params = message.get("params")
    if not isinstance(params, dict):
        return None, "malformed_rpc"
    name = params.get("name")
    if not isinstance(name, str) or not name.strip():
        return None, "malformed_rpc"
    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return None, "malformed_arguments"
    request_id = message.get("id", 1)
    if not isinstance(request_id, (int, str)):
        request_id = 1
    return (
        ToolsCallRequest(
            jsonrpc="2.0",
            id=request_id,
            method=MCP_METHOD_TOOLS_CALL,
            name=name.strip(),
            arguments=arguments,
            raw_params=params,
        ),
        "",
    )


def encode_result(*, request_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": str(payload)}] , "structuredContent": payload}}


def encode_error(*, request_id: int | str, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
