"""MCP client: encode tools/call only. Does not authorize and cannot grant tools."""

from __future__ import annotations

from typing import Any

from agentsec.mcp.protocol import encode_tools_call


class McpClient:
    """Untrusted relative to the server. Identity and grants are not taken from here."""

    def tools_call(self, *, name: str, arguments: dict[str, Any], request_id: int | str = 1) -> dict[str, Any]:
        return encode_tools_call(name=name, arguments=arguments, request_id=request_id)
