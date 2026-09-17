"""In-process MCP tools/list-shaped catalog snapshot.

THIS IS LAB MACHINERY. It is not a complete MCP transport.

The snapshot uses real MCP Tool fields (name, description, inputSchema).
Descriptions are DATA. They never become grants.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentsec.mcp.fixtures import (
    MCP_CATALOG_DESCRIPTION_MALICIOUS,
    MCP_CATALOG_DESCRIPTION_NORMAL,
)
from agentsec.mcp.registry import ToolRegistry
from agentsec.mcp.tools import TOOL_SPECS

FIXTURE_NORMAL = "NORMAL"
FIXTURE_MALICIOUS = "MALICIOUS"

ALLOWED_SNAPSHOT_KEYS = frozenset({"tools"})
ALLOWED_TOOL_OBJECT_KEYS = frozenset({"name", "description", "inputSchema"})
GRANT_LIKE_KEYS = frozenset(
    {
        "allowed_tools",
        "allowed_scope",
        "allowed_resource",
        "grant_tool",
        "security.profile",
        "control.decision",
        "role",
        "trusted",
        "metadata.trust",
        "agentsec.mcp.metadata.trust",
    }
)


@dataclass(frozen=True)
class CatalogParseError:
    reason: str
    error_stage: str = "schema_validation"


@dataclass(frozen=True)
class CatalogSnapshot:
    tools: tuple[dict[str, Any], ...]
    fixture: str | None = None

    def tool_named(self, name: str) -> dict[str, Any] | None:
        for row in self.tools:
            if row.get("name") == name:
                return row
        return None

    def as_dict(self) -> dict[str, Any]:
        return {"tools": [dict(row) for row in self.tools]}


def select_catalog_fixture(testbed_mode: str) -> str:
    """Fixture selection is mode-owned. Not an HTTP field."""
    if testbed_mode in ("ATTACK", "RETEST"):
        return FIXTURE_MALICIOUS
    return FIXTURE_NORMAL


def lookup_policy_description_for(fixture: str) -> str:
    if fixture == FIXTURE_MALICIOUS:
        return MCP_CATALOG_DESCRIPTION_MALICIOUS
    return MCP_CATALOG_DESCRIPTION_NORMAL


def build_catalog_snapshot(
    registry: ToolRegistry | None = None,
    *,
    fixture: str = FIXTURE_NORMAL,
) -> CatalogSnapshot:
    """Deterministic tools/list-shaped snapshot. Poison overlays lookup_policy only."""
    specs = (registry.specs if registry is not None else TOOL_SPECS)
    description = lookup_policy_description_for(fixture)
    tools: list[dict[str, Any]] = []
    for name in sorted(specs):
        spec = specs[name]
        tools.append(
            {
                "name": spec.name,
                "description": description if spec.name == "lookup_policy" else spec.description,
                "inputSchema": dict(spec.input_schema),
            }
        )
    return CatalogSnapshot(tools=tuple(tools), fixture=fixture)


def parse_tools_list_snapshot(payload: object) -> tuple[CatalogSnapshot | None, CatalogParseError | None]:
    """Validate a tools/list-shaped object. Malformed catalogs create no authority."""
    if not isinstance(payload, dict):
        return None, CatalogParseError(reason="malformed_catalog")
    extra_root = tuple(sorted(str(key) for key in payload if key not in ALLOWED_SNAPSHOT_KEYS))
    if extra_root:
        return None, CatalogParseError(reason="unknown_catalog_fields")
    grant_root = tuple(sorted(str(key) for key in payload if key in GRANT_LIKE_KEYS))
    if grant_root:
        return None, CatalogParseError(reason="unknown_catalog_fields")
    tools = payload.get("tools")
    if not isinstance(tools, list) or not tools:
        return None, CatalogParseError(reason="malformed_catalog")
    parsed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in tools:
        if not isinstance(item, dict):
            return None, CatalogParseError(reason="malformed_catalog")
        extra = tuple(sorted(str(key) for key in item if key not in ALLOWED_TOOL_OBJECT_KEYS))
        if extra or any(key in GRANT_LIKE_KEYS for key in item):
            return None, CatalogParseError(reason="unknown_catalog_fields")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            return None, CatalogParseError(reason="missing_tool_name")
        if name in seen:
            return None, CatalogParseError(reason="duplicate_tool_name")
        seen.add(name)
        description = item.get("description")
        if not isinstance(description, str) or not description:
            return None, CatalogParseError(reason="invalid_description")
        input_schema = item.get("inputSchema")
        if not isinstance(input_schema, dict):
            return None, CatalogParseError(reason="malformed_catalog")
        if name not in TOOL_SPECS:
            return None, CatalogParseError(reason="unknown_tool_metadata")
        parsed.append(
            {
                "name": name,
                "description": description,
                "inputSchema": dict(input_schema),
            }
        )
    return CatalogSnapshot(tools=tuple(parsed)), None
