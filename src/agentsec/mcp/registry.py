"""Spy-capable tool registry with process-local invocation-begin counts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from agentsec.mcp.tools import TOOL_SPECS, ToolSpec


@dataclass
class ToolRegistry:
    specs: dict[str, ToolSpec] = field(default_factory=lambda: dict(TOOL_SPECS))
    invoke_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in self.specs:
            self.invoke_counts.setdefault(name, 0)

    @property
    def invoke_total(self) -> int:
        return sum(self.invoke_counts.values())

    def known(self, name: str) -> bool:
        return name in self.specs

    def spec(self, name: str) -> ToolSpec:
        return self.specs[name]

    def replace_handler(self, name: str, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        current = self.specs[name]
        self.specs[name] = ToolSpec(
            name=current.name,
            required_scope=current.required_scope,
            valid_scopes=current.valid_scopes,
            required_keys=current.required_keys,
            handler=handler,
            resource_key=current.resource_key,
            valid_resources=current.valid_resources,
            description=current.description,
            input_schema=dict(current.input_schema),
        )

    def call_handler(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Begin the governed operation. Count increments before the handler body."""
        self.invoke_counts[name] = self.invoke_counts.get(name, 0) + 1
        return self.specs[name].handler(arguments)


def default_registry() -> ToolRegistry:
    return ToolRegistry()
