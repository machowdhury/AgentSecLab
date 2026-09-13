"""Harmless deterministic lab tools. No shell, filesystem writes, or network."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

POLICY_FIXTURES: dict[str, dict[str, str]] = {
    "lending-basics": {
        "policy_id": "lending-basics",
        "title": "Lab lending policy",
        "summary": "Lab-only snippet: document income before credit scoring.",
    },
    "executive-restricted": {
        "policy_id": "executive-restricted",
        "title": "Lab executive policy placeholder",
        "summary": "Lab-only restricted snippet. Not a real executive document.",
    },
}

CUSTOMER_FIXTURES: dict[str, dict[str, str]] = {
    "cust-001": {
        "customer_id": "cust-001",
        "tier": "standard",
    }
}

POLICY_READ_SCOPE = "policy:read"
POLICY_RESTRICTED_READ_SCOPE = "policy:restricted:read"
CUSTOMER_READ_SCOPE = "customer:read"
POLICY_RESOURCE_CATALOG = frozenset(POLICY_FIXTURES)
POLICY_RESOURCE_KEY = "policy_id"


@dataclass(frozen=True)
class ToolSpec:
    """Catalog of a fixture tool. valid_scopes and valid_resources are opaque labels."""

    name: str
    required_scope: str
    valid_scopes: frozenset[str]
    required_keys: frozenset[str]
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    resource_key: str | None = None
    valid_resources: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.required_scope not in self.valid_scopes:
            raise ValueError(f"{self.name}: required_scope must be a member of valid_scopes")
        if self.resource_key is not None:
            if self.resource_key not in self.required_keys:
                raise ValueError(f"{self.name}: resource_key must be a required argument key")
            if not self.valid_resources:
                raise ValueError(f"{self.name}: resource catalog must be non-empty")


def lookup_policy(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handler uses ticket-supplied policy_id only. Catalog membership is not the ACL."""
    policy_id = arguments["policy_id"]
    row = POLICY_FIXTURES[policy_id]
    return {**row, "found": True}


def lookup_customer_tier(arguments: dict[str, Any]) -> dict[str, Any]:
    customer_id = arguments["customer_id"]
    row = CUSTOMER_FIXTURES.get(customer_id)
    if row is None:
        return {"customer_id": customer_id, "found": False}
    return {**row, "found": True}


TOOL_SPECS: dict[str, ToolSpec] = {
    "lookup_policy": ToolSpec(
        name="lookup_policy",
        required_scope=POLICY_READ_SCOPE,
        valid_scopes=frozenset({POLICY_READ_SCOPE, POLICY_RESTRICTED_READ_SCOPE}),
        required_keys=frozenset({POLICY_RESOURCE_KEY}),
        handler=lookup_policy,
        resource_key=POLICY_RESOURCE_KEY,
        valid_resources=POLICY_RESOURCE_CATALOG,
    ),
    "lookup_customer_tier": ToolSpec(
        name="lookup_customer_tier",
        required_scope=CUSTOMER_READ_SCOPE,
        valid_scopes=frozenset({CUSTOMER_READ_SCOPE}),
        required_keys=frozenset({"customer_id"}),
        handler=lookup_customer_tier,
    ),
}
