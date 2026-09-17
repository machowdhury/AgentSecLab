"""Export LAB-MCP-CATALOG snapshots as scanner input bytes.

Uses the same ToolSpec/catalog machinery as the runtime. The export is DATA.
It contains no grants.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from agentsec.events import content_hash
from agentsec.mcp.catalog import (
    ALLOWED_TOOL_OBJECT_KEYS,
    FIXTURE_MALICIOUS,
    FIXTURE_NORMAL,
    GRANT_LIKE_KEYS,
    build_catalog_snapshot,
)
from agentsec.mcp.registry import ToolRegistry
from agentsec.scanners.models import ARTIFACT_TYPE_MCP_CATALOG, ArtifactIdentity


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(data).hexdigest()


def catalog_export_dict(
    fixture: str,
    registry: ToolRegistry | None = None,
) -> dict:
    if fixture not in (FIXTURE_NORMAL, FIXTURE_MALICIOUS):
        raise ValueError(f"unknown catalog fixture: {fixture}")
    snapshot = build_catalog_snapshot(registry, fixture=fixture)
    payload = snapshot.as_dict()
    if set(payload) != {"tools"}:
        raise ValueError("catalog export must be tools/list-shaped")
    for row in payload["tools"]:
        extra = set(row) - ALLOWED_TOOL_OBJECT_KEYS
        if extra:
            raise ValueError(f"catalog export grew extra keys: {sorted(extra)}")
        banned = set(row) & GRANT_LIKE_KEYS
        if banned:
            raise ValueError(f"catalog export must not carry grants: {sorted(banned)}")
    return payload


def catalog_export_bytes(
    fixture: str,
    registry: ToolRegistry | None = None,
) -> bytes:
    """Canonical UTF-8 JSON. Hash these exact bytes, not a later reconstruction."""
    payload = catalog_export_dict(fixture, registry)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    return (text + "\n").encode("utf-8")


def lookup_policy_description_hash(
    fixture: str,
    registry: ToolRegistry | None = None,
) -> str:
    payload = catalog_export_dict(fixture, registry)
    policy = next(row for row in payload["tools"] if row["name"] == "lookup_policy")
    return content_hash(policy["description"])


def write_catalog_artifact(
    dest: Path,
    fixture: str,
    registry: ToolRegistry | None = None,
    *,
    created_at: str | None = None,
) -> tuple[bytes, ArtifactIdentity]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = catalog_export_bytes(fixture, registry)
    dest.write_bytes(data)
    identity = ArtifactIdentity(
        path=str(dest),
        sha256=sha256_bytes(data),
        bytes_len=len(data),
        fixture=fixture,
        created_at=created_at or _utc_now(),
        description_sha256=lookup_policy_description_hash(fixture, registry),
        tool_count=len(catalog_export_dict(fixture, registry)["tools"]),
    )
    return data, identity


ARTIFACT_TYPE = ARTIFACT_TYPE_MCP_CATALOG
