"""Framework references (MITRE ATLAS, OWASP, NIST, MCP) with verification status.

Telemetry no longer emits agentsec.technique.id: identifiers shown to learners come from
learning/academy/framework_refs.json, and only ids with a verified entry may appear.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

REGISTRY = Path(__file__).resolve().parents[2] / "learning" / "academy" / "framework_refs.json"
SHOWABLE = ("VERIFIED", "VERIFIED_WITH_LIMITS")


@lru_cache(maxsize=1)
def load() -> dict:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def verified_ids() -> frozenset[str]:
    return frozenset(i["id"] for i in load()["items"] if i["status"] in SHOWABLE)


def references_for(scope: str) -> list[dict]:
    """Educational references for an attack or lab id, each joined to its verified item."""
    doc = load()
    items = {i["id"]: i for i in doc["items"]}
    out = []
    for ref in doc["lab_references"]:
        if ref["scope"] != scope:
            continue
        item = items.get(ref["id"])
        if item is None or item["status"] not in SHOWABLE:
            continue  # never show an id that has no verified entry
        out.append({**ref, "name": item["name"], "status": item["status"], "source_url": item["source_url"],
                    "retrieved_on": doc["retrieved_on"]})
    return out


def retired_labels(scope: str | None = None) -> list[dict]:
    """Labels removed from telemetry. With a scope, only those that were emitted for that attack id."""
    rows = load()["retired_labels"]
    return rows if scope is None else [r for r in rows if scope in r["emitted_for"]]
