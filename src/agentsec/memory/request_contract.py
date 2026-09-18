"""Closed HTTP contracts for POST /memory/write and POST /memory/recall."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.memory.fixtures import GRANT_LIKE_FIELDS

ALLOWED_MEMORY_WRITE_FIELDS = frozenset({"memory_id", "user_id"})
ALLOWED_MEMORY_RECALL_FIELDS = frozenset({"memory_id", "user_id"})


@dataclass(frozen=True)
class ParsedMemoryRequest:
    ok: bool
    memory_id: str | None
    user_id: str
    error_reason: str
    extra_fields: tuple[str, ...]


def parse_memory_write_body(data: object) -> ParsedMemoryRequest:
    return _parse(data, ALLOWED_MEMORY_WRITE_FIELDS)


def parse_memory_recall_body(data: object) -> ParsedMemoryRequest:
    return _parse(data, ALLOWED_MEMORY_RECALL_FIELDS)


def _parse(data: object, allowed: frozenset[str]) -> ParsedMemoryRequest:
    if not isinstance(data, dict):
        return ParsedMemoryRequest(
            ok=False,
            memory_id=None,
            user_id="unknown",
            error_reason="malformed_input",
            extra_fields=(),
        )

    extra = tuple(sorted(str(key) for key in data.keys() if key not in allowed))
    grant_like = tuple(sorted(str(key) for key in data.keys() if key in GRANT_LIKE_FIELDS))
    if extra or grant_like:
        memory_id = data.get("memory_id") if isinstance(data.get("memory_id"), str) else None
        return ParsedMemoryRequest(
            ok=False,
            memory_id=memory_id,
            user_id=_label_user_id(data.get("user_id")),
            error_reason="unknown_fields",
            extra_fields=tuple(sorted(set(extra + grant_like))),
        )

    memory_id = data.get("memory_id")
    if not isinstance(memory_id, str) or not memory_id:
        return ParsedMemoryRequest(
            ok=False,
            memory_id=None,
            user_id=_label_user_id(data.get("user_id")),
            error_reason="missing_memory_id",
            extra_fields=(),
        )

    user_id = data.get("user_id", "applicant-web")
    if "user_id" in data and (not isinstance(user_id, str) or not user_id.strip()):
        return ParsedMemoryRequest(
            ok=False,
            memory_id=memory_id,
            user_id="unknown",
            error_reason="malformed_input",
            extra_fields=(),
        )

    return ParsedMemoryRequest(
        ok=True,
        memory_id=memory_id,
        user_id=_label_user_id(user_id),
        error_reason="",
        extra_fields=(),
    )


def _label_user_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        return "applicant-web"
    return value.strip()[:64]
