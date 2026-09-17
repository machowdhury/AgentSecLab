"""Closed HTTP contract for POST /rag/retrieve. Unknown fields are ERROR, not policy."""

from __future__ import annotations

from dataclasses import dataclass

ALLOWED_RAG_RETRIEVE_FIELDS = frozenset({"document_id", "user_id"})


@dataclass(frozen=True)
class ParsedRagRetrieveRequest:
    ok: bool
    document_id: str | None
    user_id: str
    error_reason: str
    extra_fields: tuple[str, ...]


def parse_rag_retrieve_body(data: object) -> ParsedRagRetrieveRequest:
    if not isinstance(data, dict):
        return ParsedRagRetrieveRequest(
            ok=False,
            document_id=None,
            user_id="unknown",
            error_reason="malformed_input",
            extra_fields=(),
        )

    extra = tuple(sorted(str(key) for key in data.keys() if key not in ALLOWED_RAG_RETRIEVE_FIELDS))
    if extra:
        document_id = data.get("document_id") if isinstance(data.get("document_id"), str) else None
        return ParsedRagRetrieveRequest(
            ok=False,
            document_id=document_id,
            user_id=_label_user_id(data.get("user_id")),
            error_reason="unknown_fields",
            extra_fields=extra,
        )

    document_id = data.get("document_id")
    if not isinstance(document_id, str) or not document_id:
        return ParsedRagRetrieveRequest(
            ok=False,
            document_id=None,
            user_id=_label_user_id(data.get("user_id")),
            error_reason="missing_document_id",
            extra_fields=(),
        )

    user_id = data.get("user_id", "applicant-web")
    if "user_id" in data and (not isinstance(user_id, str) or not user_id.strip()):
        return ParsedRagRetrieveRequest(
            ok=False,
            document_id=document_id,
            user_id="unknown",
            error_reason="malformed_input",
            extra_fields=(),
        )

    return ParsedRagRetrieveRequest(
        ok=True,
        document_id=document_id,
        user_id=_label_user_id(user_id),
        error_reason="",
        extra_fields=(),
    )


def _label_user_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        return "applicant-web"
    return value.strip()[:64]
