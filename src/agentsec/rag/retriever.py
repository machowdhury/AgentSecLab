"""Deterministic exact-id local fixture retriever.

No embeddings. No prefix, case-fold, strip, wildcard, or regex identity.
Unknown ids do not fall back. Retrieved bytes are DATA, never grants.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.rag.fixtures import (
    DOCUMENT_ID_MALICIOUS,
    DOCUMENT_ID_NORMAL,
    MALICIOUS_DOCUMENT,
    MAX_DOCUMENT_BYTES,
    NORMAL_DOCUMENT,
    PROVENANCE,
)

CORPUS: dict[str, str] = {
    DOCUMENT_ID_NORMAL: NORMAL_DOCUMENT,
    DOCUMENT_ID_MALICIOUS: MALICIOUS_DOCUMENT,
}


@dataclass(frozen=True)
class RetrievedContext:
    """Immutable snapshot of retrieved bytes. Not an AllowTicket. Not a grant."""

    document_id: str
    content: str
    provenance: str = PROVENANCE


@dataclass(frozen=True)
class RetrievalError:
    reason: str
    error_stage: str = "schema_validation"
    requested_id: str = "unknown"


def retrieve(document_id: object) -> tuple[RetrievedContext | None, RetrievalError | None]:
    """Exact opaque identity. Do not trim, lowercase, or prefix-match."""
    if not isinstance(document_id, str):
        return None, RetrievalError(reason="malformed_retrieval_object", requested_id="unknown")
    if document_id not in CORPUS:
        requested = document_id if document_id else "unknown"
        return None, RetrievalError(reason="unknown_document", requested_id=requested[:128])
    content = CORPUS[document_id]
    if not isinstance(content, str):
        return None, RetrievalError(reason="malformed_retrieval_object", requested_id=document_id)
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_DOCUMENT_BYTES:
        return None, RetrievalError(reason="malformed_retrieval_object", requested_id=document_id)
    return RetrievedContext(document_id=document_id, content=content, provenance=PROVENANCE), None


def validate_retrieved_context(obj: object) -> tuple[RetrievedContext | None, RetrievalError | None]:
    """Reject malformed internal objects. Grant-like keys are not a retrieve contract."""
    if isinstance(obj, RetrievedContext):
        if not isinstance(obj.document_id, str) or not obj.document_id:
            return None, RetrievalError(reason="malformed_retrieval_object", requested_id="unknown")
        if not isinstance(obj.content, str):
            return None, RetrievalError(
                reason="malformed_retrieval_object", requested_id=obj.document_id
            )
        if obj.provenance != PROVENANCE:
            return None, RetrievalError(
                reason="malformed_retrieval_object", requested_id=obj.document_id
            )
        if len(obj.content.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            return None, RetrievalError(
                reason="malformed_retrieval_object", requested_id=obj.document_id
            )
        return obj, None
    if not isinstance(obj, dict):
        return None, RetrievalError(reason="malformed_retrieval_object", requested_id="unknown")
    grant_like = {
        "allowed_tools",
        "allowed_scopes",
        "allowed_resources",
        "trusted_document",
        "document_authorized",
        "security.profile",
        "context.trust",
        "agentsec.rag.context.trust",
    }
    if any(key in grant_like for key in obj):
        return None, RetrievalError(reason="malformed_retrieval_object", requested_id="unknown")
    document_id = obj.get("document_id")
    content = obj.get("content")
    provenance = obj.get("provenance", PROVENANCE)
    if not isinstance(document_id, str) or not document_id:
        return None, RetrievalError(reason="malformed_retrieval_object", requested_id="unknown")
    if not isinstance(content, str):
        return None, RetrievalError(reason="malformed_retrieval_object", requested_id=document_id)
    if provenance != PROVENANCE:
        return None, RetrievalError(reason="malformed_retrieval_object", requested_id=document_id)
    return RetrievedContext(document_id=document_id, content=content, provenance=PROVENANCE), None
