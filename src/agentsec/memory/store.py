"""In-process fixture-backed persistent memory store.

Persists across WRITE and RECALL runs inside one specimen. Not an
authorization store. Records never carry grants.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.events import content_hash
from agentsec.memory.fixtures import (
    GRANT_LIKE_FIELDS,
    MALICIOUS_MEMORY,
    MAX_MEMORY_BYTES,
    MEMORY_ID_CAPSTONE_MALICIOUS,
    MEMORY_ID_CAPSTONE_NORMAL,
    MEMORY_ID_MALICIOUS,
    MEMORY_ID_NORMAL,
    MEMORY_TRUST_LABEL,
    NORMAL_MEMORY,
    PROVENANCE,
)
from agentsec.rag.fixtures import MALICIOUS_DOCUMENT, NORMAL_DOCUMENT

FIXTURES: dict[str, str] = {
    MEMORY_ID_NORMAL: NORMAL_MEMORY,
    MEMORY_ID_MALICIOUS: MALICIOUS_MEMORY,
    MEMORY_ID_CAPSTONE_NORMAL: NORMAL_DOCUMENT,
    MEMORY_ID_CAPSTONE_MALICIOUS: MALICIOUS_DOCUMENT,
}


@dataclass(frozen=True)
class MemoryRecord:
    """Immutable snapshot of persisted memory. Not an AllowTicket. Not a grant."""

    memory_id: str
    content: str
    content_hash: str
    provenance: str
    writer_agent_id: str
    source_run_id: str
    trust: str = MEMORY_TRUST_LABEL


@dataclass(frozen=True)
class MemoryError:
    reason: str
    error_stage: str = "schema_validation"
    requested_id: str = "unknown"


class InProcessMemoryStore:
    """Process-local store. Survives two run.ids. Does not survive process exit."""

    def __init__(self) -> None:
        self._records: dict[str, MemoryRecord] = {}

    def write_fixture(
        self,
        memory_id: object,
        *,
        writer_agent_id: str,
        source_run_id: str,
        allow_replace_same_fixture: bool = False,
    ) -> tuple[MemoryRecord | None, MemoryError | None]:
        if not isinstance(memory_id, str) or not memory_id:
            requested = memory_id if isinstance(memory_id, str) and memory_id else "unknown"
            return None, MemoryError(reason="empty_memory_id", requested_id=requested[:128])
        if memory_id not in FIXTURES:
            return None, MemoryError(reason="unknown_memory_id", requested_id=memory_id[:128])
        content = FIXTURES[memory_id]
        if memory_id in self._records:
            if not allow_replace_same_fixture:
                return None, MemoryError(reason="duplicate_memory_id", requested_id=memory_id)
            existing = self._records[memory_id]
            if existing.content != content:
                return None, MemoryError(reason="duplicate_memory_id", requested_id=memory_id)
        return self._put(
            memory_id=memory_id,
            content=content,
            provenance=PROVENANCE,
            writer_agent_id=writer_agent_id,
            source_run_id=source_run_id,
        )

    def write(self, obj: object, *, writer_agent_id: str, source_run_id: str) -> tuple[MemoryRecord | None, MemoryError | None]:
        """Reject grant-like keys. Never interpret memory as authority."""
        if isinstance(obj, MemoryRecord):
            return self._put_record(obj)
        if not isinstance(obj, dict):
            return None, MemoryError(reason="malformed_memory_write", requested_id="unknown")
        if any(key in GRANT_LIKE_FIELDS for key in obj):
            requested = obj.get("memory_id")
            label = requested if isinstance(requested, str) and requested else "unknown"
            return None, MemoryError(reason="malformed_memory_write", requested_id=label[:128])
        memory_id = obj.get("memory_id")
        content = obj.get("content")
        provenance = obj.get("provenance", PROVENANCE)
        writer = obj.get("writer_agent_id", writer_agent_id)
        source = obj.get("source_run_id", source_run_id)
        if not isinstance(memory_id, str) or not memory_id:
            return None, MemoryError(reason="empty_memory_id", requested_id="unknown")
        if memory_id in self._records:
            return None, MemoryError(reason="duplicate_memory_id", requested_id=memory_id)
        if not isinstance(content, str):
            return None, MemoryError(reason="invalid_content_type", requested_id=memory_id)
        if provenance != PROVENANCE:
            return None, MemoryError(reason="invalid_provenance", requested_id=memory_id)
        if not isinstance(writer, str) or not writer:
            return None, MemoryError(reason="malformed_memory_write", requested_id=memory_id)
        if not isinstance(source, str) or not source:
            return None, MemoryError(reason="malformed_memory_write", requested_id=memory_id)
        return self._put(
            memory_id=memory_id,
            content=content,
            provenance=PROVENANCE,
            writer_agent_id=writer,
            source_run_id=source,
        )

    def recall(self, memory_id: object) -> tuple[MemoryRecord | None, MemoryError | None]:
        """Exact opaque identity. Do not trim, lowercase, or prefix-match."""
        if not isinstance(memory_id, str) or not memory_id:
            requested = memory_id if isinstance(memory_id, str) and memory_id else "unknown"
            return None, MemoryError(reason="empty_memory_id", requested_id=requested[:128])
        record = self._records.get(memory_id)
        if record is None:
            return None, MemoryError(reason="unknown_memory_id", requested_id=memory_id[:128])
        return record, None

    def _put(
        self,
        *,
        memory_id: str,
        content: str,
        provenance: str,
        writer_agent_id: str,
        source_run_id: str,
    ) -> tuple[MemoryRecord | None, MemoryError | None]:
        if not isinstance(content, str):
            return None, MemoryError(reason="invalid_content_type", requested_id=memory_id)
        if provenance != PROVENANCE:
            return None, MemoryError(reason="invalid_provenance", requested_id=memory_id)
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_MEMORY_BYTES:
            return None, MemoryError(reason="oversized_memory", requested_id=memory_id)
        record = MemoryRecord(
            memory_id=memory_id,
            content=content,
            content_hash=content_hash(content),
            provenance=PROVENANCE,
            writer_agent_id=writer_agent_id,
            source_run_id=source_run_id,
            trust=MEMORY_TRUST_LABEL,
        )
        self._records[memory_id] = record
        return record, None

    def _put_record(self, record: MemoryRecord) -> tuple[MemoryRecord | None, MemoryError | None]:
        if record.memory_id in self._records:
            return None, MemoryError(reason="duplicate_memory_id", requested_id=record.memory_id)
        if record.provenance != PROVENANCE or record.trust != MEMORY_TRUST_LABEL:
            return None, MemoryError(reason="malformed_memory_write", requested_id=record.memory_id)
        if record.content_hash != content_hash(record.content):
            return None, MemoryError(reason="malformed_memory_write", requested_id=record.memory_id)
        if len(record.content.encode("utf-8")) > MAX_MEMORY_BYTES:
            return None, MemoryError(reason="oversized_memory", requested_id=record.memory_id)
        self._records[record.memory_id] = record
        return record, None
