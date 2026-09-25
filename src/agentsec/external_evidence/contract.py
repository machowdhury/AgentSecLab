"""Vendor-neutral external security evidence contract.

Independent from runtime schema 1.9.0. External records are not
authorization decisions and must not be imported by the PDP.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

EXTERNAL_CONTRACT_VERSION = "1.0.0"

EVIDENCE_CLASS_FINDING = "finding"
EVIDENCE_CLASS_EVALUATION = "evaluation"
EVIDENCE_CLASS_INVENTORY = "inventory"
EVIDENCE_CLASS_ASSESSMENT = "assessment"

EVIDENCE_CLASSES = frozenset(
    {
        EVIDENCE_CLASS_FINDING,
        EVIDENCE_CLASS_EVALUATION,
        EVIDENCE_CLASS_INVENTORY,
        EVIDENCE_CLASS_ASSESSMENT,
    }
)

PRODUCER_OBSERVED_SCANNER = "OBSERVED_SCANNER"

CORRELATION_METHOD_HASH_JOIN = "hash_join"
CORRELATION_KEY_DESCRIPTION_CONTENT_HASH = "description_sha256/content.hash"

FINGERPRINT_ALG_SHA256 = "sha256"


def omit_empty(payload: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, dict):
            nested = omit_empty(value)
            if nested:
                out[key] = nested
            continue
        if isinstance(value, (tuple, list)) and not value:
            continue
        if value == "":
            continue
        out[key] = value
    return out


@dataclass(frozen=True)
class ExternalEvidence:
    """One normalized external record. Optional fields stay absent when unknown."""

    evidence_class: str
    evidence_id: str
    provider: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    subject_type: str | None = None
    subject_id: str | None = None
    subject_name: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    artifact_type: str | None = None
    artifact_fingerprint: str | None = None
    artifact_fingerprint_algorithm: str | None = None
    correlation_method: str | None = None
    correlation_key: str | None = None
    correlation_value: str | None = None
    framework_mappings: tuple[str, ...] = ()
    source_timestamp: str | None = None
    ingest_timestamp: str | None = None
    raw_evidence_ref: str | None = None
    raw_evidence_sha256: str | None = None
    producer_class: str | None = None
    contract_version: str = EXTERNAL_CONTRACT_VERSION
    extras: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.evidence_class not in EVIDENCE_CLASSES:
            raise ValueError(f"unknown external evidence_class: {self.evidence_class}")

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "contract.version": self.contract_version,
            "provider": self.provider,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "evidence_class": self.evidence_class,
            "evidence_id": self.evidence_id,
            "producer_class": self.producer_class,
            "subject": {
                "type": self.subject_type,
                "id": self.subject_id,
                "name": self.subject_name,
            },
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "artifact": {
                "type": self.artifact_type,
                "fingerprint": self.artifact_fingerprint,
                "fingerprint_algorithm": self.artifact_fingerprint_algorithm,
            },
            "correlation": {
                "method": self.correlation_method,
                "key": self.correlation_key,
                "value": self.correlation_value,
            },
            "framework_mappings": list(self.framework_mappings) if self.framework_mappings else None,
            "source_timestamp": self.source_timestamp,
            "ingest_timestamp": self.ingest_timestamp,
            "raw_evidence_ref": self.raw_evidence_ref,
            "raw_evidence_sha256": self.raw_evidence_sha256,
        }
        body = omit_empty(payload)
        if self.extras:
            native = omit_empty(dict(self.extras))
            if native:
                body["native"] = native
        return body
