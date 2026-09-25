"""Cisco mcp-scanner plugin: map NormalizedScan onto ExternalEvidence.

Preserves native Cisco finding fields in extras. Does not authorize.
"""

from __future__ import annotations

from agentsec.external_evidence.contract import (
    CORRELATION_KEY_DESCRIPTION_CONTENT_HASH,
    CORRELATION_METHOD_HASH_JOIN,
    EVIDENCE_CLASS_FINDING,
    EXTERNAL_CONTRACT_VERSION,
    FINGERPRINT_ALG_SHA256,
    PRODUCER_OBSERVED_SCANNER,
    ExternalEvidence,
)
from agentsec.scanners.models import ARTIFACT_TYPE_MCP_CATALOG, NativeFinding, NormalizedScan

CISCO_PROVIDER = "cisco-ai-defense"


def _finding_id(scan_id: str, row: NativeFinding, index: int) -> str:
    parts = [scan_id]
    if row.tool_name:
        parts.append(row.tool_name)
    if row.native_rule_id:
        parts.append(row.native_rule_id)
    else:
        parts.append(str(index))
    return "|".join(parts)


def cisco_normalized_to_external(scan: NormalizedScan) -> tuple[ExternalEvidence, ...]:
    """One record per native finding. Zero findings → one scan-level finding record."""
    common = dict(
        provider=CISCO_PROVIDER,
        tool=scan.scanner.name,
        tool_version=scan.scanner.version,
        evidence_class=EVIDENCE_CLASS_FINDING,
        producer_class=PRODUCER_OBSERVED_SCANNER,
        artifact_type=ARTIFACT_TYPE_MCP_CATALOG,
        artifact_fingerprint=scan.artifact.description_sha256,
        artifact_fingerprint_algorithm=FINGERPRINT_ALG_SHA256,
        correlation_method=CORRELATION_METHOD_HASH_JOIN,
        correlation_key=CORRELATION_KEY_DESCRIPTION_CONTENT_HASH,
        correlation_value=scan.artifact.description_sha256,
        source_timestamp=scan.artifact.created_at,
        raw_evidence_ref="raw/scanner-output.json",
        raw_evidence_sha256=scan.raw_output_sha256,
        contract_version=EXTERNAL_CONTRACT_VERSION,
    )
    if not scan.findings:
        return (
            ExternalEvidence(
                evidence_id=scan.scan_id,
                subject_type=ARTIFACT_TYPE_MCP_CATALOG,
                subject_id=scan.artifact.fixture or None,
                extras={
                    "finding_count": 0,
                    "scan_id": scan.scan_id,
                    "classification": scan.classification,
                },
                **common,
            ),
        )
    records: list[ExternalEvidence] = []
    for index, row in enumerate(scan.findings):
        records.append(
            ExternalEvidence(
                evidence_id=_finding_id(scan.scan_id, row, index),
                subject_type="mcp.tool",
                subject_id=row.tool_name,
                subject_name=row.tool_name,
                severity=row.native_severity,
                title=row.title,
                description=row.summary,
                extras={
                    "scan_id": scan.scan_id,
                    "finding_count": scan.finding_count,
                    "classification": scan.classification,
                    "native_rule_id": row.native_rule_id,
                    "native_category": row.native_category,
                    "native_severity": row.native_severity,
                    "native_confidence": row.native_confidence,
                    "analyzer": row.analyzer,
                    "tool_name": row.tool_name,
                },
                **common,
            )
        )
    return tuple(records)
