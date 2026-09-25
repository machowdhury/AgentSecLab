"""Build HEC payloads from Phase 9B scanner packs.

Scanner evidence is an independent sourcetype. It is not
agentsec.security_event 1.9.0. It does not authorize.

Event model (Phase 9C):

- One `agentsec.scanner.scan` event per scan, always.
  finding_count=0 is a successful scan with zero findings.
  Missing scan event != clean artifact.
- One `agentsec.scanner.finding` event per normalized finding.
  NORMAL Phase 9B packs therefore emit only the scan event.

Privacy: do not index artifact paths, argv, binaries, full tool
descriptions, or raw scanner stdout. Link raw files with SHA-256.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentsec.external_evidence.contract import (
    CORRELATION_KEY_DESCRIPTION_CONTENT_HASH,
    CORRELATION_METHOD_HASH_JOIN,
    EVIDENCE_CLASS_FINDING,
    EXTERNAL_CONTRACT_VERSION,
    FINGERPRINT_ALG_SHA256,
    PRODUCER_OBSERVED_SCANNER,
)

SOURCETYPE = "agentsec:scanner:finding"
INDEX_NAME = "agentsec_telemetry"
SOURCE = "agentsec-scanner-hec"
HOST = "agentsec-scanner"
EVENT_SCAN = "agentsec.scanner.scan"
EVENT_FINDING = "agentsec.scanner.finding"

CANONICAL_PACK_DIRS = (
    "normal-b3061c4e-7a81-445c-8fd8-3108dd14c419",
    "malicious-7ae3ea64-4e7a-40fe-943f-3e582bce5ee8",
)

OMITTED_FROM_INDEX = (
    "artifact.path",
    "execution.argv",
    "execution.binary",
    "raw stdout",
    "raw stderr",
    "tool description text",
    "agentsec.run.id",
    "agentsec.control.decision",
)


def evidence_root(repo: Path) -> Path:
    return repo / "docs" / "phase9b-evidence"


def canonical_packs(repo: Path) -> tuple[Path, ...]:
    root = evidence_root(repo)
    packs = tuple(root / name for name in CANONICAL_PACK_DIRS)
    for pack in packs:
        if not (pack / "manifest.json").is_file():
            raise FileNotFoundError(f"canonical Phase 9B pack missing: {pack}")
    return packs


def _omit_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _omit_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_omit_none(item) for item in value]
    return value


def _created_at(manifest: dict[str, Any]) -> str:
    return str(manifest["artifact"]["created_at"])


def _epoch(created_at: str) -> float:
    stamp = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return stamp.timestamp()


def _scanner_block(manifest: dict[str, Any]) -> dict[str, Any]:
    scanner = manifest["scanner"]
    return _omit_none(
        {
            "name": scanner.get("name"),
            "version": scanner.get("version"),
            "repository": scanner.get("repository"),
            "commit": scanner.get("commit"),
            "wheel_sha256": scanner.get("wheel_sha256"),
        }
    )


def _artifact_block(manifest: dict[str, Any]) -> dict[str, Any]:
    artifact = manifest["artifact"]
    return _omit_none(
        {
            "type": artifact.get("type"),
            "sha256": artifact.get("sha256"),
            "bytes": artifact.get("bytes"),
            "fixture": artifact.get("fixture"),
            "description_sha256": artifact.get("description_sha256"),
            "tool_count": artifact.get("tool_count"),
        }
    )


def _execution_block(manifest: dict[str, Any], *, include_exit: bool) -> dict[str, Any]:
    execution = manifest["execution"]
    block = {
        "static_scan": execution.get("static_scan"),
        "target_executed": execution.get("target_executed"),
        "network_required": execution.get("network_required"),
        "llm_used": execution.get("llm_used"),
    }
    if include_exit:
        block["exit_code"] = execution.get("exit_code")
        block["timed_out"] = execution.get("timed_out")
    return _omit_none(block)


def _provenance_block(manifest: dict[str, Any]) -> dict[str, Any]:
    provenance = manifest["provenance"]
    return _omit_none(
        {
            "raw_output_sha256": provenance.get("raw_output_sha256"),
            "adapter_version": provenance.get("adapter_version"),
        }
    )


def _finding_block(row: dict[str, Any]) -> dict[str, Any]:
    return _omit_none(
        {
            "native_rule_id": row.get("native_rule_id"),
            "native_category": row.get("native_category"),
            "native_severity": row.get("native_severity"),
            "native_confidence": row.get("native_confidence"),
            "title": row.get("title"),
            "summary": row.get("summary"),
            "tool_name": row.get("tool_name"),
            "analyzer": row.get("analyzer"),
        }
    )


def _external_and_correlation(
    manifest: dict[str, Any],
    *,
    finding_row: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive contract fields from packs. Unknown values stay omitted."""
    desc = manifest.get("artifact", {}).get("description_sha256")
    provenance = manifest.get("provenance", {})
    scanner = manifest.get("scanner", {})
    artifact = manifest.get("artifact", {})
    external_meta = manifest.get("external") or {}
    evidence_class = external_meta.get("evidence_class") or EVIDENCE_CLASS_FINDING
    native_id = None
    if finding_row:
        native_id = finding_row.get("native_rule_id")
    correlation = _omit_none(
        {
            "method": CORRELATION_METHOD_HASH_JOIN,
            "key": CORRELATION_KEY_DESCRIPTION_CONTENT_HASH,
            "value": desc,
        }
    )
    external = _omit_none(
        {
            "contract.version": external_meta.get("contract.version") or EXTERNAL_CONTRACT_VERSION,
            "evidence_class": evidence_class,
            "producer_class": manifest.get("evidence_class") or PRODUCER_OBSERVED_SCANNER,
            "provider": "cisco-ai-defense",
            "tool": scanner.get("name"),
            "tool_version": scanner.get("version"),
            "native_finding_id": native_id,
            "raw_evidence_ref": provenance.get("raw_artifact"),
            "raw_evidence_sha256": provenance.get("raw_output_sha256"),
            "artifact_fingerprint": desc,
            "artifact_fingerprint_algorithm": FINGERPRINT_ALG_SHA256,
            "subject_type": artifact.get("type"),
            "subject_id": (finding_row or {}).get("tool_name") or artifact.get("fixture"),
        }
    )
    return {"external": external, "correlation": correlation}


def _shared(
    manifest: dict[str, Any],
    *,
    include_exit: bool,
    finding_row: dict[str, Any] | None = None,
) -> dict[str, Any]:
    created_at = _created_at(manifest)
    body = {
        "timestamp": created_at,
        "evidence_class": manifest["evidence_class"],
        "scan_id": manifest["scan_id"],
        "scanner": _scanner_block(manifest),
        "artifact": _artifact_block(manifest),
        "execution": _execution_block(manifest, include_exit=include_exit),
        "provenance": _provenance_block(manifest),
    }
    body.update(_external_and_correlation(manifest, finding_row=finding_row))
    return body


def scan_event_body(manifest: dict[str, Any], findings_doc: dict[str, Any]) -> dict[str, Any]:
    scan: dict[str, Any] = {"finding_count": findings_doc.get("finding_count", manifest.get("finding_count"))}
    classification = findings_doc.get("classification", manifest.get("classification"))
    if classification is not None:
        scan["classification"] = classification
    parse_error = findings_doc.get("parse_error")
    if parse_error:
        scan["parse_error"] = parse_error
    body = _shared(manifest, include_exit=True)
    body["event.name"] = EVENT_SCAN
    body["scan"] = scan
    return body


def finding_event_body(manifest: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    body = _shared(manifest, include_exit=False, finding_row=row)
    body["event.name"] = EVENT_FINDING
    body["finding"] = _finding_block(row)
    return body


def hec_envelope(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": _epoch(str(body["timestamp"])),
        "host": HOST,
        "source": SOURCE,
        "sourcetype": SOURCETYPE,
        "index": INDEX_NAME,
        "event": body,
    }


def events_from_pack(pack: Path) -> list[dict[str, Any]]:
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    findings_doc = json.loads((pack / "normalized" / "findings.json").read_text(encoding="utf-8"))
    if manifest["scan_id"] != findings_doc["scan_id"]:
        raise ValueError(f"scan_id mismatch in {pack}")
    payloads = [hec_envelope(scan_event_body(manifest, findings_doc))]
    for row in findings_doc.get("findings") or []:
        payloads.append(hec_envelope(finding_event_body(manifest, row)))
    return payloads


def events_from_canonical_packs(repo: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for pack in canonical_packs(repo):
        events.extend(events_from_pack(pack))
    return events
