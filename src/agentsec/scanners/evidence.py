"""Write scanner evidence packs. Never fabricates agentsec.run.id."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from agentsec.scanners.adapter import classify_malicious_scan, parse_scanner_stdout
from agentsec.scanners.catalog_export import sha256_bytes, write_catalog_artifact
from agentsec.scanners.cisco_mcp_scanner import run_static_yara_scan, scanner_identity
from agentsec.external_evidence.cisco import cisco_normalized_to_external
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.scanners.models import (
    ADAPTER_VERSION,
    ARTIFACT_TYPE_MCP_CATALOG,
    EVIDENCE_CLASS,
    SCANNER_FINDING_IS_NOT_AUTHZ,
    ArtifactIdentity,
    NativeFinding,
    NormalizedScan,
    ScanProcessResult,
)

PACK_ARTIFACT_REF = "input/tools.json"
PACK_RAW_REF = "raw/scanner-output.json"


def sanitize_pack_argv(argv: tuple[str, ...], binary: str) -> tuple[list[str], str]:
    """Committed packs store CLI names, not host-absolute paths."""
    cli_name = Path(binary).name if binary else "mcp-scanner"
    cleaned: list[str] = []
    for arg in argv:
        if arg.endswith("tools.json"):
            cleaned.append(PACK_ARTIFACT_REF)
        elif arg.startswith("/") or (len(arg) > 1 and arg[1] == ":"):
            cleaned.append(Path(arg).name)
        else:
            cleaned.append(arg)
    return cleaned, cli_name


def new_scan_id() -> str:
    return str(uuid4())


def _finding_dict(row: NativeFinding) -> dict[str, Any]:
    payload = {
        "native_rule_id": row.native_rule_id,
        "native_category": row.native_category,
        "native_severity": row.native_severity,
        "native_confidence": row.native_confidence,
        "title": row.title,
        "summary": row.summary,
        "tool_name": row.tool_name,
        "analyzer": row.analyzer,
    }
    return {key: value for key, value in payload.items() if value is not None}


def normalize_scan(
    *,
    scan_id: str,
    artifact: ArtifactIdentity,
    process: ScanProcessResult,
    identity=None,
) -> NormalizedScan:
    pin_identity = identity or scanner_identity()
    findings, parse_error = parse_scanner_stdout(process.stdout)
    unsupported = parse_error == "unsupported_static_input"
    classification = classify_malicious_scan(
        fixture=artifact.fixture,
        timed_out=process.timed_out,
        exit_code=process.exit_code,
        parse_error=parse_error,
        findings=findings,
        unsupported=unsupported,
    )
    limitations = [
        SCANNER_FINDING_IS_NOT_AUTHZ,
        "Scanner PASS != trusted.",
        "Scanner FAIL != DENY.",
        "Scanner silence != safe.",
        "Network isolation is not technically guaranteed on this host; canonical argv is YARA-static with secrets stripped from the child environment.",
        "artifact.sha256 hashes the exported JSON file. description_sha256 hashes lookup_policy description UTF-8 bytes only.",
        "No schema 1.9.0 change. No runtime authorization change.",
    ]
    if process.timed_out:
        limitations.append("Scanner process timed out.")
    if parse_error:
        limitations.append(f"Parse limitation: {parse_error}")
    if b"server_url" in process.stdout:
        limitations.append(
            "Scanner JSON may include a default server_url field. Canonical argv did not pass --server-url and did not start MCP. This field is scanner-native output, not AgentSec runtime connection evidence."
        )
    return NormalizedScan(
        scan_id=scan_id,
        evidence_class=EVIDENCE_CLASS,
        scanner=pin_identity,
        artifact=artifact,
        findings=findings,
        classification=classification,
        static_scan=True,
        target_executed=False,
        network_required=False,
        llm_used=False,
        exit_code=process.exit_code,
        timed_out=process.timed_out,
        parse_error=parse_error,
        raw_output_sha256=sha256_bytes(process.stdout),
        adapter_version=ADAPTER_VERSION,
        stdout_sha256=sha256_bytes(process.stdout),
        stderr_sha256=sha256_bytes(process.stderr),
        finding_count=len(findings),
        limitations=tuple(limitations),
    )


def write_scan_bundle(
    root: Path,
    *,
    scan_id: str,
    fixture: str,
    process: ScanProcessResult,
    artifact: ArtifactIdentity,
    input_bytes: bytes,
    normalized: NormalizedScan,
) -> Path:
    pack = root / scan_id
    (pack / "input").mkdir(parents=True, exist_ok=True)
    (pack / "raw").mkdir(parents=True, exist_ok=True)
    (pack / "normalized").mkdir(parents=True, exist_ok=True)
    (pack / "input" / "tools.json").write_bytes(input_bytes)
    (pack / "raw" / "scanner-output.json").write_bytes(process.stdout)
    (pack / "raw" / "stdout.txt").write_bytes(process.stdout)
    (pack / "raw" / "stderr.txt").write_bytes(process.stderr)
    external_records = [row.to_dict() for row in cisco_normalized_to_external(normalized)]
    pack_argv, pack_binary = sanitize_pack_argv(process.argv, process.binary)
    findings_doc = {
        "scan_id": scan_id,
        "evidence_class": EVIDENCE_CLASS,
        "external_contract_version": EXTERNAL_CONTRACT_VERSION,
        "external_evidence_class": "finding",
        "classification": normalized.classification,
        "finding_count": normalized.finding_count,
        "findings": [_finding_dict(row) for row in normalized.findings],
        "external_evidence": external_records,
        "parse_error": normalized.parse_error,
        "adapter_version": ADAPTER_VERSION,
    }
    (pack / "normalized" / "findings.json").write_text(
        json.dumps(findings_doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "scan_id": scan_id,
        "evidence_class": EVIDENCE_CLASS,
        "boundary": SCANNER_FINDING_IS_NOT_AUTHZ,
        "agentsec.run.id": None,
        "scanner": {
            "name": normalized.scanner.name,
            "version": normalized.scanner.version,
            "repository": normalized.scanner.repository,
            "commit": normalized.scanner.commit,
            "license": normalized.scanner.license,
            "package": normalized.scanner.package,
            "wheel_sha256": normalized.scanner.wheel_sha256,
        },
        "artifact": {
            "type": ARTIFACT_TYPE_MCP_CATALOG,
            "path": PACK_ARTIFACT_REF,
            "sha256": artifact.sha256,
            "bytes": artifact.bytes_len,
            "fixture": artifact.fixture,
            "created_at": artifact.created_at,
            "description_sha256": artifact.description_sha256,
            "tool_count": artifact.tool_count,
        },
        "execution": {
            "static_scan": True,
            "target_executed": False,
            "network_required": False,
            "llm_used": False,
            "argv": pack_argv,
            "exit_code": process.exit_code,
            "timed_out": process.timed_out,
            "duration_ms": process.duration_ms,
            "binary": pack_binary,
        },
        "external": {
            "contract.version": EXTERNAL_CONTRACT_VERSION,
            "evidence_class": "finding",
            "producer_class": EVIDENCE_CLASS,
            "records": external_records,
        },
        "provenance": {
            "raw_artifact": PACK_RAW_REF,
            "raw_output_sha256": normalized.raw_output_sha256,
            "stdout_sha256": normalized.stdout_sha256,
            "stderr_sha256": normalized.stderr_sha256,
            "adapter_version": ADAPTER_VERSION,
        },
        "classification": normalized.classification,
        "finding_count": normalized.finding_count,
    }
    (pack / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (pack / "limitations.json").write_text(
        json.dumps({"items": list(normalized.limitations)}, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    return pack


def export_and_scan_fixture(
    *,
    fixture: str,
    packs_root: Path,
    scan_id: str | None = None,
    timeout_sec: int = 60,
    binary: Path | str | None = None,
) -> tuple[Path, NormalizedScan]:
    sid = scan_id or new_scan_id()
    pack_dir = packs_root / sid
    input_path = pack_dir / "input" / "tools.json"
    data, artifact = write_catalog_artifact(input_path, fixture)
    process = run_static_yara_scan(input_path, binary=binary, timeout_sec=timeout_sec)
    normalized = normalize_scan(scan_id=sid, artifact=artifact, process=process)
    pack = write_scan_bundle(
        packs_root,
        scan_id=sid,
        fixture=fixture,
        process=process,
        artifact=artifact,
        input_bytes=data,
        normalized=normalized,
    )
    return pack, normalized
