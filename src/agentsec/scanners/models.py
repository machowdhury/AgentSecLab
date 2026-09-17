"""Scanner evidence types. Separate from agentsec.security_event 1.5.0."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ADAPTER_VERSION = "9b.1"
EVIDENCE_CLASS = "OBSERVED_SCANNER"
SCANNER_FINDING_IS_NOT_AUTHZ = "SCANNER FINDING != AUTHORIZATION DECISION"
ARTIFACT_TYPE_MCP_CATALOG = "mcp.catalog.snapshot"

CLASS_DETECTED = "DETECTED_BY_SCANNER"
CLASS_NOT_DETECTED = "NOT_DETECTED_BY_SCANNER"
CLASS_ERROR = "SCANNER_ERROR"
CLASS_UNSUPPORTED = "UNSUPPORTED"

MAX_OUTPUT_BYTES = 2_000_000
MAX_FINDINGS = 500
MAX_STRING = 2000
DEFAULT_TIMEOUT_SEC = 60


@dataclass(frozen=True)
class ScannerIdentity:
    name: str
    version: str
    repository: str
    commit: str
    license: str
    package: str
    cli: str
    wheel_sha256: str | None = None


@dataclass(frozen=True)
class ArtifactIdentity:
    path: str
    sha256: str
    bytes_len: int
    fixture: str
    created_at: str
    description_sha256: str
    tool_count: int


@dataclass(frozen=True)
class ScanProcessResult:
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    duration_ms: int
    binary: str


@dataclass(frozen=True)
class NativeFinding:
    """Fields copied from scanner output when present. Never invented."""

    native_rule_id: str | None
    native_category: str | None
    native_severity: str | None
    native_confidence: str | None
    title: str | None
    summary: str | None
    tool_name: str | None
    analyzer: str | None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedScan:
    scan_id: str
    evidence_class: str
    scanner: ScannerIdentity
    artifact: ArtifactIdentity
    findings: tuple[NativeFinding, ...]
    classification: str | None
    static_scan: bool
    target_executed: bool
    network_required: bool
    llm_used: bool
    exit_code: int | None
    timed_out: bool
    parse_error: str | None
    raw_output_sha256: str
    adapter_version: str
    stdout_sha256: str
    stderr_sha256: str
    finding_count: int
    limitations: tuple[str, ...]
