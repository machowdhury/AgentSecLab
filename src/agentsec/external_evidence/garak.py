"""garak adapter for the ExternalEvidence 1.0.0 contract.

garak is an independently maintained adversarial AI evaluation tool. This
adapter reads its documented JSONL report; it does not run garak or authorize
AgentSec operations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from agentsec.external_evidence.contract import (
    EVIDENCE_CLASS_EVALUATION,
    EXTERNAL_CONTRACT_VERSION,
    FINGERPRINT_ALG_SHA256,
    ExternalEvidence,
)

GARAK_PROVIDER = "NVIDIA"
GARAK_TOOL = "garak"
GARAK_LICENSE = "Apache-2.0"
GARAK_REPOSITORY = "https://github.com/NVIDIA/garak"
GARAK_INTEGRATION_CLASS = "external adversarial evaluation"
GARAK_PRODUCER_CLASS = "OBSERVED_EXTERNAL_EVALUATION"

GARAK_ARTIFACT_TYPE = "garak.report.jsonl"
GARAK_CORRELATION_METHOD = "identity_tuple"
GARAK_CORRELATION_KEY = "garak.run/probe/detector/model"


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_jsonl(path: Path) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid garak JSONL at line {line_number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"garak JSONL line {line_number} is not an object")
        rows.append(row)
    return tuple(rows)


def _first(rows: Iterable[dict[str, Any]], entry_type: str) -> dict[str, Any] | None:
    return next((row for row in rows if row.get("entry_type") == entry_type), None)


def _probe_tags(rows: Iterable[dict[str, Any]], probe: str) -> tuple[str, ...]:
    cache = _first(rows, "plugin_cache") or {}
    probe_cache = cache.get("plugin_cache", {}).get("probes", {})
    metadata = probe_cache.get(f"probes.{probe}", {})
    tags = metadata.get("tags")
    if not isinstance(tags, list):
        return ()
    return tuple(str(tag) for tag in tags if isinstance(tag, str))


def _framework_mappings(tags: tuple[str, ...]) -> tuple[str, ...]:
    # Preserve only mappings emitted by garak itself. AgentSec does not infer
    # framework coverage from a probe name.
    return tuple(tag for tag in tags if tag.startswith(("owasp:", "avid-effect:")))


def _safe_relative_path(value: str, repo_root: Path) -> str:
    path = Path(value)
    if not path.is_absolute():
        return value
    try:
        relative = path.relative_to(repo_root)
    except ValueError:
        return path.name
    if ".venv" in relative.parts and "garak" in relative.parts:
        try:
            index = relative.parts.index("garak", relative.parts.index(".venv") + 1)
            return str(Path(*relative.parts[index:]))
        except ValueError:
            return path.name
    return str(relative)


def sanitize_report_rows(
    rows: tuple[dict[str, Any], ...],
    *,
    repo_root: Path,
    raw_evidence_ref: str,
) -> tuple[dict[str, Any], ...]:
    """Remove host-absolute paths while preserving native garak semantics."""

    def clean(value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {name: clean(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [clean(item, key) for item in value]
        if isinstance(value, str) and value.startswith("/"):
            if key in {"transient.report_filename", "reportfile"} or value.endswith(
                ".report.jsonl"
            ):
                return raw_evidence_ref
            return _safe_relative_path(value, repo_root)
        return value

    return tuple(clean(row) for row in rows)


def jsonl_bytes(rows: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        for row in rows
    )


@dataclass(frozen=True)
class GarakEvaluationAdapter:
    """Normalize native garak eval rows without changing their pass/fail meaning."""

    report_path: Path
    raw_evidence_ref: str
    ingest_timestamp: str | None = None

    provider: str = GARAK_PROVIDER
    tool: str = GARAK_TOOL

    def records(self) -> tuple[ExternalEvidence, ...]:
        rows = read_jsonl(self.report_path)
        setup = _first(rows, "start_run setup") or {}
        init = _first(rows, "init") or {}
        run_id = init.get("run")
        tool_version = init.get("garak_version") or setup.get("_config.version")
        source_timestamp = init.get("start_time") or setup.get("transient.starttime_iso")
        target_type = setup.get("plugins.target_type")
        target_name = setup.get("plugins.target_name")
        if not all(isinstance(value, str) and value for value in (run_id, tool_version)):
            raise ValueError("garak report missing native run id or tool version")

        raw_sha256 = sha256_bytes(self.report_path.read_bytes())
        records: list[ExternalEvidence] = []
        for row in rows:
            if row.get("entry_type") != "eval":
                continue
            probe = row.get("probe")
            detector = row.get("detector")
            if not isinstance(probe, str) or not isinstance(detector, str):
                raise ValueError("garak eval row missing probe or detector")
            tags = _probe_tags(rows, probe)
            identity = f"{run_id}|{probe}|{detector}|{target_name or 'unknown-model'}"
            passed = row.get("passed")
            fails = row.get("fails")
            total = row.get("total_evaluated")
            records.append(
                ExternalEvidence(
                    evidence_class=EVIDENCE_CLASS_EVALUATION,
                    evidence_id=f"{run_id}|{probe}|{detector}",
                    provider=self.provider,
                    tool=self.tool,
                    tool_version=tool_version,
                    subject_type="model",
                    subject_id=target_name,
                    subject_name=target_name,
                    title=f"garak {probe} / {detector} evaluation",
                    description=(
                        f"Native garak result: passed={passed}, fails={fails}, "
                        f"total_evaluated={total}."
                    ),
                    artifact_type=GARAK_ARTIFACT_TYPE,
                    artifact_fingerprint=raw_sha256,
                    artifact_fingerprint_algorithm=FINGERPRINT_ALG_SHA256,
                    correlation_method=GARAK_CORRELATION_METHOD,
                    correlation_key=GARAK_CORRELATION_KEY,
                    correlation_value=identity,
                    framework_mappings=_framework_mappings(tags),
                    source_timestamp=source_timestamp,
                    ingest_timestamp=self.ingest_timestamp,
                    raw_evidence_ref=self.raw_evidence_ref,
                    raw_evidence_sha256=raw_sha256,
                    producer_class=GARAK_PRODUCER_CLASS,
                    contract_version=EXTERNAL_CONTRACT_VERSION,
                    extras={
                        "garak_run_id": run_id,
                        "target_type": target_type,
                        "target_name": target_name,
                        "probe": probe,
                        "detector": detector,
                        "passed": passed,
                        "fails": fails,
                        "nones": row.get("nones"),
                        "total_evaluated": total,
                        "total_processed": row.get("total_processed"),
                        "intents": row.get("intents"),
                        "probe_tags": list(tags),
                    },
                )
            )
        if not records:
            raise ValueError("garak report contains no eval rows")
        return tuple(records)
