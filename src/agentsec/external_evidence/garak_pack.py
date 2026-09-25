"""Evidence-pack and HEC serialization for garak evaluations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentsec.external_evidence.contract import ExternalEvidence
from agentsec.external_evidence.garak import (
    GARAK_INTEGRATION_CLASS,
    GARAK_LICENSE,
    GARAK_PROVIDER,
    GARAK_REPOSITORY,
    GARAK_TOOL,
    GarakEvaluationAdapter,
    jsonl_bytes,
    read_jsonl,
    sanitize_report_rows,
    sha256_bytes,
)

GARAK_SOURCETYPE = "agentsec:external:evaluation"
GARAK_INDEX = "agentsec_telemetry"
GARAK_SOURCE = "agentsec-external-evaluation-hec"
GARAK_HOST = "agentsec-external-tool"
GARAK_EVENT_NAME = "agentsec.external.evaluation"

RAW_EVIDENCE_REF = "raw/garak-report.jsonl"
NORMALIZED_EVIDENCE_REF = "normalized/evaluations.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _entry(rows: tuple[dict[str, Any], ...], entry_type: str) -> dict[str, Any]:
    return next((row for row in rows if row.get("entry_type") == entry_type), {})


def write_garak_evidence_pack(
    *,
    native_report: Path,
    packs_root: Path,
    repo_root: Path,
    config_ref: str = "tools/garak/agentsec-p1a.yaml",
    ingest_timestamp: str | None = None,
) -> Path:
    """Write a bounded, path-sanitized pack from one native garak report."""
    native_rows = read_jsonl(native_report)
    init = _entry(native_rows, "init")
    native_run_id = init.get("run")
    if not isinstance(native_run_id, str) or not native_run_id:
        raise ValueError("garak report missing native run id")

    pack = packs_root / f"garak-{native_run_id}"
    raw_path = pack / RAW_EVIDENCE_REF
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    (pack / "normalized").mkdir(parents=True, exist_ok=True)

    sanitized_rows = sanitize_report_rows(
        native_rows,
        repo_root=repo_root,
        raw_evidence_ref=RAW_EVIDENCE_REF,
    )
    sanitized_bytes = jsonl_bytes(sanitized_rows)
    raw_path.write_bytes(sanitized_bytes)
    captured_at = ingest_timestamp or _utc_now()
    records = GarakEvaluationAdapter(
        report_path=raw_path,
        raw_evidence_ref=RAW_EVIDENCE_REF,
        ingest_timestamp=captured_at,
    ).records()
    normalized = {
        "contract.version": records[0].contract_version,
        "evidence_class": "evaluation",
        "record_count": len(records),
        "records": [record.to_dict() for record in records],
    }
    (pack / NORMALIZED_EVIDENCE_REF).write_text(
        json.dumps(normalized, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    setup = _entry(sanitized_rows, "start_run setup")
    completion = _entry(sanitized_rows, "completion")
    manifest = {
        "external_contract_version": records[0].contract_version,
        "evidence_class": "evaluation",
        "producer_class": records[0].producer_class,
        "native_evaluation_id": native_run_id,
        "tool": {
            "provider": GARAK_PROVIDER,
            "name": GARAK_TOOL,
            "version": records[0].tool_version,
            "repository": GARAK_REPOSITORY,
            "license": GARAK_LICENSE,
            "integration_class": GARAK_INTEGRATION_CLASS,
        },
        "target": {
            "type": setup.get("plugins.target_type"),
            "model": setup.get("plugins.target_name"),
            "location": "local Ollama",
        },
        "execution": {
            "probe": records[0].extras.get("probe") if records[0].extras else None,
            "detector": records[0].extras.get("detector") if records[0].extras else None,
            "generations": setup.get("run.generations"),
            "seed": setup.get("run.seed"),
            "started_at": init.get("start_time"),
            "completed_at": completion.get("end_time"),
            "configuration_ref": config_ref,
        },
        "provenance": {
            "raw_evidence_ref": RAW_EVIDENCE_REF,
            "raw_evidence_sha256": sha256_bytes(sanitized_bytes),
            "source_raw_sha256_before_path_sanitization": sha256_bytes(
                native_report.read_bytes()
            ),
            "path_sanitization": "host-absolute paths replaced; native result fields unchanged",
            "normalized_evidence_ref": NORMALIZED_EVIDENCE_REF,
        },
        "limitations": [
            "One local model, one probe, one generation, and one detector.",
            "Passing this evaluation does not establish that the model is safe.",
            "The model response is not AgentSec runtime tool execution.",
            "garak is not CTRL-MCP-001, Splunk, or AgentSec.",
            "No agentsec.run.id was produced or inherited.",
        ],
    }
    (pack / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return pack


def records_from_pack(pack: Path) -> tuple[ExternalEvidence, ...]:
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    raw_ref = manifest["provenance"]["raw_evidence_ref"]
    timestamp = json.loads(
        (pack / NORMALIZED_EVIDENCE_REF).read_text(encoding="utf-8")
    )["records"][0].get("ingest_timestamp")
    return GarakEvaluationAdapter(
        report_path=pack / raw_ref,
        raw_evidence_ref=raw_ref,
        ingest_timestamp=timestamp,
    ).records()


def _epoch(timestamp: str) -> float:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


def _native_result(native: dict[str, Any]) -> str:
    total = native.get("total_evaluated")
    fails = native.get("fails")
    if isinstance(total, int) and total > 0 and fails == 0:
        return "PASS"
    if isinstance(fails, int) and fails > 0:
        return "FAIL"
    return "UNKNOWN"


def hec_event(record: ExternalEvidence) -> dict[str, Any]:
    body = record.to_dict()
    native = body.get("native", {})
    timestamp = record.source_timestamp or record.ingest_timestamp
    if not timestamp:
        raise ValueError("external evaluation has no timestamp")
    event = {
        "timestamp": timestamp,
        "event.name": GARAK_EVENT_NAME,
        "external": body,
        "evaluation": {
            "native_result": _native_result(native),
            "probe": native.get("probe"),
            "detector": native.get("detector"),
            "passed": native.get("passed"),
            "fails": native.get("fails"),
            "nones": native.get("nones"),
            "total_evaluated": native.get("total_evaluated"),
        },
        "correlation": body.get("correlation", {}),
        "provenance": {
            "raw_evidence_ref": record.raw_evidence_ref,
            "raw_evidence_sha256": record.raw_evidence_sha256,
        },
    }
    return {
        "time": _epoch(timestamp),
        "host": GARAK_HOST,
        "source": GARAK_SOURCE,
        "sourcetype": GARAK_SOURCETYPE,
        "index": GARAK_INDEX,
        "event": event,
    }


def events_from_pack(pack: Path) -> list[dict[str, Any]]:
    return [hec_event(record) for record in records_from_pack(pack)]
