"""Orchestrate allowlisted PI launches. Does not evaluate CTRL-* decisions."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agentsec.evidence_readiness import (
    count_local_events,
    env_interval,
    env_timeout,
    read_export_doc,
    wait_for_searchable_evidence,
)
from agentsec.experiment_context import ExperimentContext, lookup_experiment, ROUTE_MCP
from agentsec.lab_manifest import load_lab_manifest, prediction_for
from agentsec.launch_catalog import (
    RETEST_SUPPORT,
    known_lab_ids,
    known_specimen_ids,
    lookup_launch,
)
from agentsec.launch_contract import ParsedLaunchRequest
from agentsec.search_handoff import DEFAULT_SPLUNK_WEB, handoff_doc, pair_handoff_doc
from agentsec.settings import Settings

logger = logging.getLogger("agentsec.attack.launch")

STATE_REQUESTED = "REQUESTED"
STATE_RUNNING = "RUNNING"
STATE_TELEMETRY_SENT = "TELEMETRY_SENT"
STATE_WAITING = "WAITING_FOR_EVIDENCE"
STATE_READY = "EVIDENCE_READY"
STATE_ERROR = "ERROR"


def error_body(
    error: str,
    *,
    http_status: int = 400,
    parsed: ParsedLaunchRequest | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[int, dict]:
    body: dict[str, Any] = {
        "error": error,
        "error_class": "ERROR",
        "evidence_state": STATE_ERROR,
        "detail": _DETAIL.get(error, "Launch request was rejected."),
    }
    if parsed is not None:
        body["lab_id"] = parsed.lab_id
        body["specimen_id"] = parsed.specimen_id
        body["profile"] = parsed.profile
        body["mode"] = parsed.mode
        body["execution"] = parsed.execution
        if parsed.extra_fields:
            body["extra_fields"] = list(parsed.extra_fields)
    if extra:
        body.update(extra)
    return http_status, body


_DETAIL = {
    "malformed_request": "Body is not closed JSON with the launch fields.",
    "duplicate_json_keys": "Duplicate JSON keys are ERROR, not last-wins.",
    "unknown_fields": "Unknown fields are rejected. Attack Service is not a generic proxy.",
    "unknown_lab": "lab_id is not in the Attack Service allowlist.",
    "unknown_specimen": "specimen_id is not allowlisted for this lab.",
    "unknown_profile": "profile must be defended or vulnerable.",
    "unknown_mode": "mode must be BASELINE, ATTACK, or RETEST.",
    "unknown_execution": "execution must be live. Replay is not a launch.",
    "not_allowlisted": "That lab/specimen/mode/execution tuple is not allowlisted.",
    "unknown_experiment": "experiment_id is not a predefined Attack Service specimen.",
    "malformed_experiment": "experiment selection is malformed. This is ERROR, not a vulnerable fallback.",
    "runtime_unreachable": "AcmeBank was not reachable. This is not a control DENY.",
    "runtime_exception": "The runtime call failed. This is not a control DENY.",
    "intentionally_skipped": "Launch was not sent to the runtime.",
    "malformed_compare": "Compare handoff requires two distinct UUID run.ids. It does not accept learner SPL.",
}


@dataclass
class LaunchRecord:
    run_id: str | None
    lab_id: str
    specimen_id: str
    profile: str
    mode: str
    execution_mode: str
    evidence_state: str
    lifecycle: list[str] = field(default_factory=list)
    body: dict = field(default_factory=dict)
    created_monotonic: float = field(default_factory=time.monotonic)


class LaunchService:
    def __init__(
        self,
        client: Any,
        settings: Settings,
        *,
        artifacts_dir: Path | None = None,
        splunk_web: str | None = None,
        probe_fn: Callable[[str], dict] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        lock: threading.Lock | None = None,
    ) -> None:
        self.client = client
        self.settings = settings
        self.artifacts_dir = Path(artifacts_dir or settings.artifacts_dir)
        self.splunk_web = splunk_web or os.environ.get("AGENTSEC_SPLUNK_WEB_URL", DEFAULT_SPLUNK_WEB)
        self.probe_fn = probe_fn
        self.sleep_fn = sleep_fn
        self._lock = lock or threading.Lock()
        self._records: dict[str, LaunchRecord] = {}

    def launch(self, parsed: ParsedLaunchRequest) -> tuple[int, dict]:
        if not parsed.ok:
            return error_body(parsed.error_reason, parsed=parsed)

        if parsed.lab_id not in known_lab_ids():
            return error_body("unknown_lab", parsed=parsed)
        if parsed.specimen_id not in known_specimen_ids(parsed.lab_id or ""):
            return error_body("unknown_specimen", parsed=parsed)

        row = lookup_launch(
            lab_id=parsed.lab_id or "",
            specimen_id=parsed.specimen_id or "",
            mode=parsed.mode or "",
            execution=parsed.execution or "",
        )
        if row is None:
            return error_body("not_allowlisted", parsed=parsed)

        return self._launch(parsed, row)

    def _launch(self, parsed: ParsedLaunchRequest, row: Any) -> tuple[int, dict]:
        health_status, health = _as_status_body(self.client.health())
        if health_status >= 500 or not isinstance(health, dict) or health.get("error"):
            return error_body("runtime_unreachable", parsed=parsed, http_status=503)

        record = LaunchRecord(
            run_id=None,
            lab_id=row.lab_id,
            specimen_id=row.specimen_id,
            profile=row.profile,
            mode=row.mode,
            execution_mode="LIVE",
            evidence_state=STATE_REQUESTED,
            lifecycle=[STATE_REQUESTED],
        )
        logger.info(
            "launch requested lab_id=%s specimen_id=%s profile=%s mode=%s experiment_id=%s",
            row.lab_id,
            row.specimen_id,
            row.profile,
            row.mode,
            row.experiment_id,
        )

        record.evidence_state = STATE_RUNNING
        record.lifecycle.append(STATE_RUNNING)
        definition = lookup_experiment(row.experiment_id)
        if definition is None:
            return error_body("unknown_experiment", parsed=parsed)
        ctx = ExperimentContext.from_definition(definition)
        if definition.runtime_route == ROUTE_MCP:
            payload = {
                "tool": definition.tool,
                "requested_scope": definition.requested_scope,
                "arguments": json.loads(definition.arguments_json),
                "user_id": row.user_id,
                "experiment_id": row.experiment_id,
            }
            try:
                status, data = self.client.mcp_invoke(payload)
            except Exception as exc:  # pragma: no cover - defensive
                logger.info("launch mcp runtime exception type=%s", type(exc).__name__)
                return error_body("runtime_exception", parsed=parsed, http_status=503)
        else:
            payload = {
                "input": row.payload,
                "user_id": row.user_id,
                "experiment_id": row.experiment_id,
            }
            try:
                status, data = self.client.process(payload)
            except Exception as exc:  # pragma: no cover - defensive
                logger.info("launch runtime exception type=%s", type(exc).__name__)
                return error_body("runtime_exception", parsed=parsed, http_status=503)

        if not isinstance(data, dict):
            return error_body("runtime_exception", parsed=parsed, http_status=503)
        if status >= 500 and not data.get("run_id"):
            return error_body(
                "runtime_unreachable" if status == 503 and data.get("error") else "runtime_exception",
                parsed=parsed,
                http_status=status,
                extra={"runtime": _public_runtime(data)},
            )

        run_id = data.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            return error_body(
                "runtime_exception",
                parsed=parsed,
                http_status=503,
                extra={"runtime": _public_runtime(data)},
            )

        local_count = count_local_events(self.artifacts_dir, run_id)
        export_doc = read_export_doc(self.artifacts_dir, run_id) or {}
        record.run_id = run_id
        record.evidence_state = STATE_TELEMETRY_SENT
        record.lifecycle.append(STATE_TELEMETRY_SENT)
        record.evidence_state = STATE_WAITING
        record.lifecycle.append(STATE_WAITING)

        prediction = prediction_for(row.lab_id, row.mode) or {}
        try:
            manifest = load_lab_manifest(row.lab_id)
        except FileNotFoundError:
            manifest = {}

        body = {
            "run_id": run_id,
            "lab_id": row.lab_id,
            "specimen_id": row.specimen_id,
            "experiment_id": row.experiment_id,
            "profile": row.profile,
            "mode": row.mode,
            "execution_mode": "LIVE",
            "telemetry_fidelity": data.get("telemetry_fidelity") or "OBSERVED",
            "runtime_status": "COMPLETED" if status < 500 else "ERROR",
            "evidence_state": STATE_WAITING,
            "lifecycle": list(record.lifecycle),
            "local_event_count": local_count,
            "splunk_verified": False,
            "intentionally_vulnerable": row.intentionally_vulnerable,
            "retest_support": RETEST_SUPPORT,
            "input_fingerprint": ctx.input_fingerprint,
            "otlp.ok": export_doc.get("otlp.ok"),
            "hec.ok": export_doc.get("hec.ok"),
            "search_handoff": handoff_doc(run_id, lab_id=row.lab_id, splunk_web=self.splunk_web),
            "prediction": prediction,
            "security_question": manifest.get("security_question"),
            "runtime": _public_runtime(data),
            "http_status_from_runtime": status,
            "note": (
                "Control DENY/ALLOW is in runtime hops, not this HTTP error class. "
                "WAITING_FOR_EVIDENCE is the honest default. HEC/OTLP success is not Splunk. "
                "Profile is server-owned ExperimentContext, not browser JSON."
            ),
        }
        if row.intentionally_vulnerable:
            body["vulnerable_label"] = "INTENTIONALLY VULNERABLE LAB PROFILE"
        record.body = body
        with self._lock:
            self._records[run_id] = record
        logger.info(
            "launch finished lab_id=%s specimen_id=%s run_id=%s evidence_state=%s",
            row.lab_id,
            row.specimen_id,
            run_id,
            STATE_WAITING,
        )
        return 200, body

    def get_record(self, run_id: str) -> LaunchRecord | None:
        with self._lock:
            return self._records.get(run_id)

    def compare_handoff(self, attack_run_id: str, retest_run_id: str) -> tuple[int, dict]:
        if not _is_uuid(attack_run_id) or not _is_uuid(retest_run_id) or attack_run_id == retest_run_id:
            return error_body("malformed_compare")
        return 200, pair_handoff_doc(attack_run_id, retest_run_id, splunk_web=self.splunk_web)

    def probe_evidence(self, run_id: str, *, timeout_seconds: int | None = None) -> tuple[int, dict]:
        record = self.get_record(run_id)
        if record is None:
            return 404, {
                "error": "unknown_run",
                "error_class": "ERROR",
                "evidence_state": STATE_ERROR,
                "detail": "No in-memory launch record for that run.id. This service does not invent Splunk rows.",
            }
        timeout = env_timeout() if timeout_seconds is None else timeout_seconds
        result = wait_for_searchable_evidence(
            run_id,
            artifacts_dir=self.artifacts_dir,
            timeout_seconds=timeout,
            interval_seconds=env_interval(),
            probe_fn=self.probe_fn,
            sleep_fn=self.sleep_fn,
        )
        record.evidence_state = result["evidence_state"]
        if result["evidence_state"] == STATE_READY and STATE_READY not in record.lifecycle:
            record.lifecycle.append(STATE_READY)
        result["lab_id"] = record.lab_id
        result["specimen_id"] = record.specimen_id
        result["mode"] = record.mode
        result["profile"] = record.profile
        result["lifecycle"] = list(record.lifecycle)
        result["splunk_verified"] = bool(result.get("splunk_verified"))
        if record.body:
            record.body["evidence_state"] = record.evidence_state
            record.body["splunk_verified"] = result["splunk_verified"]
            record.body["local_event_count"] = result.get("local_event_count")
        return 200, result


def _as_status_body(result: object) -> tuple[int, dict]:
    if isinstance(result, tuple) and len(result) == 2:
        status, data = result
        return int(status), data if isinstance(data, dict) else {"error": "non_json"}
    return 503, {"error": "health_unavailable"}


def _public_runtime(data: dict) -> dict:
    keys = (
        "run_id",
        "incident_id",
        "attack_id",
        "profile",
        "testbed_mode",
        "execution_mode",
        "telemetry_fidelity",
        "blocked",
        "block_reason",
        "terminal",
        "llm_call_count",
        "expected_behavior",
        "actual_behavior",
        "schema_version",
        "error_stage",
        "handler_invoke_count",
        "experiment_id",
        "input_fingerprint",
        "hops",
    )
    return {key: data[key] for key in keys if key in data}


_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _is_uuid(value: str) -> bool:
    return bool(value) and bool(_UUID.fullmatch(value))
