"""Event sinks: memory (tests/evidence) and optional OTLP logs to the collector."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Protocol

from agentsec.schema import validate_event
from agentsec.settings import Settings, get_settings

logger = logging.getLogger("agentsec.telemetry")

OTLP_OK_DOES_NOT_MEAN = (
    "otlp.ok means the OpenTelemetry SDK accepted emit + force_flush. "
    "It does NOT mean the collector received the batch, HEC accepted it, "
    "Splunk indexed it, or Splunk was verified. "
    "collector/HEC/Splunk remain NOT VERIFIED unless independently observed. "
    "Never infer downstream success from OTLP flush success."
)


@dataclass
class ExportReport:
    """Layered export status. Each layer is independent. Runtime never fills Splunk."""

    otlp_enabled: bool = False
    otlp_init_ok: bool = False
    otlp_attempted: bool = False
    otlp_emit_count: int = 0
    otlp_emit_errors: int = 0
    otlp_dropped: int = 0
    otlp_flush_attempted: bool = False
    otlp_flush_ok: bool = False
    otlp_endpoint: str | None = None
    otlp_init_error: str | None = None
    otlp_last_error: str | None = None

    @property
    def otlp_ok(self) -> bool:
        return (
            self.otlp_enabled
            and self.otlp_init_ok
            and self.otlp_attempted
            and self.otlp_emit_errors == 0
            and self.otlp_dropped == 0
            and self.otlp_flush_attempted
            and self.otlp_flush_ok
        )

    def to_export_doc(self) -> dict:
        return {
            "otlp.enabled": self.otlp_enabled,
            "otlp.init_ok": self.otlp_init_ok,
            "otlp.attempted": self.otlp_attempted,
            "otlp.emit_count": self.otlp_emit_count,
            "otlp.emit_errors": self.otlp_emit_errors,
            "otlp.dropped": self.otlp_dropped,
            "otlp.flush_attempted": self.otlp_flush_attempted,
            "otlp.flush_ok": self.otlp_flush_ok,
            "otlp.ok": self.otlp_ok,
            "otlp.endpoint": self.otlp_endpoint,
            "otlp.init_error": self.otlp_init_error,
            "otlp.last_error": self.otlp_last_error,
            "collector.observed": False,
            "hec.attempted": False,
            "hec.ok": False,
            "splunk.attempted": False,
            "splunk.ok": False,
            "splunk.verified": False,
            "layers": {
                "otlp": {
                    "enabled": self.otlp_enabled,
                    "init_ok": self.otlp_init_ok,
                    "attempted": self.otlp_attempted,
                    "ok": self.otlp_ok,
                    "flush_ok": self.otlp_flush_ok,
                    "meaning": "SDK emit+flush only",
                },
                "collector": {
                    "observed": False,
                    "meaning": "Not observed by AcmeBank. Requires collector file or metrics.",
                },
                "hec": {
                    "attempted": False,
                    "ok": False,
                    "meaning": "Not observed by AcmeBank. OTLP flush is not HEC success.",
                },
                "splunk": {
                    "attempted": False,
                    "ok": False,
                    "verified": False,
                    "meaning": "NOT VERIFIED by runtime. Requires an independent Splunk search.",
                },
            },
            "note": OTLP_OK_DOES_NOT_MEAN,
        }

    @classmethod
    def not_attempted(cls) -> ExportReport:
        return cls()


class EventSink(Protocol):
    def emit(self, event: dict) -> None: ...


class MemorySink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        validate_event(event)
        self.events.append(event)


class FanoutSink:
    def __init__(self, sinks: list[EventSink]) -> None:
        self.sinks = sinks

    def emit(self, event: dict) -> None:
        for sink in self.sinks:
            sink.emit(event)

    def force_flush(self, timeout_millis: int = 10_000) -> ExportReport:
        reports: list[ExportReport] = []
        for sink in self.sinks:
            flush = getattr(sink, "force_flush", None)
            if callable(flush):
                reports.append(flush(timeout_millis))
        if not reports:
            return ExportReport.not_attempted()
        return reports[-1]


class OtlpSink:
    """Best-effort OTLP logs export. Flush success is not Splunk success."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._provider = None
        self._logger = None
        self._resource = None
        self._init_ok = False
        self._init_error: str | None = None
        self.export_errors = 0
        self.emit_errors = 0
        self.emit_count = 0
        self.dropped_count = 0
        self.attempted = False
        self._flush_attempted = False
        self._flush_ok = False
        self._last_error: str | None = None
        if self.settings.otel_enabled:
            self._init_provider()

    def _endpoint(self) -> str:
        return f"{self.settings.otel_collector_http}/v1/logs"

    def _init_provider(self) -> None:
        try:
            from opentelemetry._logs import set_logger_provider
            from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
            from opentelemetry.sdk._logs import LoggerProvider
            from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
            from opentelemetry.sdk.resources import Resource

            self._resource = Resource.create(
                {
                    "service.name": self.settings.service_name,
                    "service.version": self.settings.version,
                    "deployment.environment": self.settings.deployment_environment,
                }
            )
            provider = LoggerProvider(resource=self._resource)
            exporter = OTLPLogExporter(endpoint=self._endpoint())
            provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
            set_logger_provider(provider)
            self._provider = provider
            self._logger = provider.get_logger("agentsec.telemetry", self.settings.version)
            self._init_ok = True
        except Exception as exc:  # pragma: no cover - import/collector wiring
            self._init_ok = False
            self._init_error = str(exc)
            self._last_error = str(exc)
            self.export_errors += 1
            self._provider = None
            self._logger = None
            logger.warning("OTLP log exporter not initialized: %s", exc)

    def report(self) -> ExportReport:
        return ExportReport(
            otlp_enabled=self.settings.otel_enabled,
            otlp_init_ok=self._init_ok,
            otlp_attempted=self.attempted,
            otlp_emit_count=self.emit_count,
            otlp_emit_errors=self.emit_errors,
            otlp_dropped=self.dropped_count,
            otlp_flush_attempted=self._flush_attempted,
            otlp_flush_ok=self._flush_ok,
            otlp_endpoint=self._endpoint() if self.settings.otel_enabled else None,
            otlp_init_error=self._init_error,
            otlp_last_error=self._last_error,
        )

    def emit(self, event: dict) -> None:
        validate_event(event)
        if self._logger is None:
            if self.settings.otel_enabled:
                self.dropped_count += 1
                self.export_errors += 1
            return
        self.attempted = True
        try:
            from opentelemetry._logs import LogRecord, SeverityNumber

            name = event.get("event.name", "")
            decision = event.get("agentsec.control.decision")
            severity = (
                SeverityNumber.ERROR
                if decision in ("DENY", "ERROR") or name.endswith("failed")
                else SeverityNumber.INFO
            )
            attributes = {
                "sourcetype": "otel:agentic:json",
                "event.name": name,
                "agentsec.run.id": event["agentsec.run.id"],
                "agentsec.testbed.mode": event["agentsec.testbed.mode"],
            }
            if decision:
                attributes["agentsec.control.decision"] = decision
            if event.get("gen_ai.agent.id"):
                attributes["gen_ai.agent.id"] = event["gen_ai.agent.id"]
            # Body remains a JSON string of the entire schema 1.0.0 event until live _raw says otherwise.
            record = LogRecord(
                timestamp=int(time.time() * 1e9),
                observed_timestamp=int(time.time() * 1e9),
                trace_id=int(event["trace_id"], 16),
                span_id=int(event["span_id"], 16),
                severity_number=severity,
                severity_text=severity.name,
                body=json.dumps(event, separators=(",", ":")),
                attributes=attributes,
            )
            self._logger.emit(record)
            self.emit_count += 1
        except Exception as exc:
            self.emit_errors += 1
            self.export_errors += 1
            self._last_error = str(exc)
            logger.warning("OTLP emit failed (evidence still local): %s", exc)

    def force_flush(self, timeout_millis: int = 10_000) -> ExportReport:
        self._flush_attempted = True
        if self._provider is None:
            self._flush_ok = False
            if self._last_error is None:
                self._last_error = "logger_provider_missing"
            return self.report()
        try:
            ok = bool(self._provider.force_flush(timeout_millis))
            self._flush_ok = ok
            if not ok:
                self.export_errors += 1
                self._last_error = "force_flush_returned_false"
                logger.warning("OTLP force_flush returned false (evidence still local)")
        except Exception as exc:
            self._flush_ok = False
            self.export_errors += 1
            self._last_error = str(exc)
            logger.warning("OTLP force_flush failed (evidence still local): %s", exc)
        report = self.report()
        # Per-/process accounting so the next request does not inherit emit_count.
        self.emit_count = 0
        self.dropped_count = 0
        self.emit_errors = 0
        self.export_errors = 0
        self.attempted = False
        return report


def flush_export(sink: object, timeout_millis: int = 10_000) -> ExportReport:
    flush = getattr(sink, "force_flush", None)
    if callable(flush):
        return flush(timeout_millis)
    return ExportReport.not_attempted()


def default_sink(memory: MemorySink | None = None, settings: Settings | None = None) -> FanoutSink:
    settings = settings or get_settings()
    memory = memory or MemorySink()
    sinks: list[EventSink] = [memory]
    if settings.otel_enabled:
        sinks.append(OtlpSink(settings))
    return FanoutSink(sinks)
