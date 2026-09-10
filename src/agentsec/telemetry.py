"""Event sinks: memory (tests/evidence) and optional OTLP logs to the collector."""

from __future__ import annotations

import logging
import time
from typing import Protocol

from agentsec.schema import validate_event
from agentsec.settings import Settings, get_settings

logger = logging.getLogger("agentsec.telemetry")

_OTLP_ATTR_KEYS = (
    "event.name",
    "timestamp",
    "user.id",
    "trace_id",
    "gen_ai.agent.id",
    "gen_ai.agent.name",
    "agentsec.agent.role",
    "agentsec.principal.id",
    "agentsec.principal.type",
    "gen_ai.request.model",
    "agentsec.technique.id",
    "agentsec.control.id",
    "agentsec.control.decision",
    "agentsec.control.reason",
    "agentsec.run.id",
    "agentsec.incident.id",
    "agentsec.testbed.mode",
    "agentsec.content.origin.type",
    "agentsec.content.origin.id",
    "agentsec.content.influence.kind",
)


def _otlp_attributes(event: dict) -> dict:
    attrs: dict = {"sourcetype": "otel:agentic:json"}
    for key in _OTLP_ATTR_KEYS:
        value = event.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, (str, bool, int, float)):
            attrs[key] = value
    return attrs


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


class OtlpSink:
    """Best-effort export. Collector failure must not become a fake ALLOW."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._logger = None
        self._resource = None
        self.export_errors = 0
        if self.settings.otel_enabled:
            self._init_provider()

    def _init_provider(self) -> None:
        try:
            from opentelemetry.sdk._logs import LoggerProvider
            from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
            from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry._logs import set_logger_provider

            self._resource = Resource.create(
                {
                    "service.name": self.settings.service_name,
                    "service.version": self.settings.version,
                    "deployment.environment": self.settings.deployment_environment,
                }
            )
            provider = LoggerProvider(resource=self._resource)
            exporter = OTLPLogExporter(
                endpoint=f"{self.settings.otel_collector_http}/v1/logs",
            )
            provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
            set_logger_provider(provider)
            self._logger = provider.get_logger("agentsec.telemetry", self.settings.version)
        except Exception as exc:  # pragma: no cover - import/collector wiring
            logger.warning("OTLP log exporter not initialized: %s", exc)
            self._logger = None

    def emit(self, event: dict) -> None:
        validate_event(event)
        if self._logger is None:
            return
        try:
            from opentelemetry.sdk._logs import LogRecord
            from opentelemetry._logs import SeverityNumber

            severity = (
                SeverityNumber.ERROR
                if event["agentsec.control.decision"] in ("DENY", "ERROR")
                else SeverityNumber.INFO
            )
            record = LogRecord(
                timestamp=int(time.time() * 1e9),
                observed_timestamp=int(time.time() * 1e9),
                trace_id=int(event["trace_id"], 16),
                span_id=int(event["span_id"], 16),
                severity_number=severity,
                severity_text=severity.name,
                body=dict(event),
                attributes=_otlp_attributes(event),
                resource=self._resource,
            )
            self._logger.emit(record)
        except Exception as exc:
            self.export_errors += 1
            logger.warning("OTLP emit failed (evidence still local): %s", exc)


def default_sink(memory: MemorySink | None = None, settings: Settings | None = None) -> FanoutSink:
    settings = settings or get_settings()
    memory = memory or MemorySink()
    sinks: list[EventSink] = [memory]
    if settings.otel_enabled:
        sinks.append(OtlpSink(settings))
    return FanoutSink(sinks)
