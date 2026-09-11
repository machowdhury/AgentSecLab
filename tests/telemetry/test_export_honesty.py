"""OTLP export honesty: SDK flush is not Splunk success. Local evidence stays complete."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock

from agentsec.attacks import BENIGN_LOAN
from agentsec.pipeline import run_loan_pipeline
from agentsec.telemetry import ExportReport, FanoutSink, OtlpSink, flush_export


class _FlushSink:
    def __init__(self, report: ExportReport) -> None:
        self._report = report
        self.emitted = 0

    def emit(self, event: dict) -> None:
        self.emitted += 1

    def force_flush(self, timeout_millis: int = 10_000) -> ExportReport:
        del timeout_millis
        return self._report


def _read_export(result) -> dict:
    return json.loads((Path(result.evidence_dir) / "export.json").read_text(encoding="utf-8"))


def _read_events_jsonl(result) -> list[dict]:
    lines = (Path(result.evidence_dir) / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines]


def test_otlp_disabled_does_not_claim_export(settings, counting_llm, memory):
    assert settings.otel_enabled is False
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    export = _read_export(result)
    assert export["otlp.enabled"] is False
    assert export["otlp.attempted"] is False
    assert export["otlp.flush_attempted"] is False
    assert export["otlp.ok"] is False
    assert export["collector.observed"] is False
    assert export["hec.attempted"] is False
    assert export["hec.ok"] is False
    assert export["splunk.attempted"] is False
    assert export["splunk.ok"] is False
    assert export["splunk.verified"] is False
    assert export["layers"]["otlp"]["ok"] is False
    assert "does NOT mean" in export["note"]


def test_otlp_attempted_flush_success_is_not_splunk_success(settings, counting_llm, memory):
    report = ExportReport(
        otlp_enabled=True,
        otlp_init_ok=True,
        otlp_attempted=True,
        otlp_emit_count=1,
        otlp_flush_attempted=True,
        otlp_flush_ok=True,
        otlp_endpoint="http://127.0.0.1:4318/v1/logs",
    )
    assert report.otlp_ok is True
    sink = FanoutSink([memory, _FlushSink(report)])
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    export = _read_export(result)
    assert export["otlp.attempted"] is True
    assert export["otlp.flush_ok"] is True
    assert export["otlp.ok"] is True
    assert export["collector.observed"] is False
    assert export["hec.ok"] is False
    assert export["splunk.ok"] is False
    assert export["splunk.verified"] is False
    assert export["layers"]["splunk"]["verified"] is False
    local = _read_events_jsonl(result)
    assert len(local) == len(result.events)
    assert [row["agentsec.sequence"] for row in local] == [event["agentsec.sequence"] for event in result.events]


def test_exporter_flush_failure_is_not_converted_to_success(settings, counting_llm, memory):
    report = ExportReport(
        otlp_enabled=True,
        otlp_init_ok=True,
        otlp_attempted=True,
        otlp_emit_count=1,
        otlp_flush_attempted=True,
        otlp_flush_ok=False,
        otlp_last_error="force_flush_returned_false",
    )
    assert report.otlp_ok is False
    sink = FanoutSink([memory, _FlushSink(report)])
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    export = _read_export(result)
    assert export["otlp.attempted"] is True
    assert export["otlp.flush_attempted"] is True
    assert export["otlp.flush_ok"] is False
    assert export["otlp.ok"] is False
    assert export["splunk.verified"] is False
    local = _read_events_jsonl(result)
    assert len(local) == len(result.events) == len(memory.events)
    assert local[0]["event.name"] == result.events[0]["event.name"]


def test_otlp_emit_failure_keeps_local_evidence_complete(settings, counting_llm, memory):
    sink_otlp = OtlpSink(replace(settings, otel_enabled=False))
    sink_otlp.settings = replace(settings, otel_enabled=True)
    sink_otlp._init_ok = True
    sink_otlp._logger = MagicMock()
    sink_otlp._logger.emit.side_effect = RuntimeError("exporter_boom")
    sink_otlp._provider = MagicMock()
    sink_otlp._provider.force_flush.return_value = True
    sink = FanoutSink([memory, sink_otlp])
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=sink,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    export = _read_export(result)
    assert export["otlp.attempted"] is True
    assert export["otlp.emit_errors"] > 0
    assert export["otlp.ok"] is False
    assert export["splunk.verified"] is False
    local = _read_events_jsonl(result)
    assert len(local) == len(result.events)
    assert {row["agentsec.sequence"] for row in local} == set(range(1, len(local) + 1))


def test_otlp_sink_force_flush_false_is_not_ok(settings):
    sink = OtlpSink(replace(settings, otel_enabled=False))
    sink.settings = replace(settings, otel_enabled=True)
    sink._init_ok = True
    sink.attempted = True
    sink.emit_count = 3
    sink._logger = MagicMock()
    sink._provider = MagicMock()
    sink._provider.force_flush.return_value = False
    report = sink.force_flush(timeout_millis=100)
    assert report.otlp_flush_attempted is True
    assert report.otlp_flush_ok is False
    assert report.otlp_ok is False
    assert report.otlp_last_error == "force_flush_returned_false"
    doc = report.to_export_doc()
    assert doc["splunk.verified"] is False
    assert doc["hec.ok"] is False
    assert doc["collector.observed"] is False


def test_flush_export_without_otlp_sink_is_not_attempted(memory):
    report = flush_export(memory)
    assert report.otlp_attempted is False
    assert report.otlp_ok is False
    assert report.to_export_doc()["splunk.verified"] is False
