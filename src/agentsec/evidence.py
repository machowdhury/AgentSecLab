"""Write artifacts/<run-id>/ experiment packs. Never invent Splunk results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from agentsec.events import content_hash, content_preview
from agentsec.experiment import EXECUTION_MODE, SCHEMA_NAME, SCHEMA_VERSION, TELEMETRY_FIDELITY
from agentsec.settings import Settings
from agentsec.telemetry import ExportReport


def write_evidence_bundle(
    *,
    run_id: str,
    incident_id: str,
    settings: Settings,
    events: list[dict],
    user_input: str,
    hops: Iterable[Any],
    testbed_mode: str,
    attack_id: str | None,
    expected_behavior: str,
    actual_behavior: str,
    llm_call_count: int,
    blocked: bool,
    terminal: str,
    export_report: ExportReport | None = None,
) -> Path:
    root = settings.artifacts_dir / run_id
    root.mkdir(parents=True, exist_ok=True)

    hop_rows = []
    for hop in hops:
        row = {
            "hop.index": hop.index,
            "gen_ai.agent.id": hop.agent_id,
            "control.decision": hop.control_decision,
            "control.reason": hop.control_reason,
            "operation.attempted": hop.operation_attempted,
            "operation.executed": hop.operation_executed,
            "operation.outcome": hop.operation_outcome,
            "llm.started": hop.llm_started,
            "llm.completed": hop.llm_completed,
            "llm.failed": hop.llm_failed,
        }
        if hop.index >= 1:
            row["delegator.agent.id"] = hop.delegator_agent_id
        hop_rows.append(row)

    events_path = root / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")

    control_result = None
    if hop_rows:
        control_result = {
            "decision": hop_rows[-1]["control.decision"],
            "reason": hop_rows[-1]["control.reason"],
        }
    elif events:
        control_result = {"decision": "ERROR", "reason": "schema_validation"}

    llm_completed_count = sum(1 for event in events if event.get("event.name") == "agentsec.llm.completed")
    llm_invoked_count = sum(1 for hop in hop_rows if hop["operation.executed"] is True)

    manifest = {
        "schema.name": SCHEMA_NAME,
        "schema.version": SCHEMA_VERSION,
        "run.id": run_id,
        "incident.id": incident_id,
        "lab.id": settings.lab_id,
        "agentsec.version": settings.version,
        "model": settings.ollama_model,
        "security.profile": settings.security_profile,
        "testbed.mode": testbed_mode,
        "execution.mode": EXECUTION_MODE,
        "telemetry.fidelity": TELEMETRY_FIDELITY,
        "attack.id": attack_id or "ATK-001",
        "expected.behavior": expected_behavior,
        "actual.behavior": actual_behavior,
        "control.result": control_result,
        "llm.invoked.count": llm_invoked_count,
        "llm.completed.count": llm_completed_count,
        "blocked": blocked,
        "terminal": terminal,
        "evidence.class": "OBSERVED",
        "evidence.class.scope": "local_runtime_and_events_jsonl; Splunk not verified by runtime",
        "splunk.validated": False,
        "workflow.entry": "/process",
        "runtime.authoritative": True,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    request_doc = {
        "input.length": len(user_input),
        "input.hash": content_hash(user_input) if user_input else content_hash(""),
        "input.preview": content_preview(user_input),
    }
    (root / "request.json").write_text(json.dumps(request_doc, indent=2) + "\n", encoding="utf-8")

    (root / "result.json").write_text(
        json.dumps(
            {
                "run.id": run_id,
                "incident.id": incident_id,
                "blocked": blocked,
                "terminal": terminal,
                "hops": hop_rows,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    report = export_report or ExportReport.not_attempted()
    export_doc = report.to_export_doc()
    (root / "export.json").write_text(json.dumps(export_doc, indent=2) + "\n", encoding="utf-8")

    limitations = {
        "items": [
            "CTRL-INPUT-001 is a lightweight lab reference control, not production prompt-injection protection.",
            "Stub-LLM tests prove deterministic control placement. Live Ollama wording is nondeterministic.",
            "Runtime never sets collector.observed, hec.ok, or splunk.verified. otlp.ok is SDK flush only.",
            "Default evidence stores sanitized preview (<=200) plus SHA-256 hash, not complete prompts.",
            "operation.executed=true means the governed LLM call began, not that it succeeded.",
            "No MCP, A2A, memory, RAG, MLTK, Cisco overlay, or attack chains in this slice.",
        ]
    }
    (root / "limitations.json").write_text(json.dumps(limitations, indent=2) + "\n", encoding="utf-8")
    return root
