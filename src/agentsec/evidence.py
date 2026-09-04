"""Write artifacts/<run-id>/ experiment packs. Never invent Splunk results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from agentsec.detections import local_q_deny_live, local_q_run
from agentsec.settings import Settings


def write_evidence_bundle(
    *,
    run_id: str,
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
) -> Path:
    root = settings.artifacts_dir / run_id
    root.mkdir(parents=True, exist_ok=True)

    hop_rows = []
    for hop in hops:
        hop_rows.append(
            {
                "agent_id": hop.agent_id,
                "decision": hop.decision,
                "reason": hop.reason,
                "operation_executed": hop.operation_executed,
                "llm_error": hop.llm_error,
            }
        )

    events_path = root / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")

    control_result = hop_rows[-1] if hop_rows else {"decision": "ERROR", "reason": "no_hops"}
    q_run = local_q_run(events, run_id)
    q_deny = local_q_deny_live(events)

    detection = {
        "class": "MEASURED",
        "scope": "local_event_list_not_splunk",
        "Q-RUN": q_run,
        "Q-DENY": q_deny,
        "splunk_validated": False,
        "note": "Python reconstruction of the two Phase 2 hunt questions. Not a Splunk search result.",
    }

    limitations = [
        "LLM text is nondeterministic when Ollama is used; stub tests are the deterministic gate.",
        "OTLP export can fail independently of the control decision.",
        "No MCP, A2A, memory, RAG, MLTK, or Cisco overlay in Phase 2.",
    ]
    if testbed_mode == "BASELINE":
        limitations.append("BASELINE traffic is benign lab load, not an attack proof.")

    manifest = {
        "run.id": run_id,
        "lab.id": settings.lab_id,
        "AgentSec version": settings.version,
        "model": settings.ollama_model,
        "security profile": settings.security_profile,
        "attack": attack_id or "ATK-001",
        "expected behavior": expected_behavior,
        "actual behavior": actual_behavior,
        "telemetry": str(events_path),
        "control result": control_result,
        "detection result": detection,
        "limitations": limitations,
        "evidence.class": "MEASURED" if events else "INFERRED",
        "testbed.mode": testbed_mode,
        "llm_call_count": llm_call_count,
        "blocked": blocked,
        "user.input.preview": user_input[:200],
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (root / "request.json").write_text(
        json.dumps({"input_preview": user_input[:200], "input_length": len(user_input)}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (root / "result.json").write_text(
        json.dumps({"hops": hop_rows, "blocked": blocked, "llm_call_count": llm_call_count}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return root
