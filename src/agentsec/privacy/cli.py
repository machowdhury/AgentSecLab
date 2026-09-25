"""Run the bounded L8 privacy pair and print investigation identifiers."""

from __future__ import annotations

import json

from agentsec.privacy.pipeline import LAB_ID, run_privacy_specimen
from agentsec.settings import get_settings
from agentsec.telemetry import MemorySink, default_sink


def main() -> None:
    settings = get_settings()
    memory = MemorySink()
    sink = default_sink(memory=memory, settings=settings)
    runs = []
    for mode in ("ATTACK", "RETEST"):
        result = run_privacy_specimen(
            mode=mode,
            sink=sink,
            memory=memory,
            settings=settings,
            write_evidence=True,
        )
        payload = result.final_output or {}
        runs.append(
            {
                "mode": mode,
                "run_id": result.run_id,
                "decision": result.hops[0].control_decision,
                "completed": result.hops[0].mcp_completed,
                "received_fields": payload.get("received_fields", []),
                "unnecessary_fields": payload.get("unnecessary_fields", []),
                "handler_invoke_count": result.handler_invoke_count,
                "evidence_dir": result.evidence_dir,
            }
        )
    print(json.dumps({"lab_id": LAB_ID, "runs": runs}, indent=2))


if __name__ == "__main__":
    main()
