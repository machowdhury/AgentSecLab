"""C2 run-timeline contract: an ordered view of one run built only from its recorded events.

Each tool call carries four independent facts. Nothing is inferred:
  proposed  - null for every current lab: the tool request comes from a server-owned payload,
              not from a model (proposal_source says so). A model-driven lab will set it.
  decision  - ALLOW / DENY / ERROR from agentsec.control.decision.
  executed  - true only if an agentsec.mcp.started event follows the decision for that tool.
              ALLOW alone never sets it.
  indexed   - null here: indexing is a Splunk fact, reported by the C1 evidence state.
"""

from __future__ import annotations

from agentsec.evidence_contract import SOURCES, ContractError

TIMELINE_VERSION = "1.0.0"
PROPOSAL_SOURCES = ("server_payload", "model")


def build_timeline(events: list[dict], *, run_id: str, source: str) -> dict:
    if source not in SOURCES:
        raise ContractError(f"unknown evidence source {source!r}")
    rows = sorted(
        (e for e in events if e.get("agentsec.run.id") == run_id),
        key=lambda e: int(e.get("agentsec.sequence") or 0),
    )
    out_events = []
    calls: list[dict] = []
    for e in rows:
        name = e.get("event.name")
        seq = int(e.get("agentsec.sequence") or 0)
        out_events.append({
            "seq": seq, "ts": e.get("timestamp"), "event": name,
            "agent": e.get("gen_ai.agent.id"), "tool": e.get("gen_ai.tool.name"),
            "decision": e.get("agentsec.control.decision"), "control_id": e.get("agentsec.control.id"),
            "reason": e.get("agentsec.control.reason"), "outcome": e.get("agentsec.outcome"),
        })
        tool = e.get("gen_ai.tool.name")
        if name == "agentsec.control.decision" and tool:
            calls.append({
                "tool": tool, "decision_seq": seq, "decision": e.get("agentsec.control.decision"),
                "control_id": e.get("agentsec.control.id"), "reason": e.get("agentsec.control.reason"),
                "proposed": None, "proposal_source": "server_payload",
                "executed": False, "started_seq": None, "completed_seq": None, "indexed": None,
            })
        elif name in ("agentsec.mcp.started", "agentsec.mcp.completed", "agentsec.mcp.failed") and tool:
            call = next((c for c in reversed(calls) if c["tool"] == tool), None)
            if call is None:
                continue  # an execution event without a recorded decision is not attributed
            if name == "agentsec.mcp.started":
                call["executed"], call["started_seq"] = True, seq
            elif name == "agentsec.mcp.completed":
                call["completed_seq"] = seq
    return {"schema_version": TIMELINE_VERSION, "run_id": run_id, "source": source,
            "event_count": len(out_events), "events": out_events, "tool_calls": calls}
