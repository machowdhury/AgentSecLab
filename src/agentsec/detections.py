"""Local hunt questions over an event list. These are NOT validated Splunk searches."""

from __future__ import annotations


def local_q_run(events: list[dict], run_id: str) -> dict:
    matched = [event for event in events if event.get("agentsec.run.id") == run_id]
    return {
        "question": "Did this run.id produce events?",
        "run.id": run_id,
        "event_count": len(matched),
        "matched": len(matched) > 0,
    }


def local_q_deny_live(events: list[dict]) -> dict:
    matched = [
        {
            "agentsec.run.id": event["agentsec.run.id"],
            "gen_ai.agent.id": event["gen_ai.agent.id"],
            "agentsec.control.reason": event["agentsec.control.reason"],
            "event.name": event["event.name"],
        }
        for event in events
        if event.get("agentsec.control.decision") == "DENY"
        and event.get("agentsec.operation.executed") is False
        and event.get("agentsec.testbed.mode") == "LIVE"
    ]
    return {
        "question": "Which LIVE events have DENY and operation.executed=false?",
        "event_count": len(matched),
        "events": matched,
    }
