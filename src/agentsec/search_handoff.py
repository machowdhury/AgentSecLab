"""Native Splunk Search handoff for a fresh run.id. No Studio token writes."""

from __future__ import annotations

from urllib.parse import quote, urlencode

DEFAULT_SPLUNK_WEB = "http://127.0.0.1:8000"
STARTER_EARLIEST = "-1h"
INDEX = "agentsec_telemetry"
SOURCETYPE = "otel:agentic:json"
HUNTS_BY_LAB = {
    "LAB-PI-001": (
        "Q-RUN-EVENTS",
        "Q-CONTROL-DECISION",
        "Q-LLM-EXECUTED",
        "Q-LLM-AFTER-DENY",
    ),
    "LAB-MCP-001": (
        "Q-MCP-WHO",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-AFTER-DENY",
    ),
}
REUSED_HUNTS = HUNTS_BY_LAB["LAB-PI-001"]


def hunts_for(lab_id: str | None) -> tuple[str, ...]:
    if lab_id and lab_id in HUNTS_BY_LAB:
        return HUNTS_BY_LAB[lab_id]
    return REUSED_HUNTS


def starter_spl(run_id: str, *, earliest: str = STARTER_EARLIEST) -> str:
    return (
        f"index={INDEX} sourcetype={SOURCETYPE} earliest={earliest} "
        f'"agentsec.run.id"="{run_id}"'
    )


def completeness_spl(run_id: str, *, earliest: str = STARTER_EARLIEST) -> str:
    return starter_spl(run_id, earliest=earliest) + " | stats dc(_raw) as n"


def search_url(run_id: str, *, splunk_web: str = DEFAULT_SPLUNK_WEB) -> str:
    query = "search " + starter_spl(run_id)
    encoded = urlencode({"q": query}, quote_via=quote)
    base = splunk_web.rstrip("/")
    return f"{base}/en-US/app/search/search?{encoded}"


def pair_starter_spl(run_a: str, run_b: str, *, earliest: str = STARTER_EARLIEST) -> str:
    return (
        f"index={INDEX} sourcetype={SOURCETYPE} earliest={earliest} "
        f'("agentsec.run.id"="{run_a}" OR "agentsec.run.id"="{run_b}")'
    )


def pair_search_url(run_a: str, run_b: str, *, splunk_web: str = DEFAULT_SPLUNK_WEB) -> str:
    query = "search " + pair_starter_spl(run_a, run_b)
    encoded = urlencode({"q": query}, quote_via=quote)
    base = splunk_web.rstrip("/")
    return f"{base}/en-US/app/search/search?{encoded}"


def pair_handoff_doc(
    attack_run_id: str,
    retest_run_id: str,
    *,
    splunk_web: str = DEFAULT_SPLUNK_WEB,
    lab_id: str | None = None,
) -> dict:
    spl = pair_starter_spl(attack_run_id, retest_run_id)
    hunts = hunts_for(lab_id)
    return {
        "copy_attack_run_id": attack_run_id,
        "copy_retest_run_id": retest_run_id,
        "starter_spl": spl,
        "search_url": pair_search_url(attack_run_id, retest_run_id, splunk_web=splunk_web),
        "reused_hunts": list(hunts),
        "studio_token_binding": "NOT SUPPORTED / DO NOT BUILD",
        "instructions": [
            "Copy both run.ids. They must be different UUIDs.",
            "Open the compare Search URL. The query is server-built; do not paste learner SPL into Attack Service.",
            f"Reuse {hunts[1]} and {hunts[3] if len(hunts) > 3 else hunts[-1]} once per run.id.",
            "SAME request fingerprint + DIFFERENT profile is the experiment, not a new detector.",
        ],
    }


def handoff_doc(
    run_id: str,
    *,
    splunk_web: str = DEFAULT_SPLUNK_WEB,
    lab_id: str | None = None,
) -> dict:
    spl = starter_spl(run_id)
    hunts = hunts_for(lab_id)
    inspect = (
        "Execute. Inspect event.name, control.decision, and mcp.* yourself."
        if lab_id == "LAB-MCP-001"
        else "Execute. Inspect event.name, control.decision, and llm.* yourself."
    )
    return {
        "copy_run_id": run_id,
        "starter_spl": spl,
        "search_url": search_url(run_id, splunk_web=splunk_web),
        "reused_hunts": list(hunts),
        "studio_token_binding": "NOT SUPPORTED / DO NOT BUILD",
        "instructions": [
            "Copy the run.id.",
            "Open Splunk Search (Search & Reporting, or the search_url).",
            "Paste the starter query. Confirm the run.id matches.",
            inspect,
            f"Reuse {' / '.join(hunts[:2])} after substituting this run.id. Do not create a new detector.",
            "This fresh LIVE id is not the canonical REPLAY dropdown.",
        ],
    }
