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
    "LAB-RAG-CONTEXT": (
        "Q-RAG-CONTEXT-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-WHO",
    ),
    "LAB-MEMORY-001": (
        "Q-MEMORY-CONTEXT-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-WHO",
    ),
    "LAB-AGENT-GOAL-INTEGRITY-001": (
        "Q-GOAL-INTEGRITY-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-WHO",
    ),
    "LAB-AGENT-DELEGATION-001": (
        "Q-AGENT-DELEGATION-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-TOOL",
        "Q-MCP-EXECUTED",
        "Q-MCP-WHO",
    ),
    "LAB-AGENTSEC-CAPSTONE-001": (
        "Q-RUN-EVENTS",
        "Q-RAG-CONTEXT-AUTHORITY",
        "Q-MEMORY-CONTEXT-AUTHORITY",
        "Q-MCP-AUTHZ",
        "Q-MCP-EXECUTED",
        "Q-GOAL-INTEGRITY-AUTHORITY",
        "Q-AGENT-DELEGATION-AUTHORITY",
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
    if lab_id == "LAB-MCP-001":
        inspect = "Execute. Inspect event.name, control.decision, and mcp.* yourself."
    elif lab_id == "LAB-RAG-CONTEXT":
        inspect = (
            "Execute. Inspect document.id, content.hash, CTRL-RAG-CONTEXT-001, "
            "and follow-on CTRL-MCP-001 yourself."
        )
    elif lab_id == "LAB-MEMORY-001":
        inspect = (
            "Execute. Inspect agentsec.memory.written / recalled, memory.id, content.hash, "
            "source_run_id, CTRL-MEMORY-CONTEXT-001, and follow-on CTRL-MCP-001 yourself."
        )
    elif lab_id == "LAB-AGENT-GOAL-INTEGRITY-001":
        inspect = (
            "Execute. Inspect task.fingerprint, instruction.hash, proposed.action, "
            "CTRL-GOAL-INTEGRITY-001, CTRL-MCP-001, and effective.action yourself."
        )
    elif lab_id == "LAB-AGENT-DELEGATION-001":
        inspect = (
            "Execute. Inspect principal, caller, callee, claimed scope, "
            "CTRL-IDENTITY-001 OBSERVE, CTRL-MCP-001, and handler counts yourself. "
            "WHO AUTHENTICATED is not proven."
        )
    elif lab_id == "LAB-AGENTSEC-CAPSTONE-001":
        inspect = (
            "Execute. Inspect retrieve, write, and recall run.ids. "
            "Join retrieved content.hash to memory content.hash. "
            "source_run_id links write to recall. CTRL-MCP-001 is on the recall run. "
            "Goal and identity event families are NOT PRESENT in this packet "
            "(instrumented absence, not a universal ruling-out)."
        )
    else:
        inspect = "Execute. Inspect event.name, control.decision, and llm.* yourself."
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


def memory_lifecycle_spl(write_run_id: str, recall_run_id: str, *, earliest: str = STARTER_EARLIEST) -> str:
    return pair_starter_spl(write_run_id, recall_run_id, earliest=earliest)


def memory_lifecycle_handoff(
    write_run_id: str,
    recall_run_id: str,
    *,
    splunk_web: str = DEFAULT_SPLUNK_WEB,
) -> dict:
    spl = memory_lifecycle_spl(write_run_id, recall_run_id)
    hunts = hunts_for("LAB-MEMORY-001")
    query = "search " + spl
    encoded = urlencode({"q": query}, quote_via=quote)
    base = splunk_web.rstrip("/")
    return {
        "copy_write_run_id": write_run_id,
        "copy_recall_run_id": recall_run_id,
        "copy_run_id": recall_run_id,
        "starter_spl": spl,
        "search_url": f"{base}/en-US/app/search/search?{encoded}",
        "write_search_url": search_url(write_run_id, splunk_web=splunk_web),
        "recall_search_url": search_url(recall_run_id, splunk_web=splunk_web),
        "reused_hunts": list(hunts),
        "studio_token_binding": "NOT SUPPORTED / DO NOT BUILD",
        "instructions": [
            "Copy BOTH run.ids. WRITE and RECALL are different UUIDs.",
            "Open Splunk Search. The starter query already ORs write and recall.",
            "Find agentsec.memory.written on the write run, then agentsec.memory.recalled on the later run.",
            "Confirm memory.id, content.hash, and agentsec.memory.source_run_id. Preview is not the fingerprint.",
            f"Reuse {hunts[0]} with both tokens. Reuse Q-MCP-* against the recall run.id.",
            "Do not create DET-MEMORY. This fresh LIVE pair is not the canonical REPLAY dropdown.",
        ],
    }


def memory_pair_handoff_doc(
    attack_write_run_id: str,
    attack_recall_run_id: str,
    retest_write_run_id: str,
    retest_recall_run_id: str,
    *,
    splunk_web: str = DEFAULT_SPLUNK_WEB,
) -> dict:
    ids = (
        attack_write_run_id,
        attack_recall_run_id,
        retest_write_run_id,
        retest_recall_run_id,
    )
    or_clause = " OR ".join(f'"agentsec.run.id"="{run_id}"' for run_id in ids)
    spl = f"index={INDEX} sourcetype={SOURCETYPE} earliest={STARTER_EARLIEST} ({or_clause})"
    query = "search " + spl
    encoded = urlencode({"q": query}, quote_via=quote)
    base = splunk_web.rstrip("/")
    hunts = hunts_for("LAB-MEMORY-001")
    return {
        "attack_write_run_id": attack_write_run_id,
        "attack_recall_run_id": attack_recall_run_id,
        "retest_write_run_id": retest_write_run_id,
        "retest_recall_run_id": retest_recall_run_id,
        "starter_spl": spl,
        "search_url": f"{base}/en-US/app/search/search?{encoded}",
        "reused_hunts": list(hunts),
        "studio_token_binding": "NOT SUPPORTED / DO NOT BUILD",
        "instructions": [
            "This query is server-built. Do not paste learner SPL into Attack Service.",
            "Four run.ids: ATTACK write/recall and RETEST write/recall.",
            "SAME should include memory.id, content.hash, provenance, follow-on tool, and requested scope.",
            "DIFFERENT should include experiment, CTRL-MCP-001 decision, execution, handler count, and run.ids.",
            "SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.",
            f"Reuse {hunts[0]} per write/recall pair. Splunk reconstructed the experiment. Splunk did not enforce it.",
        ],
    }


def capstone_lifecycle_spl(
    retrieve_run_id: str,
    write_run_id: str,
    recall_run_id: str,
    *,
    earliest: str = STARTER_EARLIEST,
) -> str:
    or_clause = " OR ".join(
        f'"agentsec.run.id"="{run_id}"'
        for run_id in (retrieve_run_id, write_run_id, recall_run_id)
    )
    return f"index={INDEX} sourcetype={SOURCETYPE} earliest={earliest} ({or_clause})"


def capstone_lifecycle_handoff(
    retrieve_run_id: str,
    write_run_id: str,
    recall_run_id: str,
    *,
    splunk_web: str = DEFAULT_SPLUNK_WEB,
) -> dict:
    spl = capstone_lifecycle_spl(retrieve_run_id, write_run_id, recall_run_id)
    hunts = hunts_for("LAB-AGENTSEC-CAPSTONE-001")
    query = "search " + spl
    encoded = urlencode({"q": query}, quote_via=quote)
    base = splunk_web.rstrip("/")
    return {
        "copy_retrieve_run_id": retrieve_run_id,
        "copy_write_run_id": write_run_id,
        "copy_recall_run_id": recall_run_id,
        "copy_run_id": recall_run_id,
        "starter_spl": spl,
        "search_url": f"{base}/en-US/app/search/search?{encoded}",
        "retrieve_search_url": search_url(retrieve_run_id, splunk_web=splunk_web),
        "write_search_url": search_url(write_run_id, splunk_web=splunk_web),
        "recall_search_url": search_url(recall_run_id, splunk_web=splunk_web),
        "reused_hunts": list(hunts),
        "studio_token_binding": "NOT SUPPORTED / DO NOT BUILD",
        "instructions": [
            "Copy THREE run.ids. RETRIEVE, WRITE, and RECALL are different UUIDs.",
            "Open Splunk Search. The starter query already ORs retrieve, write, and recall.",
            "Find retrieve on the first run, memory.written on the write run, memory.recalled on the later run.",
            "Confirm content.hash equality retrieve→write→recall and source_run_id equals the write UUID.",
            f"Reuse {hunts[1]} on retrieve, {hunts[2]} on write+recall, Q-MCP-* on the recall run.",
            "Do not create DET-CAPSTONE. This fresh LIVE triple is not the canonical REPLAY dropdown.",
        ],
    }


def capstone_pair_handoff_doc(
    attack_retrieve_run_id: str,
    attack_write_run_id: str,
    attack_recall_run_id: str,
    retest_retrieve_run_id: str,
    retest_write_run_id: str,
    retest_recall_run_id: str,
    *,
    splunk_web: str = DEFAULT_SPLUNK_WEB,
) -> dict:
    ids = (
        attack_retrieve_run_id,
        attack_write_run_id,
        attack_recall_run_id,
        retest_retrieve_run_id,
        retest_write_run_id,
        retest_recall_run_id,
    )
    or_clause = " OR ".join(f'"agentsec.run.id"="{run_id}"' for run_id in ids)
    spl = f"index={INDEX} sourcetype={SOURCETYPE} earliest={STARTER_EARLIEST} ({or_clause})"
    query = "search " + spl
    encoded = urlencode({"q": query}, quote_via=quote)
    base = splunk_web.rstrip("/")
    hunts = hunts_for("LAB-AGENTSEC-CAPSTONE-001")
    return {
        "attack_retrieve_run_id": attack_retrieve_run_id,
        "attack_write_run_id": attack_write_run_id,
        "attack_recall_run_id": attack_recall_run_id,
        "retest_retrieve_run_id": retest_retrieve_run_id,
        "retest_write_run_id": retest_write_run_id,
        "retest_recall_run_id": retest_recall_run_id,
        "starter_spl": spl,
        "search_url": f"{base}/en-US/app/search/search?{encoded}",
        "reused_hunts": list(hunts),
        "studio_token_binding": "NOT SUPPORTED / DO NOT BUILD",
        "instructions": [
            "This query is server-built. Do not paste learner SPL into Attack Service.",
            "Six run.ids: ATTACK retrieve/write/recall and RETEST retrieve/write/recall.",
            "SAME should include document bytes, content.hash, memory.id, follow-on tool, and requested scope.",
            "DIFFERENT should include experiment, CTRL-MCP-001 decision, execution, handler count, and run.ids.",
            "SAME ADVERSARIAL INFLUENCE. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.",
            f"Reuse {hunts[3]} on each recall run.id. Splunk reconstructed the experiment. Splunk did not enforce it.",
        ],
    }
