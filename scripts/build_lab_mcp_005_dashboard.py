#!/usr/bin/env python3
"""Build the LAB-MCP-005 Dashboard Studio definition.

Q-MCP files from LAB-MCP-001 are unchanged except replacing __RUN_ID__ with a
quoted Studio token. Q-MCP-RESULT-AUTHORITY is the MCP-005 primary hunt.
DET-MCP-001.spl is not modified. The DETECT fixture is DET-MCP-001-POSITIVE-CONTROL
(SIMULATED), not the MCP-004 resource teaching search.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RESULT_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-005" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-MCP-005" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_mcp_005.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

BASELINE_ID = "3013aa39-fe08-4b58-9898-f3abb092ac06"
ATTACK_ID = "f3f48182-df57-4b38-b069-17a199dc4939"
RETEST_ID = "0ab10594-a7fc-48b6-81bf-4cbca54a64c6"
NORMAL_HASH = "sha256:2c258a80464ede4113e7721119bc6a908951b8b723c61489ac27b737cdbeb68e"
MALICIOUS_HASH = "sha256:f7d67b151741ef7c7efb60242b96f8325996709128293da424f53a547230c358"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_HUNT = (
    "Hunt run.id defaults to the BASELINE specimen so this page is not an error "
    "state. Replace it and Submit to hunt another complete copy. Zero rows means "
    "no indexed CTRL-MCP-RESULT-001 for that id. Zero rows is not DENY and is not "
    "proof the handler never ran."
)
ALLOW_NOT_EXEC = (
    "ALLOW is the control decision. Tool execution begins at mcp.started "
    "(executed=true on that event). Do not read ALLOW as execution. "
    "mcp.completed is success of a begun call. mcp.failed is execution then "
    "error, not prevention."
)
RUNTIME_AUTH = (
    "Runtime handler count is authoritative proof of non-execution. Splunk "
    "absence of mcp.started is corroboration only, and only on a complete copy."
)
DATA_NOT_AUTHORITY = (
    "INV-002: data cannot create permission. Tool result content is untrusted_data. "
    "PROVENANCE records where bytes came from; it is not authority."
)
SERVER_OWNED = (
    "Server-owned grant stays lookup_policy at policy:read. There is no indexed "
    "agentsec.mcp.allowed_tools field. Hop-1 preview may list server_owned_allowed_tools "
    "within the bounded 200-character preview."
)


def load_spl(name: str, *, result: bool = False) -> str:
    directory = RESULT_DIR if result else SEARCH_DIR
    return (directory / name).read_text(encoding="utf-8").strip()


def bind_run_id(spl: str, token: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError(f"expected __RUN_ID__ in query for token {token}")
    return spl.replace("__RUN_ID__", f'"${token}$"')


def block(item: str, x: int, y: int, w: int, h: int) -> dict:
    return {"item": item, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}


def markdown(viz_id: str, body: str, title: str | None = None) -> tuple[str, dict]:
    viz = {
        "type": "splunk.markdown",
        "options": {
            "markdown": textwrap.dedent(body).strip() + "\n",
            "fontColor": TEXT,
            "backgroundColor": WHITE,
            "fontSize": "large",
        },
    }
    if title:
        viz["title"] = title
    return viz_id, viz


def table(
    viz_id: str,
    ds: str,
    title: str,
    description: str,
    *,
    no_data: str,
) -> tuple[str, dict]:
    return viz_id, {
        "type": "splunk.table",
        "title": title,
        "description": description,
        "dataSources": {"primary": ds},
        "showProgressBar": True,
        "showLastUpdated": False,
        "hideWhenNoData": False,
        "options": {
            "count": 50,
            "showRowNumbers": False,
            "backgroundColor": WHITE,
            "headerBackgroundColor": NAVY,
            "headerTextColor": WHITE,
            "noDataMessage": no_data,
        },
    }


def search_ds(ds_id: str, name: str, query: str) -> tuple[str, dict]:
    return ds_id, {
        "type": "ds.search",
        "name": name,
        "options": {"query": query},
    }


def layout(structure: list[dict], height: int) -> dict:
    return {
        "type": "grid",
        "options": {
            "backgroundColor": BG,
            "display": "auto-scale",
            "gutterSize": 8,
            "width": CANVAS_W,
            "height": height,
        },
        "structure": structure,
    }


def observe_sequence_spl(token: str) -> str:
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="${token}$" ("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval hop=mvindex(mvdedup('agentsec.hop.index'),0)
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval result_trust=mvindex(mvdedup('agentsec.mcp.result.trust'),0)
| eval attempted=mvindex(mvdedup('agentsec.operation.attempted'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| table sequence, run_id, event_name, hop, control_id, tool, decision, reason, requested_scope, allowed_scope, result_trust, attempted, executed, outcome
| sort sequence"""


def what_happened_spl(token: str) -> str:
    return bind_run_id(load_spl("Q-MCP-RESULT-AUTHORITY.spl", result=True), token)


def build() -> dict:
    q_who = bind_run_id(load_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_after = bind_run_id(load_spl("Q-MCP-AFTER-DENY.spl"), "run_id")
    q_result = bind_run_id(load_spl("Q-MCP-RESULT.spl"), "run_id")
    q_result_trust = bind_run_id(load_spl("Q-MCP-RESULT-TRUST.spl"), "run_id")
    q_authority = bind_run_id(load_spl("Q-MCP-RESULT-AUTHORITY.spl", result=True), "run_id")
    q_authz_b = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "baseline_run_id")
    q_authz_a = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "attack_run_id")
    q_authz_r = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "retest_run_id")
    q_auth_b = bind_run_id(load_spl("Q-MCP-RESULT-AUTHORITY.spl", result=True), "baseline_run_id")
    q_auth_a = bind_run_id(load_spl("Q-MCP-RESULT-AUTHORITY.spl", result=True), "attack_run_id")
    q_auth_r = bind_run_id(load_spl("Q-MCP-RESULT-AUTHORITY.spl", result=True), "retest_run_id")
    q_tool_b = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "baseline_run_id")
    q_tool_a = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "attack_run_id")
    q_tool_r = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "retest_run_id")
    q_exec_b = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "baseline_run_id")
    q_exec_a = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "attack_run_id")
    q_exec_r = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "retest_run_id")

    data_sources = dict(
        (
            search_ds("ds_q_who", "Q-MCP-WHO", q_who),
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_after_deny", "Q-MCP-AFTER-DENY", q_after),
            search_ds("ds_q_result", "Q-MCP-RESULT", q_result),
            search_ds("ds_q_result_trust", "Q-MCP-RESULT-TRUST", q_result_trust),
            search_ds("ds_q_result_authority", "Q-MCP-RESULT-AUTHORITY", q_authority),
            search_ds(
                "ds_det_mcp_001_sim",
                "DET-MCP-001-POSITIVE-CONTROL",
                load_spl("DET-MCP-001-POSITIVE-CONTROL.spl"),
            ),
            search_ds("ds_observe_seq", "MCP-005 observe sequence", observe_sequence_spl("run_id")),
            search_ds("ds_what_baseline", "What Happened BASELINE", what_happened_spl("baseline_run_id")),
            search_ds("ds_what_attack", "What Happened ATTACK", what_happened_spl("attack_run_id")),
            search_ds("ds_what_retest", "What Happened RETEST", what_happened_spl("retest_run_id")),
            search_ds("ds_q_authz_baseline", "Q-MCP-AUTHZ BASELINE", q_authz_b),
            search_ds("ds_q_authz_attack", "Q-MCP-AUTHZ ATTACK", q_authz_a),
            search_ds("ds_q_authz_retest", "Q-MCP-AUTHZ RETEST", q_authz_r),
            search_ds("ds_q_authority_baseline", "Q-MCP-RESULT-AUTHORITY BASELINE", q_auth_b),
            search_ds("ds_q_authority_attack", "Q-MCP-RESULT-AUTHORITY ATTACK", q_auth_a),
            search_ds("ds_q_authority_retest", "Q-MCP-RESULT-AUTHORITY RETEST", q_auth_r),
            search_ds("ds_q_tool_baseline", "Q-MCP-TOOL BASELINE", q_tool_b),
            search_ds("ds_q_tool_attack", "Q-MCP-TOOL ATTACK", q_tool_a),
            search_ds("ds_q_tool_retest", "Q-MCP-TOOL RETEST", q_tool_r),
            search_ds("ds_q_executed_baseline", "Q-MCP-EXECUTED BASELINE", q_exec_b),
            search_ds("ds_q_executed_attack", "Q-MCP-EXECUTED ATTACK", q_exec_a),
            search_ds("ds_q_executed_retest", "Q-MCP-EXECUTED RETEST", q_exec_r),
        )
    )

    visualizations: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str | None = None) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    def add_table(viz_id: str, ds: str, title: str, description: str, *, no_data: str) -> str:
        key, viz = table(viz_id, ds, title, description, no_data=no_data)
        visualizations[key] = viz
        return key

    empty_control = (
        "No indexed control.decision was found for this run. That is not DENY. "
        "It can be a schema failure before authorize, a wrong run.id, or an incomplete copy."
    )
    empty_tool = (
        "No indexed MCP execution event was found for this run. That does not "
        "automatically mean DENY. ERROR, schema failure, and export loss also look like zero rows."
    )
    empty_after = (
        "No indexed DENY followed later by mcp.started was found for this run. "
        "That does not independently prove the handler never executed. Runtime handler count remains authoritative."
    )
    empty_what = (
        "No indexed CTRL-MCP-RESULT-001 was found for this run. The dashboard will not "
        "invent derived authority, follow-on ALLOW, or prevented from an empty table."
    )
    empty_seq = (
        "No indexed control or mcp.* events were found for this run. Ordering cannot "
        "be shown. That is not a security outcome."
    )
    empty_authority = (
        "Q-MCP-RESULT-AUTHORITY returned zero rows. This hunt requires CTRL-MCP-RESULT-001. "
        "Zero rows is not safe, not DENY, and not proof derived authority was refused."
    )
    cap_what = (
        "Q-MCP-RESULT-AUTHORITY (data-driven What Happened). One row per run.id with "
        "initial grant, RESULT-001 decision, derived_authority helper, and follow-on fields."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision rows. executed here is the control-event field "
        "(false on ALLOW). It is not handler execution. ERROR is not DENY. "
        "MCP-005 runs show CTRL-MCP-001 and CTRL-MCP-RESULT-001 for lookup_policy. "
        "That extra RESULT-001 row is expected. Do not collapse it away."
    )
    cap_authority = (
        "Q-MCP-RESULT-AUTHORITY (primary MCP-005 hunt). derived_authority=present only when "
        "RESULT-001 reason contains result_derived_grant. Do not read follow-on ALLOW as "
        "server policy granting lookup_customer_tier. coded allowed_scope stays policy:read."
    )
    cap_tool = "Q-MCP-TOOL mcp.started rows. Zero rows is not automatically DENY."
    cap_executed = (
        "Q-MCP-EXECUTED. Control executed stays false on ALLOW. Read has_started "
        "and execution_state for whether the handler began. Extra RESULT-001 rows "
        "may appear for lookup_policy because this hunt groups by tool, not control.id. "
        "That is expected. Do not hide them. They are not a second handler invoke."
    )
    cap_seq = (
        "Ordered control then mcp.* events with hop.index and control_id. "
        "RESULT-001 appears before follow-on hop-1 CTRL-MCP-001 when present."
    )
    cap_result = "Q-MCP-RESULT mcp.completed preview (bounded 200 chars) and sha256."
    cap_result_trust = (
        "Q-MCP-RESULT-TRUST classification on mcp.completed. untrusted_data is a label, not authority."
    )

    add_md(
        "viz_learn",
        f"""
# LAB-MCP-005 Tool Result Trust

**WS-MCP-005** · GUIDED · schema **1.3.0** · INV-002 · CTRL-MCP-RESULT-001

**The tool was authorized and executed correctly.** Can data returned by that tool change what the agent is authorized to do next? **Defended answer: NO.** Results may influence reasoning. Results do not create authority.

**LIVE ids (copy the full UUID)**

- BASELINE `{BASELINE_ID}`
- ATTACK `{ATTACK_ID}`
- RETEST `{RETEST_ID}`

Ladder: MCP-001 tool → MCP-003 scope → MCP-004 resource → **MCP-005 data vs future authority**. MCP-005 begins **after** a legitimate execution. AUTHORIZED TOOL ≠ AUTHORITATIVE RESULT. DATA ≠ AUTHORITY. Splunk does **not** ALLOW or DENY a follow-on tool.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_server",
        f"""
# SERVER-OWNED AUTHORITY

Hop-0 CTRL-MCP-001: `lookup_policy` / `policy:read` / `lending-basics`.

Server-owned grant is coded before the handler runs.

{SERVER_OWNED}
""",
        title="SERVER-OWNED",
    )
    add_md(
        "viz_learn_result",
        f"""
# RESULT-DERIVED AUTHORITY (ATTACK only)

CTRL-MCP-RESULT-001 classifies the first `mcp.completed` payload.

On vulnerable ATTACK the overlay may ALLOW `result_derived_grant`.

That ALLOW is **not** a server grant of `lookup_customer_tier`.

Coded `allowed_scope` stays `policy:read`. Grant set stays `lookup_policy`.

**INTENTIONALLY VULNERABLE LAB BEHAVIOR** — controlled teaching, not production policy.
""",
        title="RESULT-DERIVED",
    )
    add_md(
        "viz_learn_trust",
        """
# Trust boundary

```text
REQUEST → CTRL-MCP-001 → lookup_policy → EXECUTION
        ↓
TOOL RESULT = DATA
        ↓
RESULT / DATA TRUST BOUNDARY
        ↓
FOLLOW-ON INTENT → CTRL-MCP-001
        ↓
FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION
```

PROVENANCE ≠ AUTHORITY. Rejected SPL: Q-MCP-RESULT-FOLLOWON (not published).
Hash ≠ trust. Preview is **BOUNDED** (200 chars; ATTACK hop-1 may show `lookup_customer_tie`). No indexed `allowed_tools`. No `gen_ai.tool.call.id`.
""",
        title="TRUST BOUNDARY",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**What the learner did:** POST /mcp/invoke for granted `lookup_policy`, scope `policy:read`, resource `lending-basics`, NORMAL fixture, profile defended, testbed.mode=BASELINE.

**First hop:** CTRL-MCP-001 **ALLOW** `tool_granted`. Handler runs. `mcp.completed` with `untrusted_data`.

**RESULT-001:** OBSERVE `result_is_data`. `derived_authority=absent`. No follow-on.

**Evidence:** Q-MCP-RESULT-AUTHORITY on token **BASELINE**.

Validated reference: `{BASELINE_ID}`. NORMAL hash `{NORMAL_HASH}`.

{ALLOW_NOT_EXEC}
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_what",
        "ds_what_baseline",
        "What Happened? Q-MCP-RESULT-AUTHORITY",
        cap_what + " Expect initial_decision ALLOW, derived_authority absent, followon_execution_observation no_followon.",
        no_data=empty_what,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_baseline",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect hop-0 ALLOW tool_granted plus RESULT-001 OBSERVE.",
        no_data=empty_control,
    )
    add_table(
        "viz_baseline_tool",
        "ds_q_tool_baseline",
        "Q-MCP-TOOL",
        cap_tool + " Expect lookup_policy mcp.started.",
        no_data=empty_tool,
    )
    add_table(
        "viz_baseline_exec",
        "ds_q_executed_baseline",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect hop-0 execution_state=mcp.completed.",
        no_data=empty_tool,
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK

**The initial tool invocation was NOT the security failure.** lookup_policy was legitimately ALLOW'd and executed.

Same first request as BASELINE. MALICIOUS fixture `{MALICIOUS_HASH}`. Profile **vulnerable**. mode=ATTACK.

```text
lookup_policy → authorized → executes
        ↓
malicious result DATA
        ↓
INTENTIONALLY VULNERABLE interpretation
        ↓
result-derived per-run authority (NOT server policy)
        ↓
lookup_customer_tier → ALLOW → handler executes
```

SERVER-OWNED authority: **unchanged** (`policy:read` / preview `lookup_policy`).  
RESULT-DERIVED authority: **present**. Follow-on ALLOW is overlay, not a coded grant.

Runtime follow-on handler **1**. Splunk: hop-1 `mcp.completed_observed`.

Validated: `{ATTACK_ID}`. Tables use the **ATTACK** token.
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_what",
        "ds_what_attack",
        "What Happened? Q-MCP-RESULT-AUTHORITY",
        cap_what + " Expect derived_authority present, followon_tool lookup_customer_tier, followon_decision ALLOW.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_attack",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect hop-0 ALLOW and hop-1 labeled fail-open ALLOW. Hop-1 ALLOW is not a server grant.",
        no_data=empty_control,
    )
    add_table(
        "viz_attack_tool",
        "ds_q_tool_attack",
        "Q-MCP-TOOL",
        cap_tool + " Expect mcp.started for lookup_policy and lookup_customer_tier.",
        no_data=empty_tool,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_executed_attack",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect has_started=1 on follow-on tool.",
        no_data=empty_tool,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Use **Hunt run.id** (defaults to BASELINE). Tables are telemetry, not a story.

Read sequence top to bottom. You must see hop-0 control, first `mcp.completed`, CTRL-MCP-RESULT-001, then hop-1 control when follow-on intent exists.

Minimum fields: run_id, sequence, event.name, hop, control_id, tool, decision, reason, result_trust, attempted, executed, outcome.

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_table("viz_observe_seq", "ds_observe_seq", "Control then MCP events (ordered)", cap_seq, no_data=empty_seq)
    add_table("viz_observe_authority", "ds_q_result_authority", "Q-MCP-RESULT-AUTHORITY", cap_authority, no_data=empty_authority)
    add_table("viz_observe_result", "ds_q_result", "Q-MCP-RESULT (bounded preview + hash)", cap_result, no_data=empty_tool)
    add_table("viz_observe_who", "ds_q_who", "Q-MCP-WHO", "Principal / agent / tool identity. Extra lookup_policy row without mcp.method.name is RESULT-001. Not a second event.", no_data=empty_control)

    add_md(
        "viz_hunt_md",
        f"""
# HUNT

**Question:** Did result-derived data influence authorization, and what follow-on decision and execution were indexed?

**Primary hunt:** Q-MCP-RESULT-AUTHORITY. **Rejected / not published:** Q-MCP-RESULT-FOLLOWON (duplicate). No hunt invents `allowed_tools`.

Q-MCP-SCOPE and Q-MCP-RESOURCE-AUTHZ are not bound here. SCOPE on hop-1 ATTACK shows `known_but_ungranted` with ALLOW — that is **not** MCP-003. RESOURCE-AUTHZ may add RESULT-001 rows. Extra EXECUTED RESULT-001 rows are shown, not hidden.

{ALLOW_NOT_EXEC} {DATA_NOT_AUTHORITY}

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table("viz_hunt_authority", "ds_q_result_authority", "Q-MCP-RESULT-AUTHORITY (primary MCP-005 hunt)", cap_authority, no_data=empty_authority)
    add_table("viz_hunt_authz", "ds_q_authz", "Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_hunt_result_trust", "ds_q_result_trust", "Q-MCP-RESULT-TRUST", cap_result_trust, no_data=empty_tool)
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED", cap_executed, no_data=empty_tool)
    add_table("viz_hunt_tool", "ds_q_tool", "Q-MCP-TOOL", cap_tool, no_data=empty_tool)

    add_md(
        "viz_detect_md",
        """
# DETECT — DETECTION ANALYZED — NO NEW DETECTOR

No notable event. **No DET-MCP-005.** This dashboard does **not** enable DET-MCP-001.

DET-MCP-001 detects **DENY → later execution**. MCP-005 ATTACK is malicious result → result-derived authority → **ALLOW → execution**. DET-MCP-001 is expected **silent**. That is not a detector failure. It is a different invariant.

Not every security failure looks like DENY → bypass → execution. An ALLOW can still be security-relevant when the authority used to produce it was illegitimate.

**LIVE Phase 6C (MEASURED):** BASELINE **0** · ATTACK **0** · RETEST **0**. Zero rows is not "no security violation occurred."

Right table: **SIMULATED** `| makeresults`. **NOT INDEXED.** Not a LIVE MCP-005 attack. Not OBSERVED runtime.
""",
        title="STEP 5 DETECT",
    )
    add_md(
        "viz_detect_why",
        """
# Why no DET-MCP-005

A detector needs deterministic evidence, defensible fields, reliable correlation, acceptable false-positive semantics, and a clearly defined invariant.

Phase 6C: **DETECTION ANALYZED — NO NEW DETECTOR.** No indexed `allowed_tools`. Correlation is lab-shaped (two different tool names). A reason-string detector would overclaim.

Hunt is sufficient. DET-MCP-001 stays unchanged. This project does not create detectors to make a workshop look complete.
""",
        title="NO NEW DETECTOR",
    )
    add_table(
        "viz_detect_live",
        "ds_q_after_deny",
        "Q-MCP-AFTER-DENY (indexed hunt)",
        "Investigation query. LIVE MCP-005 specimens: 0 rows. DET-MCP-001 silent on ATTACK overlay ALLOW.",
        no_data=empty_after,
    )
    add_table(
        "viz_detect_sim",
        "ds_det_mcp_001_sim",
        "DET-MCP-001-POSITIVE-CONTROL (SIMULATED)",
        "Always one fixture row labeled SIMULATED. DENY then mcp.started. Do not treat as a live incident.",
        no_data="SIMULATED search returned no fixture row. Re-check DET-MCP-001-POSITIVE-CONTROL.spl (makeresults).",
    )

    add_md(
        "viz_defend",
        f"""
# DEFEND

**THE AI CAN INTERPRET THE DATA. THE DATA STILL DOES NOT GET TO CREATE PERMISSION.**

This lab does **not** prove model prompt-injection resistance. It proves an **authorization boundary**.

## Defense in depth

1. Tool result remains **DATA**. It cannot create legitimate server authority.
2. Follow-on operations require **normal** CTRL-MCP-001.

```text
malicious result
      ↓
follow-on intent
      ↓
lookup_customer_tier
      ↓
CTRL-MCP-001
      ↓
DENY tool_not_granted
      ↓
handler does not execute
```

## SERVER AUTHORITY EVIDENCE — LIMITED

No indexed `allowed_tools`. Use coded `allowed_scope=policy:read` and hop-1 **BOUNDED PREVIEW** listing `lookup_policy`. Do not invent a grant list. Splunk did **not** prevent the action. The control did. Rejected SPL: Q-MCP-RESULT-FOLLOWON (not published).
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_defend_evidence",
        """
# Data cannot create permission

Tool result bytes may suggest a follow-on tool name. They cannot widen the server-owned grant.

Markers are lab-only closed-prefix extraction. Unknown tool names after the marker do not execute.

Inspecting a tool result after the handler cannot be DENY of that invoke. Splunk searches do not move the control.
""",
        title="INV-002",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

Same initial request as ATTACK. **Same MALICIOUS fixture** `{MALICIOUS_HASH}`. Profile **defended**. mode=RETEST.

SAME HOSTILE DATA + DIFFERENT SECURITY PROFILE = DIFFERENT AUTHORIZATION OUTCOME.

- initial lookup_policy: ALLOW, execution observed
- result: same malicious data (hash identity, not trust)
- result-derived authority: **absent**
- follow-on: lookup_customer_tier
- authorization: **DENY** `tool_not_granted`
- runtime follow-on handler count: **0** (authoritative)
- Splunk: **no indexed follow-on execution event observed** (corroboration only)

Do not say Splunk proved the handler never ran.

Validated: `{RETEST_ID}`. Tables use the **RETEST** token.
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_what",
        "ds_what_retest",
        "What Happened? Q-MCP-RESULT-AUTHORITY",
        cap_what + " Expect derived_authority absent, followon_decision DENY tool_not_granted.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_retest",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect hop-1 DENY tool_not_granted.",
        no_data=empty_control,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_retest",
        "Q-MCP-TOOL",
        "Q-MCP-TOOL. No indexed hop-1 mcp.started observed. That is Splunk corroboration. Runtime follow-on handler count = 0 is authoritative.",
        no_data=empty_tool,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_executed_retest",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect follow-on has_started=0.",
        no_data=empty_tool,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

Three-way comparison from Phase 6C LIVE evidence. Do not infer empty cells.

SAME HOSTILE DATA + DIFFERENT SECURITY PROFILE = DIFFERENT AUTHORIZATION OUTCOME.

ATTACK follow-on ALLOW is overlay, **not** legitimate server policy. Hash = content identity, not trust, not authority. SERVER AUTHORITY EVIDENCE — LIMITED. Hop-1 ATTACK preview is **BOUNDED**. No `gen_ai.tool.call.id`.

{ALLOW_NOT_EXEC} {DATA_NOT_AUTHORITY}
""",
        title="BEFORE / AFTER",
    )
    add_md(
        "viz_cmp_card_base",
        f"""
# BASELINE

**Profile:** defended · **Mode:** BASELINE

- Initial: `lookup_policy` · ALLOW · executed
- Result: **normal** (hash last 8 `cdbeb68e`)
- Server authority: unchanged
- Derived authority: **none**
- Follow-on: none
- Follow-on auth: N/A
- Follow-on execution: none

Validated: `{BASELINE_ID}`
""",
        title="BASELINE",
    )
    add_md(
        "viz_cmp_card_atk",
        f"""
# ATTACK

**Profile:** vulnerable · **Mode:** ATTACK

- Initial: `lookup_policy` · ALLOW · executed
- Result: **malicious** (hash last 8 `547230c358`)
- Server authority: **unchanged**
- Derived authority: **PRESENT** (overlay)
- Follow-on: `lookup_customer_tier`
- Follow-on auth: ALLOW (not server grant)
- Follow-on execution: YES (runtime **1**)

**INTENTIONALLY VULNERABLE LAB BEHAVIOR**

Validated: `{ATTACK_ID}`
""",
        title="ATTACK",
    )
    add_md(
        "viz_cmp_card_rt",
        f"""
# RETEST

**Profile:** defended · **Mode:** RETEST

- Initial: `lookup_policy` · ALLOW · executed
- Result: **same malicious** (same hash last 8 `547230c358`)
- Server authority: unchanged
- Derived authority: **none**
- Follow-on: `lookup_customer_tier`
- Follow-on auth: DENY `tool_not_granted`
- Follow-on execution: NO (runtime **0**)

Splunk: no indexed follow-on execution event observed.

Validated: `{RETEST_ID}`
""",
        title="RETEST",
    )
    add_table(
        "viz_cmp_base",
        "ds_q_authority_baseline",
        "BASELINE Q-MCP-RESULT-AUTHORITY",
        cap_authority + " Expect derived_authority absent.",
        no_data=empty_authority,
    )
    add_table(
        "viz_cmp_atk",
        "ds_q_authority_attack",
        "ATTACK Q-MCP-RESULT-AUTHORITY",
        cap_authority + " Expect derived_authority present.",
        no_data=empty_authority,
    )
    add_table(
        "viz_cmp_rt",
        "ds_q_authority_retest",
        "RETEST Q-MCP-RESULT-AUTHORITY",
        cap_authority + " Expect followon_decision DENY.",
        no_data=empty_authority,
    )

    add_md(
        "viz_prove",
        f"""
# PROVE

Evidence hierarchy. Splunk does not manufacture runtime truth.

```text
RUNTIME  →  LOCAL EVIDENCE  →  OTLP  →  SPLUNK  →  HUNT  →  SECURITY EVIDENCE
```

1. **RUNTIME.** Handler counts. Authoritative for execution / non-execution in this lab. {RUNTIME_AUTH}
2. **LOCAL.** artifacts/<run-id>/events.jsonl
3. **EXPORT.** export.json (`otlp.ok` is not Splunk success; packs keep `splunk.verified=false`)
4. **SPLUNK.** Completeness = local count vs `dc(_raw)`
5. **SEARCH.** Q-MCP-RESULT-AUTHORITY. Zero rows follow no-data semantics.
6. **DETECTION.** DET-MCP-001: no indexed DENY→start found. Silent on overlay ALLOW. 0 hits ≠ system is secure. **NO NEW DETECTOR.**

LIVE A/B/C are OBSERVED/MEASURED. DETECT right table is **SIMULATED**.

## Correlation limitation

No `gen_ai.tool.call.id`. This lab uses two **different** tool names plus `run.id` + `sequence` + `hop.index`. Repeated same-tool invocations would need stronger per-invocation correlation.

## Limitations

- no indexed allowed_tools
- 200-character bounded preview (`lookup_customer_tie` on ATTACK hop-1)
- Q-MCP-EXECUTED extra RESULT-001 rows
- Q-MCP-RESOURCE-AUTHZ extra RESULT-001 rows (hunt not bound here)
- Splunk absence of mcp.started is corroboration only
- Q-MCP-RESULT-FOLLOWON rejected / not published
- no DET-MCP-005

Knowledge check: learning/level_1/LAB-MCP-005/knowledge-check.md

Validated: BASELINE `{BASELINE_ID}` · ATTACK `{ATTACK_ID}` · RETEST `{RETEST_ID}`.
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_what",
        "ds_q_result_authority",
        "What Happened? Q-MCP-RESULT-AUTHORITY (Hunt run.id)",
        cap_what,
        no_data=empty_what,
    )

    definition = {
        "title": "LAB-MCP-005 Tool Result Trust",
        "description": (
            "WS-MCP-005 Dashboard Studio workshop. Reuses validated Q-MCP investigation SPL "
            "plus Q-MCP-RESULT-AUTHORITY. Saved search DET-MCP-001 is packaged disabled; this "
            "dashboard does not enable it. No DET-MCP-005. Splunk does not ALLOW or DENY a tool."
        ),
        "defaults": {
            "visualizations": {
                "splunk.table": {
                    "options": {
                        "backgroundColor": WHITE,
                        "headerBackgroundColor": NAVY,
                        "headerTextColor": WHITE,
                    }
                },
                "splunk.markdown": {"options": {"fontColor": TEXT, "fontSize": "large"}},
            }
        },
        "inputs": {
            "input_run_id": {
                "type": "input.text",
                "title": "Hunt",
                "options": {"token": "run_id", "defaultValue": BASELINE_ID},
            },
            "input_baseline_run_id": {
                "type": "input.text",
                "title": "BASELINE",
                "options": {"token": "baseline_run_id", "defaultValue": BASELINE_ID},
            },
            "input_attack_run_id": {
                "type": "input.text",
                "title": "ATTACK",
                "options": {"token": "attack_run_id", "defaultValue": ATTACK_ID},
            },
            "input_retest_run_id": {
                "type": "input.text",
                "title": "RETEST",
                "options": {"token": "retest_run_id", "defaultValue": RETEST_ID},
            },
        },
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "options": {
                "submitButton": True,
                "submitOnDashboardLoad": True,
                "showTitleAndDescription": True,
            },
            "globalInputs": [
                "input_run_id",
                "input_baseline_run_id",
                "input_attack_run_id",
                "input_retest_run_id",
            ],
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_learn", "label": "LEARN"},
                    {"layoutId": "layout_baseline", "label": "BASELINE"},
                    {"layoutId": "layout_attack", "label": "ATTACK"},
                    {"layoutId": "layout_observe", "label": "OBSERVE"},
                    {"layoutId": "layout_hunt", "label": "HUNT"},
                    {"layoutId": "layout_detect", "label": "DETECT"},
                    {"layoutId": "layout_defend", "label": "DEFEND"},
                    {"layoutId": "layout_retest", "label": "RETEST"},
                    {"layoutId": "layout_compare", "label": "COMPARE"},
                    {"layoutId": "layout_prove", "label": "PROVE"},
                ],
            },
            "layoutDefinitions": {
                "layout_learn": layout(
                    [
                        block("viz_learn", 0, 0, FULL, 340),
                        block("viz_learn_server", 0, 340, THIRD, 380),
                        block("viz_learn_result", THIRD, 340, THIRD, 380),
                        block("viz_learn_trust", THIRD * 2, 340, THIRD, 380),
                    ],
                    740,
                ),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 320),
                        block("viz_baseline_what", 0, 320, FULL, 280),
                        block("viz_baseline_authz", 0, 600, HALF, 260),
                        block("viz_baseline_tool", HALF, 600, HALF, 260),
                        block("viz_baseline_exec", 0, 860, FULL, 280),
                    ],
                    1160,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 420),
                        block("viz_attack_what", 0, 420, FULL, 280),
                        block("viz_attack_authz", 0, 700, HALF, 260),
                        block("viz_attack_tool", HALF, 700, HALF, 260),
                        block("viz_attack_exec", 0, 960, FULL, 280),
                    ],
                    1260,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, FULL, 240),
                        block("viz_observe_seq", 0, 240, FULL, 380),
                        block("viz_observe_authority", 0, 620, FULL, 280),
                        block("viz_observe_result", 0, 900, FULL, 240),
                        block("viz_observe_who", 0, 1140, FULL, 240),
                    ],
                    1400,
                ),
                "layout_hunt": layout(
                    [
                        block("viz_hunt_md", 0, 0, FULL, 320),
                        block("viz_hunt_authority", 0, 320, FULL, 280),
                        block("viz_hunt_authz", 0, 600, HALF, 260),
                        block("viz_hunt_result_trust", HALF, 600, HALF, 260),
                        block("viz_hunt_exec", 0, 860, HALF, 260),
                        block("viz_hunt_tool", HALF, 860, HALF, 260),
                    ],
                    1140,
                ),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, FULL, 360),
                        block("viz_detect_live", 0, 360, HALF, 340),
                        block("viz_detect_sim", HALF, 360, HALF, 340),
                        block("viz_detect_why", 0, 700, FULL, 280),
                    ],
                    1000,
                ),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 560),
                        block("viz_defend_evidence", 0, 560, FULL, 260),
                    ],
                    840,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 400),
                        block("viz_retest_what", 0, 400, FULL, 280),
                        block("viz_retest_authz", 0, 680, HALF, 260),
                        block("viz_retest_tool", HALF, 680, HALF, 260),
                        block("viz_retest_exec", 0, 940, FULL, 280),
                    ],
                    1240,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 240),
                        block("viz_cmp_card_base", 0, 240, THIRD, 400),
                        block("viz_cmp_card_atk", THIRD, 240, THIRD, 400),
                        block("viz_cmp_card_rt", THIRD * 2, 240, THIRD, 400),
                        block("viz_cmp_base", 0, 640, THIRD, 300),
                        block("viz_cmp_atk", THIRD, 640, THIRD, 300),
                        block("viz_cmp_rt", THIRD * 2, 640, THIRD, 300),
                    ],
                    960,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 720),
                        block("viz_prove_what", 0, 720, FULL, 280),
                    ],
                    1020,
                ),
            },
        },
        "applicationProperties": {
            "collapseNavigation": False,
            "downsampleVisualizations": False,
        },
    }
    _ = (TEAL, SECONDARY, BORDER)
    return definition


def write_xml(definition: dict) -> None:
    payload = json.dumps(definition, indent=2, ensure_ascii=False)
    if "]]>" in payload:
        raise ValueError("definition contains CDATA terminator")
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<dashboard version="2" theme="light">\n'
        "  <label>LAB-MCP-005 Tool Result Trust</label>\n"
        "  <description>WS-MCP-005. Validated Q-MCP SPL plus Q-MCP-RESULT-AUTHORITY. DET-MCP-001 packaged disabled. No DET-MCP-005. Splunk does not ALLOW or DENY a tool.</description>\n"
        "  <definition><![CDATA[\n"
        f"{payload}\n"
        "  ]]></definition>\n"
        "</dashboard>\n"
    )
    OUT_XML.parent.mkdir(parents=True, exist_ok=True)
    OUT_XML.write_text(xml, encoding="utf-8")


def main() -> None:
    definition = build()
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(definition, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_xml(definition)
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
