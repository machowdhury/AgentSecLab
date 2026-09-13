#!/usr/bin/env python3
"""Build the LAB-MCP-001 Dashboard Studio definition from validated Q-MCP SPL.

The only SPL change for Q-MCP files is replacing __RUN_ID__ with a quoted Studio
token. Dashboard-only display searches reuse the same index, event.name filters,
and mvindex(mvdedup(...),0) collapse. They do not change Q-MCP semantics.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_mcp_001.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

BASELINE_ID = "163d11e2-e751-4282-9406-19b490542ed4"
ATTACK_ID = "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49"
RETEST_ID = "7a1d37b5-d589-4dfd-8322-25ebd0152dbc"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_HUNT = (
    "Hunt `run.id` defaults to the BASELINE specimen so this page is not an error "
    "state. Replace it and Submit to hunt another complete copy. Zero rows means "
    "no matching indexed events for that id. Zero rows is not DENY and is not "
    "proof the handler never ran."
)
ALLOW_NOT_EXEC = (
    "ALLOW is the control decision. Tool execution begins at `mcp.started` "
    "(`executed=true` on that event). Do not read ALLOW as execution. "
    "`mcp.completed` is success of a begun call. `mcp.failed` is execution then "
    "error, not prevention."
)
RUNTIME_AUTH = (
    "Runtime handler count is authoritative proof of non-execution. Splunk "
    "absence of `mcp.started` is corroboration only, and only on a complete copy."
)


def load_spl(name: str) -> str:
    return (SEARCH_DIR / name).read_text(encoding="utf-8").strip()


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
    """description is always visible. no_data is Studio empty-state only."""
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
    """Same control+mcp filter as Q-MCP-EXECUTED, without collapsing to one row."""
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="${token}$" ("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval attempted=mvindex(mvdedup('agentsec.operation.attempted'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| table sequence, run_id, event_name, tool, decision, reason, attempted, executed, outcome
| sort sequence"""


def what_happened_spl(token: str) -> str:
    """Telemetry summary from indexed control + mcp fields. Not LLM prose."""
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="${token}$" ("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval profile=mvindex(mvdedup('agentsec.security.profile'),0)
| eval mode=mvindex(mvdedup('agentsec.testbed.mode'),0)
| eval agent=mvindex(mvdedup('gen_ai.agent.id'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| eval result_trust=mvindex(mvdedup('agentsec.mcp.result.trust'),0)
| eval is_started=if(event_name="agentsec.mcp.started",1,0)
| eval is_completed=if(event_name="agentsec.mcp.completed",1,0)
| eval is_failed=if(event_name="agentsec.mcp.failed",1,0)
| eventstats max(is_started) as has_started, max(is_completed) as has_completed, max(is_failed) as has_failed, latest(eval(if(event_name="agentsec.mcp.completed",result_trust,null()))) as completed_trust by run_id, tool
| where event_name="agentsec.control.decision"
| eval execution_state=case(has_completed=1,"mcp.completed",has_failed=1,"mcp.failed",has_started=1,"mcp.started",decision="ALLOW","ALLOW_execution_not_proven_in_this_copy",1=1,"no_mcp_execution_event")
| eval result_trust=if(isnull(completed_trust),"no_completed_result",completed_trust)
| table run_id, profile, mode, agent, tool, decision, reason, requested_scope, allowed_scope, execution_state, outcome, result_trust"""


def what_identity_spl(token: str) -> str:
    return what_happened_spl(token) + "\n| table run_id, profile, mode, agent, tool"


def what_decision_spl(token: str) -> str:
    return (
        what_happened_spl(token)
        + "\n| table run_id, decision, reason, requested_scope, allowed_scope, execution_state, outcome, result_trust"
    )


def build() -> dict:
    q_who = bind_run_id(load_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_scope = bind_run_id(load_spl("Q-MCP-SCOPE.spl"), "run_id")
    q_params = bind_run_id(load_spl("Q-MCP-PARAMS.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_after = bind_run_id(load_spl("Q-MCP-AFTER-DENY.spl"), "run_id")
    q_result = bind_run_id(load_spl("Q-MCP-RESULT.spl"), "run_id")
    q_trust = bind_run_id(load_spl("Q-MCP-RESULT-TRUST.spl"), "run_id")
    q_authz_b = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "baseline_run_id")
    q_authz_a = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "attack_run_id")
    q_authz_r = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "retest_run_id")
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
            search_ds("ds_q_scope", "Q-MCP-SCOPE", q_scope),
            search_ds("ds_q_params", "Q-MCP-PARAMS", q_params),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_after_deny", "Q-MCP-AFTER-DENY", q_after),
            search_ds(
                "ds_det_mcp_001_sim",
                "DET-MCP-001-POSITIVE-CONTROL",
                load_spl("DET-MCP-001-POSITIVE-CONTROL.spl"),
            ),
            search_ds("ds_q_result", "Q-MCP-RESULT", q_result),
            search_ds("ds_q_result_trust", "Q-MCP-RESULT-TRUST", q_trust),
            search_ds("ds_observe_seq", "MCP observe sequence", observe_sequence_spl("run_id")),
            search_ds("ds_what_identity", "What Happened identity hunt", what_identity_spl("run_id")),
            search_ds("ds_what_decision", "What Happened decision hunt", what_decision_spl("run_id")),
            search_ds("ds_q_authz_baseline", "Q-MCP-AUTHZ BASELINE", q_authz_b),
            search_ds("ds_q_authz_attack", "Q-MCP-AUTHZ ATTACK", q_authz_a),
            search_ds("ds_q_authz_retest", "Q-MCP-AUTHZ RETEST", q_authz_r),
            search_ds("ds_q_tool_baseline", "Q-MCP-TOOL BASELINE", q_tool_b),
            search_ds("ds_q_tool_attack", "Q-MCP-TOOL ATTACK", q_tool_a),
            search_ds("ds_q_tool_retest", "Q-MCP-TOOL RETEST", q_tool_r),
            search_ds("ds_q_executed_baseline", "Q-MCP-EXECUTED BASELINE", q_exec_b),
            search_ds("ds_q_executed_attack", "Q-MCP-EXECUTED ATTACK", q_exec_a),
            search_ds("ds_q_executed_retest", "Q-MCP-EXECUTED RETEST", q_exec_r),
            search_ds("ds_what_baseline_id", "What Happened identity BASELINE", what_identity_spl("baseline_run_id")),
            search_ds("ds_what_baseline_dec", "What Happened decision BASELINE", what_decision_spl("baseline_run_id")),
            search_ds("ds_what_attack_id", "What Happened identity ATTACK", what_identity_spl("attack_run_id")),
            search_ds("ds_what_attack_dec", "What Happened decision ATTACK", what_decision_spl("attack_run_id")),
            search_ds("ds_what_retest_id", "What Happened identity RETEST", what_identity_spl("retest_run_id")),
            search_ds("ds_what_retest_dec", "What Happened decision RETEST", what_decision_spl("retest_run_id")),
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
        "No indexed violation was found. That does not independently prove the "
        "handler never executed. Runtime handler count remains authoritative."
    )
    empty_what = (
        "No indexed control.decision was found for this run. The dashboard will not "
        "invent DENY, executed, or prevented from an empty table."
    )
    empty_seq = (
        "No indexed control or mcp.* events were found for this run. Ordering cannot "
        "be shown. That is not a security outcome."
    )
    cap_what_id = (
        "Indexed identity fields for this run. Not a story. Empty is not DENY."
    )
    cap_what_dec = (
        "Indexed decision fields. `decision` is the control token. `execution_state` "
        "is derived from mcp.* presence in this copy. Control `executed` is not this table."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision row. `executed` here is the control-event field "
        "(false on ALLOW). It is not handler execution."
    )
    cap_tool = (
        "Q-MCP-TOOL `mcp.started` rows. Zero rows is not automatically DENY."
    )
    cap_executed = (
        "Q-MCP-EXECUTED. Control `executed` stays false on ALLOW. Read `has_started` "
        "and `execution_state` for whether the handler began. Scroll right if needed."
    )
    cap_seq = (
        "Ordered control then mcp.* events. Same event.name filter as Q-MCP-EXECUTED "
        "without collapsing rows. You must see control.decision before mcp.started when execution occurred."
    )

    add_md(
        "viz_learn",
        f"""
# LAB-MCP-001 MCP tool authorization

**WS-MCP-001** · GUIDED · schema `agentsec.security_event` **1.1.0** · INV-001 / INV-002 / INV-007 / INV-008 · MCP-001 / MCP-002 · CTRL-MCP-001

Splunk is the hunt workbench. Splunk does **not** ALLOW or DENY a tool. AcmeBank `POST /mcp/invoke` is the enforcement point.

Transport today is **in-process JSON-RPC `tools/call`**. It is a real authorize-then-execute path. It is not a full remote MCP product.

## What you will learn

- `tools/call` is a named tool plus arguments, not a prompt regex.
- Registered is not the same as granted.
- Registered + granted → ALLOW. Registered + not granted → DENY. Not registered → ERROR.
- ALLOW is not execution. `mcp.started` means the handler began. `mcp.failed` is not prevention.
- Authorization must run **before** the tool handler.
- Tool results are `untrusted_data`. They do not become a new grant.
- Splunk is evidence of a copy. Missing Splunk events alone cannot prove prevention.

## Validated specimen ids (Phase 3C LIVE)

Copy the full UUID. Token fields may ellipsis; these bullets do not. Do not hunt loan-pipeline ids here.

- **BASELINE** `{BASELINE_ID}` — defended, `lookup_policy`, ALLOW, handler=1, `mcp.completed`
- **ATTACK** `{ATTACK_ID}` — vulnerable, `lookup_customer_tier`, labeled fail-open ALLOW, handler=1
- **RETEST** `{RETEST_ID}` — defended, same ungranted tool, DENY, handler=0, no `mcp.started`

`lookup_customer_tier` is not malicious by itself. The problem is **unauthorized invocation**.

## Trust path

```text
User / HTTP POST /mcp/invoke
        │  tool, arguments, requested_scope, user_id
        ▼
MCP Policy Agent (acme-agent-mcp-001)
        ▼
MCP Client  JSON-RPC tools/call
        ▼
CTRL-MCP-001  (server-owned policy)
        │
   ALLOW → MCP Server execute → Tool Handler
   DENY / ERROR → stop, no mcp.started, handler count unchanged
        ▼
Result (untrusted_data)
        ▼
OTel → Splunk (observe only)
```

## AUTHORIZATION DECISION vs TOOL EXECUTION

Authorization is `event.name=agentsec.control.decision` (`ALLOW` / `DENY` / `ERROR`).
Execution begins only after ALLOW, at `event.name=agentsec.mcp.started`.

{ALLOW_NOT_EXEC}

Tabs: LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE.
""",
        title="LEARN",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**What the learner did:** `POST /mcp/invoke` for granted tool `lookup_policy`, scope `policy:read`, profile `defended`, `testbed.mode=BASELINE`.

**What happened:** CTRL-MCP-001 ALLOW `tool_granted`. Handler began. `mcp.started` then `mcp.completed`. Runtime handler count **1**.

**Why it was allowed:** the tool is registered **and** granted to `acme-agent-mcp-001`.

**Evidence:** What Happened table (indexed fields), then Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED for token **BASELINE**.

Validated reference: `{BASELINE_ID}`.

{ALLOW_NOT_EXEC}

Do not imply ALLOW itself proves execution. Execution is `mcp.started`.
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_what_id",
        "ds_what_baseline_id",
        "What Happened? identity (indexed fields)",
        cap_what_id + " Expect agent acme-agent-mcp-001, tool lookup_policy, profile defended, mode BASELINE.",
        no_data=empty_what,
    )
    add_table(
        "viz_baseline_what_dec",
        "ds_what_baseline_dec",
        "What Happened? decision (indexed fields)",
        cap_what_dec + " Expect decision ALLOW, reason tool_granted, execution_state mcp.completed, result_trust untrusted_data.",
        no_data=empty_what,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_baseline",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect ALLOW, tool_granted, scopes both policy:read.",
        no_data=empty_control,
    )
    add_table(
        "viz_baseline_tool",
        "ds_q_tool_baseline",
        "Q-MCP-TOOL",
        cap_tool + " Expect one mcp.started row, executed=true on that event.",
        no_data=empty_tool,
    )
    add_table(
        "viz_baseline_exec",
        "ds_q_executed_baseline",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect execution_state=mcp.completed.",
        no_data=empty_tool,
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK

**Request:** same MCP agent asks for `lookup_customer_tier` with scope `customer:read`.

This tool is **registered** in the lab registry. It is **not granted** to this agent. That is unauthorized invocation, not a “malicious tool” by itself. This is a controlled lab authorization failure, not a production exploit.

**Vulnerable profile:** CTRL-MCP-001 intentionally **fails open** with a labeled ALLOW reason `vulnerable_profile_fail_open:CTRL-MCP-001…`. The handler begins. `mcp.completed` is observed. Runtime handler count **1**.

**Validated reference:** `{ATTACK_ID}` — profile `vulnerable`, `testbed.mode=ATTACK`.

Tables on this tab use the **ATTACK** token (not Hunt). Predict DENY vs fail-open before you read them.

Splunk does **not** send this request. Fire `POST /mcp/invoke` on AcmeBank with `AGENTSEC_SECURITY_PROFILE=vulnerable`.
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_what_id",
        "ds_what_attack_id",
        "What Happened? identity (indexed fields)",
        cap_what_id + " Expect tool lookup_customer_tier, profile vulnerable, mode ATTACK.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_what_dec",
        "ds_what_attack_dec",
        "What Happened? decision (indexed fields)",
        cap_what_dec + " Expect labeled fail-open ALLOW and execution_state mcp.completed. ALLOW is not a grant.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_attack",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect labeled fail-open ALLOW. requested customer:read, allowed still policy:read.",
        no_data=empty_control,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_executed_attack",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect has_started=1 and execution_state=mcp.completed. Fail-open executed the handler; it did not create a grant.",
        no_data=empty_tool,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Use **Hunt run.id** (defaults to BASELINE). Tables are telemetry, not a story.

Read sequence top to bottom. You must see `agentsec.control.decision` **before** `agentsec.mcp.started` when execution occurred.

Distinguish: ALLOW without start in this copy; ALLOW then `mcp.started`; `mcp.completed`; `mcp.failed`; DENY with no mcp.*; ERROR with no mcp.*.

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_table(
        "viz_observe_seq",
        "ds_observe_seq",
        "Control then MCP events (ordered)",
        cap_seq,
        no_data=empty_seq,
    )
    add_table(
        "viz_observe_authz",
        "ds_q_authz",
        "Q-MCP-AUTHZ",
        cap_authz,
        no_data=empty_control,
    )
    add_table(
        "viz_observe_tool",
        "ds_q_tool",
        "Q-MCP-TOOL",
        cap_tool,
        no_data=empty_tool,
    )

    add_md(
        "viz_hunt_md",
        f"""
# HUNT

**Question:** Which principal and agent requested which tool, what was decided, what scope was asked vs coded, and did execution begin?

Filter is already `agentsec.run.id`. Do not hunt `session.id`.

{ALLOW_NOT_EXEC}

Zero Q-MCP-TOOL rows does **not** automatically mean DENY.

If Splunk is empty, check `artifacts/<run-id>/export.json`. Do not conclude DENY.

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table("viz_hunt_who", "ds_q_who", "Q-MCP-WHO", "Principal, agent, tool, method, profile, mode.", no_data=empty_control)
    add_table(
        "viz_hunt_scope",
        "ds_q_scope",
        "Q-MCP-SCOPE",
        "Requested vs coded allowed scope. allowed_scope is not rewritten by fail-open.",
        no_data=empty_control,
    )
    add_table(
        "viz_hunt_params",
        "ds_q_params",
        "Q-MCP-PARAMS",
        "Preview + hash only. No gen_ai.tool.call.arguments. Not a secret dump.",
        no_data=empty_control,
    )
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED", cap_executed, no_data=empty_tool)
    add_table(
        "viz_hunt_result",
        "ds_q_result",
        "Q-MCP-RESULT",
        "Safe result metadata. Empty means no mcp.completed/failed in this copy.",
        no_data=empty_tool,
    )
    add_table(
        "viz_hunt_trust",
        "ds_q_result_trust",
        "Q-MCP-RESULT-TRUST",
        "Expect untrusted_data on completed results. Empty is not 'trusted'. Preparatory; not MCP-005.",
        no_data="No completed MCP result in this copy. That is not a trust upgrade.",
    )

    add_md(
        "viz_detect_md",
        """
# DETECT — investigation hunt and one operational detection

No notable event. No ES notable. No automatic remediation.

**Invariant:** if CTRL-MCP-001 returns DENY for a run/tool, no later `mcp.started` may occur for that same run/tool (`sequence` greater than the DENY).

## HUNT vs DETECTION

- **HUNT** (`Q-MCP-AFTER-DENY` on Hunt run.id): asks whether the violation occurred in this copy. Left table. Validated LIVE specimens: **0** rows. Zero rows is not independent proof the handler never ran.
- **DETECTION** (`DET-MCP-001`, saved search `AgentSec - MCP Execution After Authorization Deny`): continuously checks the same invariant across the index window. Severity **HIGH** because authorization already denied and execution nevertheless began. Packaged **disabled**. This dashboard does **not** enable it. It did **not** fire on the validated LIVE runs.

DENY alone is not an alert. ALLOW (including labeled fail-open) is not this detection. `mcp.failed` after ALLOW is execution then error, not DENY-then-start. ERROR is not DENY. Splunk detects a copy of a violation; it does not enforce authorization.

Right table: `DET-MCP-001-POSITIVE-CONTROL` — **SIMULATED** `| makeresults` (DENY seq 3, `mcp.started` seq 4). Not indexed. Not an AcmeBank run. Not OBSERVED runtime evidence. Hunt fixture `Q-MCP-AFTER-DENY-POSITIVE-CONTROL` remains in `searches/` and is also SIMULATED.
""",
        title="STEP 5 DETECT",
    )
    add_table(
        "viz_detect_live",
        "ds_q_after_deny",
        "Q-MCP-AFTER-DENY (indexed hunt)",
        "Investigation query. Validated LIVE specimens: 0 rows. Zero rows = no indexed violation found, not independent proof of non-execution. DET-MCP-001 did not fire on those runs.",
        no_data=empty_after,
    )
    add_table(
        "viz_detect_sim",
        "ds_det_mcp_001_sim",
        "DET-MCP-001-POSITIVE-CONTROL (SIMULATED)",
        "Always one fixture row labeled SIMULATED. Detection-shaped columns. Do not treat as a live incident. Not written to index=agentsec_telemetry. Not OBSERVED runtime evidence.",
        no_data="SIMULATED search returned no fixture row. Re-check DET-MCP-001-POSITIVE-CONTROL.spl (makeresults).",
    )

    add_md(
        "viz_defend",
        """
# DEFEND

**Control:** CTRL-MCP-001 (`src/agentsec/mcp/authorize.py`). Type `mcp_allowlist`.

**Where it executes:** MCP server, **before** the tool handler.

This is a **lab allow-list**, not production IAM, not enterprise MCP gateway policy, and not Splunk authorization.

## What it checks

- Server-owned coded policy (`allowed_tools={lookup_policy}`, `allowed_scope=policy:read`). HTTP cannot widen grants.
- Tool registry: unknown name → **ERROR** (`unknown_tool`), not DENY.
- Grant check: known but not granted → **DENY** in `defended`.
- Scope comparison: requested scope vs coded allowed scope.
- Fail closed for unknown tools and control-evaluation failures (ERROR, no handler).
- `vulnerable` is an intentional labeled fail-open for the **known-ungranted** tool only.

Inspecting a tool result after the handler cannot be DENY of that invoke. Splunk searches do not move the control.

**SPL this step:** none. Re-read HUNT. **Next:** RETEST the same unauthorized request with `defended`.
""",
        title="STEP 6 DEFEND",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

Same request as ATTACK: `lookup_customer_tier`, scope `customer:read`. Profile **defended**. `testbed.mode=RETEST`.

**Expected:** DENY `tool_not_granted`. Control `attempted=false`, `executed=false`, `outcome=prevented`. Runtime handler count **0**. No `mcp.started`.

Validated reference: `{RETEST_ID}`.

{RUNTIME_AUTH}

Tables on this tab use the **RETEST** token.

Do not describe `lookup_customer_tier` as malware. The defended result is unauthorized invocation denied.
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_what_id",
        "ds_what_retest_id",
        "What Happened? identity (indexed fields)",
        cap_what_id + " Expect tool lookup_customer_tier, profile defended, mode RETEST.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_what_dec",
        "ds_what_retest_dec",
        "What Happened? decision (indexed fields)",
        cap_what_dec + " Expect decision DENY, reason tool_not_granted, execution_state no_mcp_execution_event, outcome prevented.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_retest",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect DENY, tool_not_granted, outcome=prevented.",
        no_data=empty_control,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_retest",
        "Q-MCP-TOOL",
        "Complete RETEST copy should have zero mcp.started rows. That is Splunk corroboration, not independent proof. Runtime handler count remains authoritative.",
        no_data=empty_tool,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_executed_retest",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect has_started=0 and execution_state=no_mcp_execution_event.",
        no_data=empty_tool,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

Same known-ungranted request (`lookup_customer_tier`) in ATTACK vs RETEST. BASELINE is the granted happy path.

**BASELINE** `{BASELINE_ID}`
profile defended · mode BASELINE · tool lookup_policy · registered yes · granted yes · decision ALLOW · reason tool_granted · mcp.started yes · terminal mcp.completed · runtime handler count **1** · mcp executed true · outcome success

**ATTACK** `{ATTACK_ID}`
profile vulnerable · mode ATTACK · tool lookup_customer_tier · registered yes · granted **no** · decision ALLOW (labeled fail-open) · mcp.started yes · terminal mcp.completed · runtime handler count **1** · mcp executed true · outcome success

**RETEST** `{RETEST_ID}`
profile defended · mode RETEST · tool lookup_customer_tier · registered yes · granted **no** · decision DENY · reason tool_not_granted · mcp.started **no** · terminal none · runtime handler count **0** · control executed false · outcome prevented

Handler counts are **runtime** facts from Phase 3C. Splunk tables below corroborate the indexed copy. Empty COMPARE tables on this volume mean those run.ids are not in `index=agentsec_telemetry` here. That is not DENY.

Q-MCP-EXECUTED column `executed` is the **control-event** field (false on ALLOW). Do not read it as handler execution. Use `has_started` and `execution_state`. Scroll right in the EXECUTED tables.

{ALLOW_NOT_EXEC}

Core lesson: same known-ungranted request. Vulnerable → labeled fail-open ALLOW → executes. Defended → DENY → does not execute.
""",
        title="BEFORE / AFTER",
    )
    add_table(
        "viz_cmp_c_base",
        "ds_q_authz_baseline",
        "BASELINE Q-MCP-AUTHZ",
        cap_authz + " Expect ALLOW tool_granted.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_c_atk",
        "ds_q_authz_attack",
        "ATTACK Q-MCP-AUTHZ",
        cap_authz + " Expect labeled fail-open ALLOW. ALLOW is not execution.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_c_rt",
        "ds_q_authz_retest",
        "RETEST Q-MCP-AUTHZ",
        cap_authz + " Expect DENY prevented.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_e_base",
        "ds_q_executed_baseline",
        "BASELINE Q-MCP-EXECUTED",
        cap_executed + " Expect execution_state=mcp.completed.",
        no_data=empty_tool,
    )
    add_table(
        "viz_cmp_e_atk",
        "ds_q_executed_attack",
        "ATTACK Q-MCP-EXECUTED",
        cap_executed + " Expect execution_state=mcp.completed.",
        no_data=empty_tool,
    )
    add_table(
        "viz_cmp_e_rt",
        "ds_q_executed_retest",
        "RETEST Q-MCP-EXECUTED",
        cap_executed + " Expect execution_state=no_mcp_execution_event.",
        no_data=empty_tool,
    )
    add_table(
        "viz_cmp_t_base",
        "ds_q_tool_baseline",
        "BASELINE Q-MCP-TOOL",
        cap_tool,
        no_data=empty_tool,
    )
    add_table(
        "viz_cmp_t_atk",
        "ds_q_tool_attack",
        "ATTACK Q-MCP-TOOL",
        cap_tool,
        no_data=empty_tool,
    )
    add_table(
        "viz_cmp_t_rt",
        "ds_q_tool_retest",
        "RETEST Q-MCP-TOOL",
        cap_tool + " Complete RETEST copy should be empty here.",
        no_data=empty_tool,
    )

    add_md(
        "viz_prove",
        f"""
# PROVE

Five layers. Never merge them into one evidence claim. Never a single PROVEN tile from index presence.

1. **Runtime (authoritative).** Did the handler run? `ToolRegistry` / `handler_invoke_count`. Splunk does not decide this.
2. **Local evidence.** `artifacts/<run-id>/events.jsonl` sequence and event contract.
3. **OTLP export.** `export.json` — telemetry was emitted. `otlp.ok` is not Splunk success. Packs keep `splunk.verified=false` until a search ran.
4. **Splunk indexed.** A copy arrived. Completeness is local count vs `dc(_raw)` for that `run.id`.
5. **SPL query result.** Analytical interpretation of that copy (Q-MCP-*). Zero rows follow Phase 3C no-data semantics.

States: COMPLETE / PARTIAL / FAILED / NOT VERIFIED per layer.

{RUNTIME_AUTH}

## Knowledge check (not scored)

Questions live in `learning/level_1/LAB-MCP-001/knowledge-check.md`. Sample:

- Why is `lookup_customer_tier` DENY instead of ERROR?
- Why is an unknown tool ERROR?
- Does ALLOW prove the tool executed?
- What proves the handler actually began?
- Why is `mcp.failed` not prevention?
- Why can't zero Splunk events alone prove the handler never executed?
- Why are MCP tool results `untrusted_data`?

## Limitations that still apply

- CTRL-MCP-001 is a lab allow-list, not production IAM.
- JSON-RPC is in-process, not stdio/HTTP MCP transport.
- Q-MCP-AFTER-DENY zero rows ≠ independent non-execution.
- Positive control is **SIMULATED** (`makeresults`).
- This dashboard is not a detection pack. It does not prove INV-001 by existing.
- No MCP-003 / MCP-004 / MCP-005 / MCP-006 on this page.

Validated references: BASELINE `{BASELINE_ID}` · ATTACK `{ATTACK_ID}` · RETEST `{RETEST_ID}`.
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_what_id",
        "ds_what_identity",
        "What Happened? identity (Hunt run.id)",
        cap_what_id,
        no_data=empty_what,
    )
    add_table(
        "viz_prove_what_dec",
        "ds_what_decision",
        "What Happened? decision (Hunt run.id)",
        cap_what_dec,
        no_data=empty_what,
    )

    definition = {
        "title": "LAB-MCP-001 MCP tool authorization",
        "description": (
            "WS-MCP-001 Dashboard Studio workshop. Reuses validated Q-MCP investigation SPL. "
            "Saved search DET-MCP-001 is packaged disabled; this dashboard does not enable it. "
            "Not a notable-event pack. Splunk does not ALLOW or DENY a tool."
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
                "layout_learn": layout([block("viz_learn", 0, 0, FULL, 980)], 1000),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 300),
                        block("viz_baseline_what_id", 0, 300, FULL, 220),
                        block("viz_baseline_what_dec", 0, 520, FULL, 240),
                        block("viz_baseline_authz", 0, 760, FULL, 260),
                        block("viz_baseline_tool", 0, 1020, HALF, 260),
                        block("viz_baseline_exec", HALF, 1020, HALF, 260),
                    ],
                    1300,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 340),
                        block("viz_attack_what_id", 0, 340, FULL, 220),
                        block("viz_attack_what_dec", 0, 560, FULL, 240),
                        block("viz_attack_authz", 0, 800, HALF, 280),
                        block("viz_attack_exec", HALF, 800, HALF, 280),
                    ],
                    1100,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, FULL, 260),
                        block("viz_observe_seq", 0, 260, FULL, 360),
                        block("viz_observe_authz", 0, 620, HALF, 300),
                        block("viz_observe_tool", HALF, 620, HALF, 300),
                    ],
                    940,
                ),
                "layout_hunt": layout(
                    [
                        block("viz_hunt_md", 0, 0, FULL, 280),
                        block("viz_hunt_who", 0, 280, HALF, 260),
                        block("viz_hunt_scope", HALF, 280, HALF, 260),
                        block("viz_hunt_params", 0, 540, HALF, 280),
                        block("viz_hunt_exec", HALF, 540, HALF, 280),
                        block("viz_hunt_result", 0, 820, HALF, 280),
                        block("viz_hunt_trust", HALF, 820, HALF, 280),
                    ],
                    1120,
                ),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, FULL, 420),
                        block("viz_detect_live", 0, 420, HALF, 400),
                        block("viz_detect_sim", HALF, 420, HALF, 400),
                    ],
                    840,
                ),
                "layout_defend": layout([block("viz_defend", 0, 0, FULL, 520)], 540),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 300),
                        block("viz_retest_what_id", 0, 300, FULL, 220),
                        block("viz_retest_what_dec", 0, 520, FULL, 240),
                        block("viz_retest_authz", 0, 760, FULL, 260),
                        block("viz_retest_tool", 0, 1020, HALF, 260),
                        block("viz_retest_exec", HALF, 1020, HALF, 260),
                    ],
                    1300,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 480),
                        block("viz_cmp_c_base", 0, 480, THIRD, 280),
                        block("viz_cmp_c_atk", THIRD, 480, THIRD, 280),
                        block("viz_cmp_c_rt", THIRD * 2, 480, THIRD, 280),
                        block("viz_cmp_e_base", 0, 760, THIRD, 300),
                        block("viz_cmp_e_atk", THIRD, 760, THIRD, 300),
                        block("viz_cmp_e_rt", THIRD * 2, 760, THIRD, 300),
                        block("viz_cmp_t_base", 0, 1060, THIRD, 260),
                        block("viz_cmp_t_atk", THIRD, 1060, THIRD, 260),
                        block("viz_cmp_t_rt", THIRD * 2, 1060, THIRD, 260),
                    ],
                    1340,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 720),
                        block("viz_prove_what_id", 0, 720, FULL, 220),
                        block("viz_prove_what_dec", 0, 940, FULL, 240),
                    ],
                    1200,
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
        "  <label>LAB-MCP-001 MCP tool authorization</label>\n"
        "  <description>WS-MCP-001. Validated Q-MCP SPL. DET-MCP-001 packaged disabled. Not a notable-event pack. Splunk does not ALLOW or DENY a tool.</description>\n"
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
