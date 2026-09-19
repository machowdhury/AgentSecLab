#!/usr/bin/env python3
"""Build the LAB-MCP-003 Dashboard Studio definition from validated Q-MCP SPL.

Q-MCP files are unchanged except replacing __RUN_ID__ with a quoted Studio token.
DET-MCP-001.spl is not modified. The DETECT fixture is the existing SIMULATED
scope teaching search, not a new detector.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-MCP-003" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_mcp_003.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

BASELINE_ID = "5b089682-1d5a-49a7-ac43-967265fd6bc6"
ATTACK_ID = "b466ad12-72ec-44b7-be28-aacfaf2c25b1"
RETEST_ID = "f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5"
UNKNOWN_ID = "6ce19813-6cb5-4aae-a3a0-aa59386a82dd"

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
GRANT_UNCHANGED = (
    "allowed_scope stays the coded grant policy:read. Fail-open ALLOW does "
    "not rewrite the grant. The tool being granted does not mean the requested "
    "scope is granted."
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
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval attempted=mvindex(mvdedup('agentsec.operation.attempted'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| table sequence, run_id, event_name, tool, requested_scope, allowed_scope, decision, reason, attempted, executed, outcome
| sort sequence"""


def what_happened_spl(token: str) -> str:
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
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_scope = bind_run_id(load_spl("Q-MCP-SCOPE.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_after = bind_run_id(load_spl("Q-MCP-AFTER-DENY.spl"), "run_id")
    q_authz_b = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "baseline_run_id")
    q_authz_a = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "attack_run_id")
    q_authz_r = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "retest_run_id")
    q_authz_u = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "unknown_run_id")
    q_scope_b = bind_run_id(load_spl("Q-MCP-SCOPE.spl"), "baseline_run_id")
    q_scope_a = bind_run_id(load_spl("Q-MCP-SCOPE.spl"), "attack_run_id")
    q_scope_r = bind_run_id(load_spl("Q-MCP-SCOPE.spl"), "retest_run_id")
    q_scope_u = bind_run_id(load_spl("Q-MCP-SCOPE.spl"), "unknown_run_id")
    q_tool_b = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "baseline_run_id")
    q_tool_a = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "attack_run_id")
    q_tool_r = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "retest_run_id")
    q_exec_b = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "baseline_run_id")
    q_exec_a = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "attack_run_id")
    q_exec_r = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "retest_run_id")

    data_sources = dict(
        (
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_scope", "Q-MCP-SCOPE", q_scope),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_after_deny", "Q-MCP-AFTER-DENY", q_after),
            search_ds(
                "ds_det_mcp_001_scope_sim",
                "DET-MCP-001-SCOPE-POSITIVE-CONTROL",
                load_spl("DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl"),
            ),
            search_ds("ds_observe_seq", "MCP-003 observe sequence", observe_sequence_spl("run_id")),
            search_ds("ds_what_identity", "What Happened identity hunt", what_identity_spl("run_id")),
            search_ds("ds_what_decision", "What Happened decision hunt", what_decision_spl("run_id")),
            search_ds("ds_q_authz_baseline", "Q-MCP-AUTHZ BASELINE", q_authz_b),
            search_ds("ds_q_authz_attack", "Q-MCP-AUTHZ ATTACK", q_authz_a),
            search_ds("ds_q_authz_retest", "Q-MCP-AUTHZ RETEST", q_authz_r),
            search_ds("ds_q_authz_unknown", "Q-MCP-AUTHZ UNKNOWN", q_authz_u),
            search_ds("ds_q_scope_baseline", "Q-MCP-SCOPE BASELINE", q_scope_b),
            search_ds("ds_q_scope_attack", "Q-MCP-SCOPE ATTACK", q_scope_a),
            search_ds("ds_q_scope_retest", "Q-MCP-SCOPE RETEST", q_scope_r),
            search_ds("ds_q_scope_unknown", "Q-MCP-SCOPE UNKNOWN", q_scope_u),
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
    cap_what_id = "Indexed identity fields for this run. Not a story. Empty is not DENY."
    cap_what_dec = (
        "Indexed decision fields. `decision` is the control token. `execution_state` "
        "is derived from mcp.* presence in this copy. Control `executed` is not this table."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision row. `executed` here is the control-event field "
        "(false on ALLOW). It is not handler execution. ERROR is not DENY."
    )
    cap_scope = (
        "Q-MCP-SCOPE. `scope_relation` is a display helper. `granted` is ALLOW with "
        "matching scopes. `known_but_ungranted` is catalog-valid requested ≠ allowed "
        "(DENY or fail-open ALLOW). `not_a_grant` is ERROR (unknown or missing scope). "
        "Do not collapse known-but-ungranted with unknown."
    )
    cap_tool = "Q-MCP-TOOL `mcp.started` rows. Zero rows is not automatically DENY."
    cap_executed = (
        "Q-MCP-EXECUTED. Control `executed` stays false on ALLOW. Read `has_started` "
        "and `execution_state` for whether the handler began. Scroll right if needed."
    )
    cap_seq = (
        "Ordered control then mcp.* events. You must see control.decision before "
        "mcp.started when execution occurred. Scopes appear on the control row."
    )

    add_md(
        "viz_learn",
        f"""
# LAB-MCP-003 Scope escalation in MCP tool authorization

**WS-MCP-003** · GUIDED · schema `agentsec.security_event` **1.1.0** · INV-001 · MCP-003 · CTRL-MCP-001

Splunk is the hunt workbench. Splunk does **not** ALLOW or DENY a tool. AcmeBank `POST /mcp/invoke` is the enforcement point.

## Two labs, two questions

- **LAB-MCP-001:** May this agent call this **tool**?
- **LAB-MCP-003:** May this agent call this tool **at this requested scope**?

In this lab the **tool is granted**. The **excessive scope is not**. Same tool `lookup_policy`, same arguments `policy_id=lending-basics`. Only requested authority changes.

## Validated specimen ids (Phase 4C LIVE)

Copy the full UUID. Token fields may ellipsis; these bullets do not.

- **BASELINE** `{BASELINE_ID}` — defended, `policy:read`, ALLOW `tool_granted`, handler=1, `mcp.completed`
- **ATTACK** `{ATTACK_ID}` — vulnerable, `policy:restricted:read`, labeled fail-open ALLOW, handler=1
- **RETEST** `{RETEST_ID}` — defended, same excessive scope, DENY `scope_not_granted`, handler=0
- **UNKNOWN** `{UNKNOWN_ID}` — `policy:write`, ERROR `unknown_scope`, handler=0 (not RETEST)

## Authorization path (before the handler)

```text
request
  → tool exists?
  → tool granted?
  → requested scope valid?   (in tool catalog)
  → requested scope granted? (in agent grant)
  → args valid?
  → ALLOW
  → handler
```

Colons are **opaque labels**. No hierarchy, no wildcard, no prefix matching. `policy:read` does not imply `policy:restricted:read`.

{ALLOW_NOT_EXEC}

Tabs: LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_granted",
        """
# GRANTED

`requested_scope=policy:read`  
`allowed_scope=policy:read`

Known to the tool catalog **and** granted to the agent.

Defended result: **ALLOW** `tool_granted`.
""",
        title="GRANTED",
    )
    add_md(
        "viz_learn_known",
        """
# KNOWN BUT UNGRANTED

`requested_scope=policy:restricted:read`  
`allowed_scope=policy:read`

Known to the **tool catalog**. **Not** granted to the agent.

Defended: **DENY** `scope_not_granted`.  
Vulnerable: labeled **ALLOW** fail-open. The grant does not change.
""",
        title="KNOWN BUT UNGRANTED",
    )
    add_md(
        "viz_learn_unknown",
        """
# UNKNOWN

`requested_scope=policy:write`

Not in the tool catalog. Not a grant question.

Result: **ERROR** `unknown_scope`. Not DENY. Not RETEST.
""",
        title="UNKNOWN",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**What the learner did:** `POST /mcp/invoke` for granted tool `lookup_policy`, requested_scope `policy:read`, profile `defended`, `testbed.mode=BASELINE`.

**Authorization:** CTRL-MCP-001 **ALLOW** `tool_granted`. Requested and allowed scopes both `policy:read`.

**Execution (separate fact):** `mcp.started` then `mcp.completed`. Runtime handler count **1**.

**Evidence:** What Happened (indexed fields), then Q-MCP-AUTHZ / Q-MCP-SCOPE / Q-MCP-TOOL / Q-MCP-EXECUTED on token **BASELINE**.

Validated reference: `{BASELINE_ID}`.

{ALLOW_NOT_EXEC}
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
        cap_what_dec + " Expect ALLOW, tool_granted, scopes both policy:read, execution_state mcp.completed.",
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
        "viz_baseline_scope",
        "ds_q_scope_baseline",
        "Q-MCP-SCOPE",
        cap_scope + " Expect scope_relation=granted.",
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

**Request:** same granted tool `lookup_policy`, same arguments. Requested scope `policy:restricted:read`. Profile `vulnerable`. `testbed.mode=ATTACK`.

- The **tool** is granted.
- The requested scope is **known** to the catalog.
- The requested scope is **not granted** to the agent.
- Vulnerable profile intentionally **fails open**.
- Decision: **ALLOW** `vulnerable_profile_fail_open:scope_not_granted`.
- {GRANT_UNCHANGED}
- Handler executes. Runtime handler count **1**. `mcp.completed` is observed.

This is a controlled lab authorization failure, not a production exploit. The grant did **not** change.

**Validated reference:** `{ATTACK_ID}`.

Tables on this tab use the **ATTACK** token. Predict DENY vs fail-open before you read them.
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_what_id",
        "ds_what_attack_id",
        "What Happened? identity (indexed fields)",
        cap_what_id + " Expect tool lookup_policy, profile vulnerable, mode ATTACK.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_what_dec",
        "ds_what_attack_dec",
        "What Happened? decision (indexed fields)",
        cap_what_dec + " Expect labeled fail-open ALLOW, requested policy:restricted:read, allowed still policy:read, execution_state mcp.completed.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_attack",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect ALLOW vulnerable_profile_fail_open:scope_not_granted. allowed_scope remains policy:read.",
        no_data=empty_control,
    )
    add_table(
        "viz_attack_scope",
        "ds_q_scope_attack",
        "Q-MCP-SCOPE",
        cap_scope + " Expect known_but_ungranted with decision ALLOW.",
        no_data=empty_control,
    )
    add_table(
        "viz_attack_tool",
        "ds_q_tool_attack",
        "Q-MCP-TOOL",
        cap_tool + " Expect mcp.started. Fail-open executed the handler; it did not create a grant.",
        no_data=empty_tool,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_executed_attack",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect has_started=1 and execution_state=mcp.completed.",
        no_data=empty_tool,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Use **Hunt run.id** (defaults to BASELINE). Tables are telemetry, not a story.

Read sequence top to bottom. You must see `agentsec.control.decision` **before** `agentsec.mcp.started` when execution occurred.

Minimum fields: `run_id`, `sequence`, `event.name`, tool, requested_scope, allowed_scope, decision, reason, attempted, executed, outcome.

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_table("viz_observe_seq", "ds_observe_seq", "Control then MCP events (ordered)", cap_seq, no_data=empty_seq)
    add_table("viz_observe_authz", "ds_q_authz", "Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_observe_scope", "ds_q_scope", "Q-MCP-SCOPE", cap_scope, no_data=empty_control)

    add_md(
        "viz_hunt_md",
        f"""
# HUNT

**Question:** What did CTRL-MCP-001 decide, what scope was requested vs coded, and did execution begin?

Reuse validated Q-MCP searches. Do not invent a duplicate scope query. Filter is already `agentsec.run.id`. Do not hunt `session.id`.

{ALLOW_NOT_EXEC}

Zero Q-MCP-TOOL rows does **not** automatically mean DENY.

If Splunk is empty, check `artifacts/<run-id>/export.json`. Do not conclude DENY.

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table("viz_hunt_authz", "ds_q_authz", "Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_hunt_scope", "ds_q_scope", "Q-MCP-SCOPE", cap_scope, no_data=empty_control)
    add_table("viz_hunt_tool", "ds_q_tool", "Q-MCP-TOOL", cap_tool, no_data=empty_tool)
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED", cap_executed, no_data=empty_tool)

    add_md(
        "viz_detect_md",
        """
# DETECT — reuse DET-MCP-001

No notable event. No ES notable. No DET-MCP-003. This dashboard does **not** enable the saved search.

**Invariant:** if CTRL-MCP-001 returns **DENY** for a run/tool, no later `mcp.started` may occur for that same run/tool (`sequence` greater than the DENY).

DET-MCP-001 does **not** care whether DENY came from `tool_not_granted` or `scope_not_granted`. The invariant is DENY, then later `mcp.started`, same run/tool.

## HUNT vs DETECTION

- **HUNT** (`Q-MCP-AFTER-DENY` on Hunt run.id): left table. LIVE MCP-003 specimens: **0** rows. Zero rows is not independent proof the handler never ran.
- **DETECTION** (`DET-MCP-001`): same invariant across the index window. Severity **HIGH**. Packaged **disabled**. It did **not** fire on the validated LIVE MCP-003 runs.

DENY alone is not an alert. ALLOW (including labeled fail-open) is not this detection. ERROR is not DENY. Splunk detects a copy of a violation; it does not enforce authorization.

Right table: `DET-MCP-001-SCOPE-POSITIVE-CONTROL` — **SIMULATED** `| makeresults` (DENY `scope_not_granted`, requested `policy:restricted:read`, allowed `policy:read`, then `mcp.started`). Not indexed. Not an AcmeBank run. Not OBSERVED runtime evidence.
""",
        title="STEP 5 DETECT",
    )
    add_table(
        "viz_detect_live",
        "ds_q_after_deny",
        "Q-MCP-AFTER-DENY (indexed hunt)",
        "Investigation query. LIVE MCP-003 specimens: 0 rows. Zero rows = no indexed violation found, not independent proof of non-execution. DET-MCP-001 did not fire on those runs.",
        no_data=empty_after,
    )
    add_table(
        "viz_detect_sim",
        "ds_det_mcp_001_scope_sim",
        "DET-MCP-001-SCOPE-POSITIVE-CONTROL (SIMULATED)",
        "Always one fixture row labeled SIMULATED. Scope-context DENY then mcp.started. Do not treat as a live incident. Not written to index=agentsec_telemetry. Not OBSERVED runtime evidence. Not DET-MCP-003.",
        no_data="SIMULATED search returned no fixture row. Re-check DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl (makeresults).",
    )

    add_md(
        "viz_defend",
        f"""
# DEFEND

**Control:** CTRL-MCP-001 (`src/agentsec/mcp/authorize.py`). Same control as LAB-MCP-001. No CTRL-MCP-003.

**Where it executes:** MCP server, **before** the tool handler.

This is a **lab allow-list**, not production IAM, not an enterprise MCP gateway, and not Splunk authorization.

## Defended policy for this lab

Tool granted. Requested scope **known** to the catalog. Requested scope **not granted** to the agent.

→ **DENY** `scope_not_granted`  
→ handler does not begin  
→ {GRANT_UNCHANGED}

`vulnerable` is an intentional labeled fail-open for that **known-but-ungranted scope** only. Unknown catalog tokens stay ERROR and do not fail-open.

Inspecting a tool result after the handler cannot be DENY of that invoke. Splunk searches do not move the control.

**SPL this step:** none for the policy text. Unknown-scope tables below use the **UNKNOWN** token. **Next:** RETEST the same excessive-scope request with `defended`.
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_unknown_md",
        f"""
# UNKNOWN SCOPE (not RETEST)

Requested `policy:write`. That token is **not** in `lookup_policy` catalog `valid_scopes`.

**Expected:** **ERROR** `unknown_scope`. Runtime handler count **0**. No `mcp.started`.

**DENY** means known authority was requested but not granted (`policy:restricted:read`).  
**ERROR** means the requested scope is not part of the tool's defined scope model (`policy:write`).

Do not treat this as RETEST. Validated reference: `{UNKNOWN_ID}`.
""",
        title="UNKNOWN SCOPE TEACHING",
    )
    add_table(
        "viz_unknown_authz",
        "ds_q_authz_unknown",
        "Q-MCP-AUTHZ (UNKNOWN token)",
        cap_authz + " Expect ERROR unknown_scope, requested policy:write, allowed still policy:read.",
        no_data=empty_control,
    )
    add_table(
        "viz_unknown_scope",
        "ds_q_scope_unknown",
        "Q-MCP-SCOPE (UNKNOWN token)",
        cap_scope + " Expect decision ERROR and scope_relation=not_a_grant. Not known_but_ungranted.",
        no_data=empty_control,
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

Same request as ATTACK: `lookup_policy`, requested_scope `policy:restricted:read`, same arguments. Profile **defended**. `testbed.mode=RETEST`.

**Expected:** DENY `scope_not_granted`. Control `attempted=false`, `executed=false`, `outcome=prevented`. Runtime handler count **0**. No `mcp.started`. {GRANT_UNCHANGED}

Validated reference: `{RETEST_ID}`.

{RUNTIME_AUTH}

Tables on this tab use the **RETEST** token.
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_what_id",
        "ds_what_retest_id",
        "What Happened? identity (indexed fields)",
        cap_what_id + " Expect tool lookup_policy, profile defended, mode RETEST.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_what_dec",
        "ds_what_retest_dec",
        "What Happened? decision (indexed fields)",
        cap_what_dec + " Expect DENY, scope_not_granted, execution_state no_mcp_execution_event, outcome prevented.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_retest",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect DENY, scope_not_granted, outcome=prevented.",
        no_data=empty_control,
    )
    add_table(
        "viz_retest_scope",
        "ds_q_scope_retest",
        "Q-MCP-SCOPE",
        cap_scope + " Expect known_but_ungranted with decision DENY.",
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

Same tool `lookup_policy`. Same arguments. Different requested authority.

**BASELINE** `{BASELINE_ID}`  
profile defended · mode BASELINE · tool lookup_policy · tool granted **yes** · requested `policy:read` · scope known **yes** · scope granted **yes** · allowed `policy:read` · ALLOW `tool_granted` · mcp.started **yes** · terminal `mcp.completed` · runtime handler **1** · control executed false · mcp executed true · outcome success

**ATTACK** `{ATTACK_ID}`  
profile vulnerable · mode ATTACK · tool lookup_policy · tool granted **yes** · requested `policy:restricted:read` · scope known **yes** · scope granted **no** · allowed still `policy:read` · ALLOW fail-open `scope_not_granted` · mcp.started **yes** · terminal `mcp.completed` · runtime handler **1** · control executed false · mcp executed true · outcome success

**RETEST** `{RETEST_ID}`  
profile defended · mode RETEST · tool lookup_policy · tool granted **yes** · requested `policy:restricted:read` · scope known **yes** · scope granted **no** · allowed `policy:read` · DENY `scope_not_granted` · mcp.started **no** · terminal none · runtime handler **0** · control executed false · outcome prevented

Handler counts are **runtime** facts from Phase 4C. Splunk tables below corroborate the indexed copy. Empty COMPARE tables on this volume mean those run.ids are not in `index=agentsec_telemetry` here. That is not DENY.

Q-MCP-EXECUTED column `executed` is the **control-event** field (false on ALLOW). Use `has_started` and `execution_state`. Scroll right in the EXECUTED tables.

{ALLOW_NOT_EXEC}

Core lesson: same granted tool, same arguments, different requested scope. Vulnerable labeled fail-open ALLOW executes. Defended DENY does not. The grant never becomes `policy:restricted:read`.
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
        cap_authz + " Expect labeled fail-open ALLOW. ALLOW is not execution. Grant unchanged.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_c_rt",
        "ds_q_authz_retest",
        "RETEST Q-MCP-AUTHZ",
        cap_authz + " Expect DENY scope_not_granted prevented.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_s_base",
        "ds_q_scope_baseline",
        "BASELINE Q-MCP-SCOPE",
        cap_scope + " Expect granted.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_s_atk",
        "ds_q_scope_attack",
        "ATTACK Q-MCP-SCOPE",
        cap_scope + " Expect known_but_ungranted with ALLOW.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_s_rt",
        "ds_q_scope_retest",
        "RETEST Q-MCP-SCOPE",
        cap_scope + " Expect known_but_ungranted with DENY.",
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

    add_md(
        "viz_prove",
        f"""
# PROVE

Six layers. Never merge them into one evidence claim. Never a single PROVEN tile from index presence.

1. **RUNTIME.** Did the handler run? `ToolRegistry` / `handler_invoke_count`. Splunk does not decide this.
2. **LOCAL.** `artifacts/<run-id>/events.jsonl` sequence and event contract.
3. **EXPORT.** `export.json` — telemetry was emitted. `otlp.ok` is not Splunk success. Packs keep `splunk.verified=false` until a search ran.
4. **SPLUNK.** A copy arrived. Completeness is local count vs `dc(_raw)` for that `run.id`.
5. **SEARCH.** Analytical interpretation of that copy (Q-MCP-*). Zero rows follow no-data semantics.
6. **DETECTION.** DET-MCP-001 proves only that **no indexed DENY→execution invariant violation was found**. It does not prove the handler never ran.

States: COMPLETE / PARTIAL / FAILED / NOT VERIFIED per layer.

{RUNTIME_AUTH}

## Knowledge check (not scored)

Questions live in `learning/level_1/LAB-MCP-003/knowledge-check.md`. Sample:

- Why is `policy:restricted:read` DENY rather than ERROR?
- Why is `policy:write` ERROR?
- Does ALLOW mean the tool executed?
- Why must `allowed_scope` remain `policy:read` during vulnerable fail-open?
- Can arguments grant a broader scope?
- Why can DET-MCP-001 be reused?
- Why is no detector hit not proof that the handler never ran?

## Limitations that still apply

- CTRL-MCP-001 is a lab allow-list, not production IAM.
- JSON-RPC is in-process, not stdio/HTTP MCP transport.
- Q-MCP-AFTER-DENY zero rows ≠ independent non-execution.
- Scope positive control is **SIMULATED** (`makeresults`).
- This dashboard is not a detection pack. It does not enable DET-MCP-001. It does not create DET-MCP-003.
- No MCP-004 / Cisco / MLTK on this page.

Validated references: BASELINE `{BASELINE_ID}` · ATTACK `{ATTACK_ID}` · RETEST `{RETEST_ID}` · UNKNOWN `{UNKNOWN_ID}`.
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
        "title": "LAB-MCP-003 Scope escalation in MCP tool authorization",
        "description": (
            "WS-MCP-003 Dashboard Studio workshop. Reuses validated Q-MCP investigation SPL. "
            "Saved search DET-MCP-001 is packaged disabled; this dashboard does not enable it. "
            "Not a notable-event pack. Not DET-MCP-003. Splunk does not ALLOW or DENY a tool."
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
            "input_unknown_run_id": {
                "type": "input.text",
                "title": "UNKNOWN",
                "options": {"token": "unknown_run_id", "defaultValue": UNKNOWN_ID},
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
                "input_unknown_run_id",
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
                        block("viz_learn", 0, 0, FULL, 680),
                        block("viz_learn_granted", 0, 680, THIRD, 300),
                        block("viz_learn_known", THIRD, 680, THIRD, 300),
                        block("viz_learn_unknown", THIRD * 2, 680, THIRD, 300),
                    ],
                    1000,
                ),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 320),
                        block("viz_baseline_what_id", 0, 320, FULL, 220),
                        block("viz_baseline_what_dec", 0, 540, FULL, 240),
                        block("viz_baseline_authz", 0, 780, HALF, 260),
                        block("viz_baseline_scope", HALF, 780, HALF, 260),
                        block("viz_baseline_tool", 0, 1040, HALF, 260),
                        block("viz_baseline_exec", HALF, 1040, HALF, 260),
                    ],
                    1320,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 400),
                        block("viz_attack_what_id", 0, 400, FULL, 220),
                        block("viz_attack_what_dec", 0, 620, FULL, 240),
                        block("viz_attack_authz", 0, 860, HALF, 260),
                        block("viz_attack_scope", HALF, 860, HALF, 260),
                        block("viz_attack_tool", 0, 1120, HALF, 260),
                        block("viz_attack_exec", HALF, 1120, HALF, 260),
                    ],
                    1400,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, FULL, 260),
                        block("viz_observe_seq", 0, 260, FULL, 380),
                        block("viz_observe_authz", 0, 640, HALF, 300),
                        block("viz_observe_scope", HALF, 640, HALF, 300),
                    ],
                    960,
                ),
                "layout_hunt": layout(
                    [
                        block("viz_hunt_md", 0, 0, FULL, 300),
                        block("viz_hunt_authz", 0, 300, HALF, 280),
                        block("viz_hunt_scope", HALF, 300, HALF, 280),
                        block("viz_hunt_exec", 0, 580, FULL, 300),
                        block("viz_hunt_tool", 0, 880, FULL, 240),
                    ],
                    1140,
                ),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, FULL, 440),
                        block("viz_detect_live", 0, 440, HALF, 400),
                        block("viz_detect_sim", HALF, 440, HALF, 400),
                    ],
                    860,
                ),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 400),
                        block("viz_unknown_md", 0, 400, FULL, 260),
                        block("viz_unknown_authz", 0, 660, HALF, 300),
                        block("viz_unknown_scope", HALF, 660, HALF, 300),
                    ],
                    980,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 300),
                        block("viz_retest_what_id", 0, 300, FULL, 220),
                        block("viz_retest_what_dec", 0, 520, FULL, 240),
                        block("viz_retest_authz", 0, 760, HALF, 260),
                        block("viz_retest_scope", HALF, 760, HALF, 260),
                        block("viz_retest_tool", 0, 1020, HALF, 260),
                        block("viz_retest_exec", HALF, 1020, HALF, 260),
                    ],
                    1300,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 520),
                        block("viz_cmp_c_base", 0, 520, THIRD, 280),
                        block("viz_cmp_c_atk", THIRD, 520, THIRD, 280),
                        block("viz_cmp_c_rt", THIRD * 2, 520, THIRD, 280),
                        block("viz_cmp_s_base", 0, 800, THIRD, 280),
                        block("viz_cmp_s_atk", THIRD, 800, THIRD, 280),
                        block("viz_cmp_s_rt", THIRD * 2, 800, THIRD, 280),
                        block("viz_cmp_e_base", 0, 1080, THIRD, 300),
                        block("viz_cmp_e_atk", THIRD, 1080, THIRD, 300),
                        block("viz_cmp_e_rt", THIRD * 2, 1080, THIRD, 300),
                    ],
                    1400,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 760),
                        block("viz_prove_what_id", 0, 760, FULL, 220),
                        block("viz_prove_what_dec", 0, 980, FULL, 240),
                    ],
                    1240,
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
        "  <label>LAB-MCP-003 Scope escalation in MCP tool authorization</label>\n"
        "  <description>WS-MCP-003. Validated Q-MCP SPL. DET-MCP-001 packaged disabled. Not DET-MCP-003. Not a notable-event pack. Splunk does not ALLOW or DENY a tool.</description>\n"
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
