#!/usr/bin/env python3
"""Build the LAB-MCP-004 Dashboard Studio definition.

Q-MCP files from LAB-MCP-001 are unchanged except replacing __RUN_ID__ with a
quoted Studio token. Q-MCP-RESOURCE-AUTHZ is the MCP-004 primary hunt.
DET-MCP-001.spl is not modified. The DETECT fixture is the existing SIMULATED
resource teaching search, not a new detector.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RESOURCE_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-004" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-MCP-004" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_mcp_004.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

BASELINE_ID = "fb50dcaf-8e84-4a3f-a55b-997c72edbd04"
ATTACK_ID = "5ab59fc7-303e-4eea-84e7-ae0b2f405146"
RETEST_ID = "0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd"
UNKNOWN_ID = "0e4e0051-528d-4bf3-8773-d1fb55a5864f"
MALFORMED_ID = "9ea63448-bf6a-4619-b313-b152f4d94bb6"
DUPLICATE_ID = "ffafb62e-a6c6-42c0-837d-094cbfb3f795"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_HUNT = (
    "Investigate specimen defaults to BASELINE so this page is not an error "
    "state. Custom run.id is available from Search. Zero rows means "
    "no matching indexed events for that id. Zero rows is not DENY and is not "
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
GRANT_UNCHANGED = (
    "allowed_resource.ids stays the coded grant lending-basics. Fail-open ALLOW "
    "does not rewrite the grant. The resource was not granted."
)


def load_spl(name: str, *, resource: bool = False) -> str:
    directory = RESOURCE_DIR if resource else SEARCH_DIR
    return (directory / name).read_text(encoding="utf-8").strip()


def bind_run_id(spl: str, token: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError(f"expected __RUN_ID__ in query for token {token}")
    return spl.replace("__RUN_ID__", f'"${token}$"')

def bind_literal(spl: str, run_id: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError("expected __RUN_ID__ in query")
    return spl.replace("__RUN_ID__", f'"{run_id}"')


def bound_run(ref: str) -> str:
    """Token name stays "$token$"; UUID becomes a quoted literal."""
    if len(ref) == 36 and ref.count("-") == 4:
        return f'"{ref}"'
    return f'"${ref}$"'



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
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"={bound_run(token)} ("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval resource_id=mvindex(mvdedup('agentsec.mcp.resource.id'),0)
| eval allowed_resource_ids=mvindex(mvdedup('agentsec.mcp.allowed_resource.ids'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval attempted=mvindex(mvdedup('agentsec.operation.attempted'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| table sequence, run_id, event_name, tool, requested_scope, allowed_scope, resource_id, allowed_resource_ids, decision, reason, attempted, executed, outcome
| sort sequence"""


def what_happened_spl(token: str) -> str:
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"={bound_run(token)} ("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
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
| eval resource_id=mvindex(mvdedup('agentsec.mcp.resource.id'),0)
| eval allowed_resource_ids=mvindex(mvdedup('agentsec.mcp.allowed_resource.ids'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| eval result_trust=mvindex(mvdedup('agentsec.mcp.result.trust'),0)
| eval is_started=if(event_name="agentsec.mcp.started",1,0)
| eval is_completed=if(event_name="agentsec.mcp.completed",1,0)
| eval is_failed=if(event_name="agentsec.mcp.failed",1,0)
| eventstats max(is_started) as has_started, max(is_completed) as has_completed, max(is_failed) as has_failed, latest(eval(if(event_name="agentsec.mcp.completed",result_trust,null()))) as completed_trust by run_id, tool
| where event_name="agentsec.control.decision"
| eval execution_state=case(has_completed=1,"mcp.completed",has_failed=1,"mcp.failed",has_started=1,"mcp.started",decision="ALLOW","ALLOW_execution_not_proven_in_this_copy",1=1,"no_mcp_execution_event")
| eval result_trust=if(isnull(completed_trust),"no_completed_result",completed_trust)
| table run_id, profile, mode, agent, tool, decision, reason, requested_scope, allowed_scope, resource_id, allowed_resource_ids, execution_state, outcome, result_trust"""


def what_identity_spl(token: str) -> str:
    return what_happened_spl(token) + "\n| table run_id, profile, mode, agent, tool"


def what_decision_spl(token: str) -> str:
    return (
        what_happened_spl(token)
        + "\n| table run_id, decision, reason, requested_scope, allowed_scope, resource_id, allowed_resource_ids, execution_state, outcome, result_trust"
    )


def build() -> dict:
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_scope = bind_run_id(load_spl("Q-MCP-SCOPE.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_after = bind_run_id(load_spl("Q-MCP-AFTER-DENY.spl"), "run_id")
    q_resource = bind_run_id(load_spl("Q-MCP-RESOURCE-AUTHZ.spl", resource=True), "run_id")
    q_authz_b = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), BASELINE_ID)
    q_authz_a = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), ATTACK_ID)
    q_authz_r = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), RETEST_ID)
    q_authz_u = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), UNKNOWN_ID)
    q_res_b = bind_literal(load_spl("Q-MCP-RESOURCE-AUTHZ.spl", resource=True), BASELINE_ID)
    q_res_a = bind_literal(load_spl("Q-MCP-RESOURCE-AUTHZ.spl", resource=True), ATTACK_ID)
    q_res_r = bind_literal(load_spl("Q-MCP-RESOURCE-AUTHZ.spl", resource=True), RETEST_ID)
    q_res_u = bind_literal(load_spl("Q-MCP-RESOURCE-AUTHZ.spl", resource=True), UNKNOWN_ID)
    q_tool_b = bind_literal(load_spl("Q-MCP-TOOL.spl"), BASELINE_ID)
    q_tool_a = bind_literal(load_spl("Q-MCP-TOOL.spl"), ATTACK_ID)
    q_tool_r = bind_literal(load_spl("Q-MCP-TOOL.spl"), RETEST_ID)
    q_exec_b = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), BASELINE_ID)
    q_exec_a = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), ATTACK_ID)
    q_exec_r = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), RETEST_ID)

    data_sources = dict(
        (
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_scope", "Q-MCP-SCOPE", q_scope),
            search_ds("ds_q_resource", "Q-MCP-RESOURCE-AUTHZ", q_resource),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_after_deny", "Q-MCP-AFTER-DENY", q_after),
            search_ds(
                "ds_det_mcp_001_resource_sim",
                "DET-MCP-001-RESOURCE-POSITIVE-CONTROL",
                load_spl("DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl", resource=True),
            ),
            search_ds("ds_observe_seq", "MCP-004 observe sequence", observe_sequence_spl("run_id")),
            search_ds("ds_what_identity", "What Happened identity hunt", what_identity_spl("run_id")),
            search_ds("ds_what_decision", "What Happened decision hunt", what_decision_spl("run_id")),
            search_ds("ds_q_authz_baseline", "Q-MCP-AUTHZ BASELINE", q_authz_b),
            search_ds("ds_q_authz_attack", "Q-MCP-AUTHZ ATTACK", q_authz_a),
            search_ds("ds_q_authz_retest", "Q-MCP-AUTHZ RETEST", q_authz_r),
            search_ds("ds_q_authz_unknown", "Q-MCP-AUTHZ UNKNOWN", q_authz_u),
            search_ds("ds_q_resource_baseline", "Q-MCP-RESOURCE-AUTHZ BASELINE", q_res_b),
            search_ds("ds_q_resource_attack", "Q-MCP-RESOURCE-AUTHZ ATTACK", q_res_a),
            search_ds("ds_q_resource_retest", "Q-MCP-RESOURCE-AUTHZ RETEST", q_res_r),
            search_ds("ds_q_resource_unknown", "Q-MCP-RESOURCE-AUTHZ UNKNOWN", q_res_u),
            search_ds("ds_q_tool_baseline", "Q-MCP-TOOL BASELINE", q_tool_b),
            search_ds("ds_q_tool_attack", "Q-MCP-TOOL ATTACK", q_tool_a),
            search_ds("ds_q_tool_retest", "Q-MCP-TOOL RETEST", q_tool_r),
            search_ds("ds_q_executed_baseline", "Q-MCP-EXECUTED BASELINE", q_exec_b),
            search_ds("ds_q_executed_attack", "Q-MCP-EXECUTED ATTACK", q_exec_a),
            search_ds("ds_q_executed_retest", "Q-MCP-EXECUTED RETEST", q_exec_r),
            search_ds("ds_what_baseline_id", "What Happened identity BASELINE", what_identity_spl(BASELINE_ID)),
            search_ds("ds_what_baseline_dec", "What Happened decision BASELINE", what_decision_spl(BASELINE_ID)),
            search_ds("ds_what_attack_id", "What Happened identity ATTACK", what_identity_spl(ATTACK_ID)),
            search_ds("ds_what_attack_dec", "What Happened decision ATTACK", what_decision_spl(ATTACK_ID)),
            search_ds("ds_what_retest_id", "What Happened identity RETEST", what_identity_spl(RETEST_ID)),
            search_ds("ds_what_retest_dec", "What Happened decision RETEST", what_decision_spl(RETEST_ID)),
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
        "No indexed control.decision was found for this run. The dashboard will not "
        "invent DENY, executed, or prevented from an empty table."
    )
    empty_seq = (
        "No indexed control or mcp.* events were found for this run. Ordering cannot "
        "be shown. That is not a security outcome."
    )
    cap_what_id = "Indexed identity fields for this run. Not a story. Empty is not DENY."
    cap_what_dec = (
        "Indexed decision fields. decision is the control token. execution_state "
        "is derived from mcp.* presence in this copy. Control executed is not this table. "
        "resource_id and allowed_resource_ids are schema 1.2.0 fields."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision row. executed here is the control-event field "
        "(false on ALLOW). It is not handler execution. ERROR is not DENY."
    )
    cap_scope = (
        "Q-MCP-SCOPE. On MCP-004 the requested scope stays policy:read, so ATTACK "
        "often shows granted. That is why Q-MCP-RESOURCE-AUTHZ is the primary hunt. "
        "Scope granted is not resource granted."
    )
    cap_resource = (
        "Q-MCP-RESOURCE-AUTHZ (primary MCP-004 hunt). resource_relation uses the "
        "control reason. granted is ALLOW with matching resource.id and allowed_resource.ids. "
        "known_but_ungranted is reason containing resource_not_granted (DENY or fail-open ALLOW). "
        "not_a_grant is ERROR (unknown_resource or malformed_arguments). Do not infer "
        "known vs unknown from set membership alone."
    )
    cap_tool = "Q-MCP-TOOL mcp.started rows. Zero rows is not automatically DENY."
    cap_executed = (
        "Q-MCP-EXECUTED. Control executed stays false on ALLOW. Read has_started "
        "and execution_state for whether the handler began. Scroll right if needed."
    )
    cap_seq = (
        "Ordered control then mcp.* events. You must see control.decision before "
        "mcp.started when execution occurred. resource.id and allowed_resource.ids "
        "appear on the control row."
    )

    add_md(
        "viz_learn",
        f"""
# Parameter / Resource Authorization

Investigate why a granted tool and granted scope do not authorize every resource.

**REPLAY SPECIMEN** · historical evidence · Schema 1.2.0 · CTRL-MCP-001

Splunk is the hunt workbench. Splunk does **not** ALLOW or DENY a resource. AcmeBank POST /mcp/invoke is the enforcement point.

## Three labs, three questions

- **LAB-MCP-001:** May the agent call this **tool**?
- **LAB-MCP-003:** May the agent call this tool at this **scope**?
- **LAB-MCP-004:** May the agent call this tool at this scope for **this resource**?

tool authorization is not scope authorization. Scope authorization is not resource authorization. Syntactically valid arguments are not authorized arguments. In this lab the **tool is granted** (lookup_policy) and the **scope is granted** (policy:read). The **resource** may not be.

## Evidence identity

Canonical specimens. Full run.id remains here; HUNT uses Investigate specimen.

- **BASELINE** `{BASELINE_ID}` — defended, resource.id lending-basics, ALLOW tool_granted, handler=1, mcp.completed
- **ATTACK** `{ATTACK_ID}` — vulnerable, resource.id executive-restricted, labeled fail-open ALLOW, handler=1
- **RETEST** `{RETEST_ID}` — defended, same resource as ATTACK, DENY resource_not_granted, handler=0
- **UNKNOWN** `{UNKNOWN_ID}` — resource.id does-not-exist, ERROR unknown_resource, handler=0 (not RETEST)

**Path:** request → tool exists → tool granted → scope valid → scope granted → arguments structurally valid → resource exists → resource granted → ALLOW ticket → handler.

Arguments **identify** the requested resource. Arguments do **not** grant authority. {ALLOW_NOT_EXEC} Tabs: LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_granted",
        """
# GRANTED

resource.id=lending-basics  
allowed_resource.ids=lending-basics

Known to the catalog **and** granted to the agent.

Defended result: **ALLOW** tool_granted.
""",
        title="GRANTED",
    )
    add_md(
        "viz_learn_known",
        """
# KNOWN BUT UNGRANTED

resource.id=executive-restricted  
allowed_resource.ids=lending-basics

Known to the **catalog**. **Not** granted to the agent.

Defended: **DENY** resource_not_granted.  
Vulnerable: labeled **ALLOW** fail-open. The grant does not change.
""",
        title="KNOWN BUT UNGRANTED",
    )
    add_md(
        "viz_learn_unknown",
        """
# UNKNOWN RESOURCE

resource.id=does-not-exist

Not in the catalog. Not a grant question.

Result: **ERROR** unknown_resource. Not DENY. Not RETEST.
""",
        title="UNKNOWN RESOURCE",
    )
    add_md(
        "viz_learn_params",
        f"""
# Valid arguments are not authorized resources

Malformed shape is a **schema** failure. A well-formed policy_id can still be unauthorized.

- `{{}}` → **ERROR** malformed_arguments (Phase 5C `{MALFORMED_ID}` has no resource.id)
- `{{"policy_id": 123}}` → **ERROR** malformed_arguments (wrong type)
- `{{"policy_id": "executive-restricted"}}` → valid argument shape, known resource, **not granted** → DENY or vulnerable fail-open

Do not call executive-restricted malformed. Do not call does-not-exist DENY.

## Check then use (AllowTicket)

When the control ALLOWs, it records the exact resource.id that was checked on an AllowTicket. The handler uses that ticket resource. The request must not be changeable after authorization so a different resource is executed. Resource authorized means resource used.

## Duplicate JSON keys (HTTP boundary)

Two policy_id keys in one object are rejected at the HTTP boundary. Phase 5C `{DUPLICATE_ID}` ended as run.failed duplicate_json_keys with **no** CTRL-MCP-001 event. Do not invent a control.decision hunt for that copy.
""",
        title="PARAMETER VALIDATION",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**What the learner did:** POST /mcp/invoke for granted tool lookup_policy, granted scope policy:read, resource.id lending-basics, profile defended, testbed.mode=BASELINE.

**Authorization:** CTRL-MCP-001 **ALLOW** tool_granted. allowed_resource.ids=lending-basics. Resource relation: **granted**.

**Execution (separate fact):** mcp.started then mcp.completed. Runtime handler count **1**.

**Evidence:** What Happened (indexed fields), then Q-MCP-AUTHZ / Q-MCP-RESOURCE-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED on token **BASELINE**.

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
        cap_what_dec + " Expect ALLOW, tool_granted, resource_id lending-basics, allowed_resource_ids lending-basics, execution_state mcp.completed.",
        no_data=empty_what,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_baseline",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect ALLOW, tool_granted.",
        no_data=empty_control,
    )
    add_table(
        "viz_baseline_resource",
        "ds_q_resource_baseline",
        "Q-MCP-RESOURCE-AUTHZ",
        cap_resource + " Expect resource_relation=granted.",
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

**Request:** same granted tool lookup_policy, same granted scope policy:read. resource.id=executive-restricted. Profile vulnerable. testbed.mode=ATTACK.

- The **tool** is granted.
- The **scope** is granted (policy:read).
- The resource is **known** to the catalog.
- The resource is **not granted** to the agent (grant remains lending-basics).
- Vulnerable profile intentionally **fails open**.
- Decision: **ALLOW** vulnerable_profile_fail_open:resource_not_granted.
- Resource relation: **known_but_ungranted**.
- {GRANT_UNCHANGED}
- Handler executes. Runtime handler count **1**. mcp.completed is observed.

This is a controlled lab authorization failure, not a production exploit. Do not label this resource authorized, resource granted, or grant widened.

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
        cap_what_dec + " Expect labeled fail-open ALLOW, resource_id executive-restricted, allowed_resource_ids still lending-basics, execution_state mcp.completed.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_attack",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect ALLOW vulnerable_profile_fail_open:resource_not_granted. This ALLOW is not a resource grant.",
        no_data=empty_control,
    )
    add_table(
        "viz_attack_resource",
        "ds_q_resource_attack",
        "Q-MCP-RESOURCE-AUTHZ",
        cap_resource + " Expect known_but_ungranted with decision ALLOW. Q-MCP-SCOPE on this run is still granted.",
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

Read sequence top to bottom. You must see agentsec.control.decision **before** agentsec.mcp.started when execution occurred.

Minimum fields: run_id, sequence, event.name, tool, requested_scope, allowed_scope, resource.id, allowed_resource.ids, decision, reason, attempted, executed, outcome.

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_table("viz_observe_seq", "ds_observe_seq", "Control then MCP events (ordered)", cap_seq, no_data=empty_seq)
    add_table("viz_observe_authz", "ds_q_authz", "Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_observe_resource", "ds_q_resource", "Q-MCP-RESOURCE-AUTHZ", cap_resource, no_data=empty_control)

    add_md(
        "viz_hunt_md",
        f"""
# HUNT

**REPLAY workshop.** There is no Attack Service launcher here. This is historical evidence, not a launch you just minted.

**WHY search this?** Reconstruct a canonical experiment in Search. Practice Path A without minting a new run.id.

**Path A — try it yourself:** [Open Splunk Search](http://127.0.0.1:8000/en-US/app/search/search). Copy a canonical Investigate specimen run.id. Start with `index=agentsec_telemetry sourcetype=otel:agentic:json` and quoted `agentsec.run.id`. Construct the hunt before you treat the tables as the answer. If zero rows, this volume may not contain that specimen. Empty is not DENY.

**Path B — show solution:** the bound tables on this tab are the expected shape for that specimen. Read them after Path A. They are not policy and not LIVE launch evidence.

**YOU SHOULD SEE** control.id, decision, reason, and whether execution events exist.
**THAT MEANS** this is the expected shape of a historical copy.
**IT DOES NOT MEAN** Splunk enforced the decision.
**NEXT** COMPARE ATTACK vs RETEST on the same fields, then PROVE.

**Question:** What did CTRL-MCP-001 decide, what resource was requested vs coded, and did execution begin?

**Primary hunt:** Q-MCP-RESOURCE-AUTHZ. Do not invent a duplicate resource query.

Q-MCP-SCOPE is shown because MCP-004 ATTACK still has granted scope (policy:read). Scope granted is not resource granted.

Reuse validated Q-MCP searches. Filter is already agentsec.run.id. Do not hunt session.id.

{ALLOW_NOT_EXEC}

Zero Q-MCP-TOOL rows does **not** automatically mean DENY.

If Search returns zero rows, this volume may not contain that specimen. Empty is not DENY.

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table("viz_hunt_authz", "ds_q_authz", "Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_hunt_scope", "ds_q_scope", "Q-MCP-SCOPE", cap_scope, no_data=empty_control)
    add_table(
        "viz_hunt_resource",
        "ds_q_resource",
        "Q-MCP-RESOURCE-AUTHZ (primary MCP-004 hunt)",
        cap_resource,
        no_data=empty_control,
    )
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED", cap_executed, no_data=empty_tool)
    add_table("viz_hunt_tool", "ds_q_tool", "Q-MCP-TOOL", cap_tool, no_data=empty_tool)

    add_md(
        "viz_detect_md",
        """
# DETECT — reuse DET-MCP-001

No notable event. No ES notable. No DET-MCP-004. This dashboard does **not** enable the saved search.

**Invariant:** if CTRL-MCP-001 returns **DENY** for a run/tool, no later mcp.started may occur for that same run/tool (sequence greater than the DENY).

DET-MCP-001 does **not** care whether DENY came from tool_not_granted, scope_not_granted, or resource_not_granted. The invariant is DENY, then later mcp.started, same run/tool.

## HUNT vs DETECTION

- **HUNT** (Q-MCP-AFTER-DENY on Hunt run.id): left table. LIVE MCP-004 specimens: **0** rows. Zero rows is not independent proof the handler never ran.
- **DETECTION** (DET-MCP-001): same invariant across the index window. Severity **HIGH**. Packaged **disabled**. It did **not** fire on the validated LIVE MCP-004 runs.

DENY alone is not an alert. ALLOW (including labeled fail-open) is not this detection. ERROR is not DENY. Splunk detects a copy of a violation; it does not enforce authorization.

Right table: DET-MCP-001-RESOURCE-POSITIVE-CONTROL — **SIMULATED** makeresults (DENY resource_not_granted, resource.id executive-restricted, allowed_resource.ids lending-basics, then mcp.started). Not indexed. Not an AcmeBank run. Not OBSERVED runtime evidence.

## Correlation limitation (advanced)

DET-MCP-001 currently correlates run_id + tool. That is valid for current canonical labs (one invocation per run). It is not sufficient for future flows with multiple same-tool invocations against different resources. Future per-invocation identity may be required. This workshop does not add that field.
""",
        title="STEP 5 DETECT",
    )
    add_table(
        "viz_detect_live",
        "ds_q_after_deny",
        "Q-MCP-AFTER-DENY (indexed hunt)",
        "Investigation query. LIVE MCP-004 specimens: 0 rows. Zero rows = no indexed violation found, not independent proof of non-execution. DET-MCP-001 did not fire on those runs.",
        no_data=empty_after,
    )
    add_table(
        "viz_detect_sim",
        "ds_det_mcp_001_resource_sim",
        "DET-MCP-001-RESOURCE-POSITIVE-CONTROL (SIMULATED)",
        "Always one fixture row labeled SIMULATED. Resource-context DENY then mcp.started. Do not treat as a live incident. Not written to index=agentsec_telemetry. Not OBSERVED runtime evidence. Not DET-MCP-004.",
        no_data="SIMULATED search returned no fixture row. Re-check DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl (makeresults).",
    )

    add_md(
        "viz_defend",
        f"""
# DEFEND

**Control:** CTRL-MCP-001 (the tool PDP). Same control as Tool Authorization and Scope Escalation. No extra resource control.

**Where it executes:** MCP server, **before** the tool handler.

This is a **lab allow-list**, not production IAM, not an enterprise MCP gateway, and not Splunk authorization.

## Defended policy for this lab

Tool granted. Scope granted. Arguments valid. Resource **known**. Resource **not granted**.

→ **DENY** resource_not_granted  
→ handler does not begin  
→ handler count 0 at runtime  
→ no indexed mcp.started on a complete copy  
→ {GRANT_UNCHANGED}

Splunk did **not** prevent the action. The control did.

`vulnerable` is an intentional labeled fail-open for that **known-but-ungranted resource** only. Unknown catalog tokens stay ERROR and do not fail-open.

Inspecting a tool result after the handler cannot be DENY of that invoke. Splunk searches do not move the control.

## Duplicate JSON keys (HTTP boundary)

Two policy_id keys in one JSON object must not become last-value-wins. AcmeBank rejects that at the HTTP boundary. Phase 5C `{DUPLICATE_ID}` is run.failed duplicate_json_keys with **no** control.decision event. Do not fabricate MCP control telemetry for that rejection.

**SPL this step:** none for the policy text. Unknown-resource tables below use the **UNKNOWN** token. **Next:** RETEST the same ungranted resource with defended.
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_unknown_md",
        f"""
# UNKNOWN RESOURCE (not RETEST)

Requested resource.id=does-not-exist. That id is **not** in the lookup_policy catalog.

**Expected:** **ERROR** unknown_resource. Runtime handler count **0**. No mcp.started.

**DENY** means known authority was requested but not granted (executive-restricted).  
**ERROR** means the requested resource is not part of the tool's defined resource model (does-not-exist).

Do not treat this as RETEST or as ATTACK. Validated reference: `{UNKNOWN_ID}`.
""",
        title="UNKNOWN RESOURCE TEACHING",
    )
    add_table(
        "viz_unknown_authz",
        "ds_q_authz_unknown",
        "Q-MCP-AUTHZ (UNKNOWN token)",
        cap_authz + " Expect ERROR unknown_resource. ERROR is not DENY.",
        no_data=empty_control,
    )
    add_table(
        "viz_unknown_resource",
        "ds_q_resource_unknown",
        "Q-MCP-RESOURCE-AUTHZ (UNKNOWN token)",
        cap_resource + " Expect decision ERROR and resource_relation=not_a_grant. Not known_but_ungranted.",
        no_data=empty_control,
    )
    add_md(
        "viz_malformed_md",
        f"""
# Malformed arguments (not a resource grant question)

Valid JSON with a missing or wrong-type policy_id fails **before** resource membership.

Phase 5C `{MALFORMED_ID}`: `{{}}` → **ERROR** malformed_arguments. No resource.id on the control row.

A string policy_id of executive-restricted is **not** malformed. That path is known-but-ungranted (DENY or fail-open).
""",
        title="MALFORMED ARGUMENT TEACHING",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

Same request as ATTACK: lookup_policy, scope policy:read, resource.id executive-restricted. Profile **defended**. testbed.mode=RETEST.

**Expected:** DENY resource_not_granted. Control attempted=false, executed=false, outcome=prevented. Runtime handler count **0**. No mcp.started. {GRANT_UNCHANGED}

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
        cap_what_dec + " Expect DENY, resource_not_granted, resource_id executive-restricted, execution_state no_mcp_execution_event, outcome prevented.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_retest",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect DENY, resource_not_granted, outcome=prevented.",
        no_data=empty_control,
    )
    add_table(
        "viz_retest_resource",
        "ds_q_resource_retest",
        "Q-MCP-RESOURCE-AUTHZ",
        cap_resource + " Expect known_but_ungranted with decision DENY.",
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

Same tool lookup_policy. Same scope policy:read. ATTACK and RETEST use the same resource. Different profile changes whether the vulnerable fail-open is permitted.

**BASELINE** `{BASELINE_ID}`  
profile defended · mode BASELINE · tool lookup_policy · tool granted **yes** · scope policy:read · scope granted **yes** · resource.id lending-basics · resource known **yes** · resource granted **yes** · allowed_resource.ids lending-basics · ALLOW tool_granted · mcp.started **yes** · terminal mcp.completed · runtime handler **1** · control executed false · mcp executed true · outcome success

**ATTACK** `{ATTACK_ID}`  
profile vulnerable · mode ATTACK · tool lookup_policy · tool granted **yes** · scope policy:read · scope granted **yes** · resource.id executive-restricted · resource known **yes** · resource granted **no** · allowed_resource.ids still lending-basics · ALLOW fail-open resource_not_granted · mcp.started **yes** · terminal mcp.completed · runtime handler **1** · control executed false · mcp executed true · outcome success

**RETEST** `{RETEST_ID}`  
profile defended · mode RETEST · tool lookup_policy · tool granted **yes** · scope policy:read · scope granted **yes** · resource.id executive-restricted · resource known **yes** · resource granted **no** · allowed_resource.ids lending-basics · DENY resource_not_granted · mcp.started **no** · terminal none · runtime handler **0** · control executed false · outcome prevented

Handler counts are **runtime** facts from Phase 5C. Splunk tables below corroborate the indexed copy. Empty COMPARE tables on this volume mean those run.ids are not in index=agentsec_telemetry here. That is not DENY.

Q-MCP-EXECUTED column executed is the **control-event** field (false on ALLOW). Use has_started and execution_state. Scroll right in the EXECUTED tables.

Q-MCP-SCOPE on ATTACK remains granted. That is expected. The resource hunt is the difference.

{ALLOW_NOT_EXEC}

Core lesson: same granted tool, same granted scope, same ungranted resource on ATTACK vs RETEST. Vulnerable labeled fail-open ALLOW executes. Defended DENY does not. The grant never becomes executive-restricted.
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
        cap_authz + " Expect DENY resource_not_granted prevented.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_r_base",
        "ds_q_resource_baseline",
        "BASELINE Q-MCP-RESOURCE-AUTHZ",
        cap_resource + " Expect granted.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_r_atk",
        "ds_q_resource_attack",
        "ATTACK Q-MCP-RESOURCE-AUTHZ",
        cap_resource + " Expect known_but_ungranted with ALLOW.",
        no_data=empty_control,
    )
    add_table(
        "viz_cmp_r_rt",
        "ds_q_resource_retest",
        "RETEST Q-MCP-RESOURCE-AUTHZ",
        cap_resource + " Expect known_but_ungranted with DENY.",
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

1. **RUNTIME.** Did the handler run? ToolRegistry / handler_invoke_count. Splunk does not decide this.
2. **LOCAL.** artifacts/<run-id>/events.jsonl sequence and event contract.
3. **EXPORT.** export.json — telemetry was emitted. otlp.ok is not Splunk success. Packs keep splunk.verified=false until a search ran.
4. **SPLUNK.** A copy arrived. Completeness is local count vs dc(_raw) for that run.id.
5. **SEARCH.** Analytical interpretation of that copy (Q-MCP-* including Q-MCP-RESOURCE-AUTHZ). Zero rows follow no-data semantics.
6. **DETECTION.** DET-MCP-001 proves only that **no indexed DENY→execution invariant violation was found**. It does not prove the handler never ran. 0 detector hits is not: system is secure.

States: COMPLETE / PARTIAL / FAILED / NOT VERIFIED per layer.

{RUNTIME_AUTH}

## Correlation limitation

DET-MCP-001 currently correlates run_id + tool. Valid for one invocation per run. Not sufficient later for multiple same-tool calls against different resources. Do not invent invocation.id in this workshop.

## Knowledge check (not scored)

Questions on this tab. Sample:

- Why is executive-restricted not malformed?
- Why is executive-restricted DENY but does-not-exist ERROR?
- Does ALLOW mean the resource was granted?
- Why does vulnerable ATTACK show ALLOW while resource_relation remains known_but_ungranted?
- Can tool arguments widen allowed_resource.ids?
- Why does AllowTicket.resource_id matter?
- Why is no mcp.started row not authoritative proof of non-execution?
- Why can DET-MCP-001 be reused?
- Why might run_id + tool become insufficient later?

## Limitations that still apply

- CTRL-MCP-001 is a lab allow-list, not production IAM.
- JSON-RPC is in-process, not stdio/HTTP MCP transport.
- Q-MCP-AFTER-DENY zero rows ≠ independent non-execution.
- Resource positive control is **SIMULATED** (makeresults).
- This dashboard is not a detection pack. It does not enable DET-MCP-001. It does not create DET-MCP-004.
- Duplicate-key rejection has no control.decision event. Do not hunt one.
- No MCP-005 / Cisco / MLTK on this page.

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
        "title": "Parameter / Resource Authorization",
        "description": (
            "WS-MCP-004 Dashboard Studio workshop. Reuses validated Q-MCP investigation SPL "
            "plus Q-MCP-RESOURCE-AUTHZ. Saved search DET-MCP-001 is packaged disabled; this "
            "dashboard does not enable it. Not a notable-event pack. Not DET-MCP-004. "
            "Splunk does not ALLOW or DENY a resource."
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
                "type": "input.dropdown",
                "title": "Investigate specimen",
                "options": {
                    "token": "run_id",
                    "defaultValue": BASELINE_ID,
                    "items": [
                        {"label": "Baseline — defended / normal", "value": BASELINE_ID},
                        {"label": "Attack — vulnerable / malicious", "value": ATTACK_ID},
                        {"label": "Retest — defended / malicious", "value": RETEST_ID},
                        {"label": "Unknown — missing security context", "value": UNKNOWN_ID},
                    ],
                },
            },
        },
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "options": {
                "submitButton": False,
                "submitOnDashboardLoad": True,
                "showTitleAndDescription": True,
            },
            "globalInputs": [
                "input_run_id",
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
                        block("viz_learn", 0, 0, FULL, 440),
                        block("viz_learn_granted", 0, 440, THIRD, 300),
                        block("viz_learn_known", THIRD, 440, THIRD, 300),
                        block("viz_learn_unknown", THIRD * 2, 440, THIRD, 300),
                        block("viz_learn_params", 0, 740, FULL, 360),
                    ],
                    1120,
                ),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 340),
                        block("viz_baseline_what_id", 0, 340, FULL, 220),
                        block("viz_baseline_what_dec", 0, 560, FULL, 260),
                        block("viz_baseline_authz", 0, 820, HALF, 260),
                        block("viz_baseline_resource", HALF, 820, HALF, 260),
                        block("viz_baseline_tool", 0, 1080, FULL, 240),
                        block("viz_baseline_exec", 0, 1320, FULL, 300),
                    ],
                    1640,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 440),
                        block("viz_attack_what_id", 0, 440, FULL, 220),
                        block("viz_attack_what_dec", 0, 660, FULL, 260),
                        block("viz_attack_authz", 0, 920, HALF, 260),
                        block("viz_attack_resource", HALF, 920, HALF, 260),
                        block("viz_attack_tool", 0, 1180, FULL, 240),
                        block("viz_attack_exec", 0, 1420, FULL, 300),
                    ],
                    1740,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, FULL, 280),
                        block("viz_observe_seq", 0, 280, FULL, 400),
                        block("viz_observe_authz", 0, 680, HALF, 300),
                        block("viz_observe_resource", HALF, 680, HALF, 300),
                    ],
                    1000,
                ),
                "layout_hunt": layout(
                    [
                        block("viz_hunt_md", 0, 0, FULL, 360),
                        block("viz_hunt_authz", 0, 360, HALF, 280),
                        block("viz_hunt_scope", HALF, 360, HALF, 280),
                        block("viz_hunt_resource", 0, 640, FULL, 320),
                        block("viz_hunt_exec", 0, 960, FULL, 300),
                        block("viz_hunt_tool", 0, 1260, FULL, 240),
                    ],
                    1520,
                ),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, FULL, 560),
                        block("viz_detect_live", 0, 560, HALF, 400),
                        block("viz_detect_sim", HALF, 560, HALF, 400),
                    ],
                    980,
                ),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 520),
                        block("viz_unknown_md", 0, 520, FULL, 280),
                        block("viz_unknown_authz", 0, 800, HALF, 300),
                        block("viz_unknown_resource", HALF, 800, HALF, 300),
                        block("viz_malformed_md", 0, 1100, FULL, 240),
                    ],
                    1360,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 320),
                        block("viz_retest_what_id", 0, 320, FULL, 220),
                        block("viz_retest_what_dec", 0, 540, FULL, 260),
                        block("viz_retest_authz", 0, 800, HALF, 260),
                        block("viz_retest_resource", HALF, 800, HALF, 260),
                        block("viz_retest_tool", 0, 1060, FULL, 240),
                        block("viz_retest_exec", 0, 1300, FULL, 300),
                    ],
                    1620,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 560),
                        block("viz_cmp_c_base", 0, 560, THIRD, 280),
                        block("viz_cmp_c_atk", THIRD, 560, THIRD, 280),
                        block("viz_cmp_c_rt", THIRD * 2, 560, THIRD, 280),
                        block("viz_cmp_r_base", 0, 840, THIRD, 280),
                        block("viz_cmp_r_atk", THIRD, 840, THIRD, 280),
                        block("viz_cmp_r_rt", THIRD * 2, 840, THIRD, 280),
                        block("viz_cmp_e_base", 0, 1120, THIRD, 300),
                        block("viz_cmp_e_atk", THIRD, 1120, THIRD, 300),
                        block("viz_cmp_e_rt", THIRD * 2, 1120, THIRD, 300),
                    ],
                    1440,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 820),
                        block("viz_prove_what_id", 0, 820, FULL, 220),
                        block("viz_prove_what_dec", 0, 1040, FULL, 260),
                    ],
                    1320,
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
        "  <label>Parameter / Resource Authorization</label>\n"
        "  <description>LIVE Parameter / Resource Authorization workshop. LAB-MCP-004. Splunk does not ALLOW or DENY.</description>\n"
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
