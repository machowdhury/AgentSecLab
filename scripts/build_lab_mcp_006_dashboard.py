#!/usr/bin/env python3
"""Build the LAB-MCP-006 Dashboard Studio definition.

Q-MCP files from LAB-MCP-001 are unchanged except replacing __RUN_ID__ with a
quoted Studio token. Q-MCP-DELEGATION is the MCP-006 primary hunt.
DET-MCP-001.spl is not modified. The DETECT fixture is DET-MCP-001-POSITIVE-CONTROL
(SIMULATED). No DET-MCP-006.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
DELEGATION_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-006" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-MCP-006" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_mcp_006.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

BASELINE_ID = "1cf98c4d-1bd8-4df5-be70-b82419e2c2b2"
ATTACK_ID = "d7524a4e-8da6-4171-8867-d2a2168128ac"
RETEST_ID = "50f7ec04-7524-41c0-95a8-3b1ef4d91dc4"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_HUNT = (
    "Investigate specimen defaults to the BASELINE specimen so this page is not an error "
    "state. Custom run.id is available from Search. Zero rows means "
    "no indexed CTRL-DELEGATION-001 for that id. Zero rows is not DENY and is not "
    "proof of non-execution by itself."
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
DEPUTY_NOT_CALLER = (
    "DEPUTY AUTHORITY ≠ CALLER AUTHORITY. DEPUTY AUTHORITY ≠ DELEGATED AUTHORITY. "
    "The deputy may possess a tool. That is not proof the caller delegated it."
)
GRANT_GAP = (
    "SERVER AUTHORITY EVIDENCE — LIMITED. There is no indexed allowed_tools. "
    "Delegated tools {lookup_policy} and ambient tools {lookup_policy, lookup_customer_tier} "
    "are runtime/manifest facts. Indexed authority.source is what CTRL-DELEGATION-001 consulted. "
    "Hop-0 allowed_scope is coded delegated SCOPE (policy:read), not a tool list."
)


def load_spl(name: str, *, delegation: bool = False) -> str:
    directory = DELEGATION_DIR if delegation else SEARCH_DIR
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
| eval hop=mvindex(mvdedup('agentsec.hop.index'),0)
| eval agent=mvindex(mvdedup('gen_ai.agent.id'),0)
| eval delegator=mvindex(mvdedup('agentsec.delegator.agent.id'),0)
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval authority_source=mvindex(mvdedup('agentsec.delegation.authority.source'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval attempted=mvindex(mvdedup('agentsec.operation.attempted'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| table sequence, run_id, event_name, hop, agent, delegator, control_id, tool, requested_scope, allowed_scope, authority_source, decision, reason, attempted, executed, outcome
| sort sequence"""


def what_happened_spl(token: str) -> str:
    return bind_run_id(load_spl("Q-MCP-DELEGATION.spl", delegation=True), token)


def build() -> dict:
    q_who = bind_run_id(load_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_after = bind_run_id(load_spl("Q-MCP-AFTER-DENY.spl"), "run_id")
    q_delegation = bind_run_id(load_spl("Q-MCP-DELEGATION.spl", delegation=True), "run_id")
    q_authz_b = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), BASELINE_ID)
    q_authz_a = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), ATTACK_ID)
    q_authz_r = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), RETEST_ID)
    q_tool_a = bind_literal(load_spl("Q-MCP-TOOL.spl"), ATTACK_ID)
    q_tool_r = bind_literal(load_spl("Q-MCP-TOOL.spl"), RETEST_ID)
    q_exec_b = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), BASELINE_ID)
    q_exec_a = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), ATTACK_ID)
    q_exec_r = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), RETEST_ID)
    q_who_b = bind_literal(load_spl("Q-MCP-WHO.spl"), BASELINE_ID)

    data_sources = dict(
        (
            search_ds("ds_q_who", "Q-MCP-WHO", q_who),
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_after_deny", "Q-MCP-AFTER-DENY", q_after),
            search_ds("ds_q_delegation", "Q-MCP-DELEGATION", q_delegation),
            search_ds(
                "ds_det_mcp_001_sim",
                "DET-MCP-001-POSITIVE-CONTROL",
                load_spl("DET-MCP-001-POSITIVE-CONTROL.spl"),
            ),
            search_ds("ds_observe_seq", "MCP-006 observe sequence", observe_sequence_spl("run_id")),
            search_ds("ds_what_baseline", "What Happened BASELINE", what_happened_spl(BASELINE_ID)),
            search_ds("ds_what_attack", "What Happened ATTACK", what_happened_spl(ATTACK_ID)),
            search_ds("ds_what_retest", "What Happened RETEST", what_happened_spl(RETEST_ID)),
            search_ds("ds_q_authz_baseline", "Q-MCP-AUTHZ BASELINE", q_authz_b),
            search_ds("ds_q_authz_attack", "Q-MCP-AUTHZ ATTACK", q_authz_a),
            search_ds("ds_q_authz_retest", "Q-MCP-AUTHZ RETEST", q_authz_r),
            search_ds("ds_q_tool_attack", "Q-MCP-TOOL ATTACK", q_tool_a),
            search_ds("ds_q_tool_retest", "Q-MCP-TOOL RETEST", q_tool_r),
            search_ds("ds_q_executed_baseline", "Q-MCP-EXECUTED BASELINE", q_exec_b),
            search_ds("ds_q_executed_attack", "Q-MCP-EXECUTED ATTACK", q_exec_a),
            search_ds("ds_q_executed_retest", "Q-MCP-EXECUTED RETEST", q_exec_r),
            search_ds("ds_q_who_baseline", "Q-MCP-WHO BASELINE", q_who_b),
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
        "No indexed MCP execution-start event was found for this run. That does not "
        "automatically mean DENY. ERROR, schema failure, and export loss also look like zero rows."
    )
    empty_after = (
        "No indexed DENY followed later by mcp.started was found for this run. "
        "That does not independently prove the handler never executed. Runtime handler count remains authoritative."
    )
    empty_what = (
        "No indexed CTRL-DELEGATION-001 was found for this run. The dashboard will not "
        "invent delegated authority, ambient substitution, or prevention from an empty table."
    )
    empty_seq = (
        "No indexed control or mcp.* events were found for this run. Ordering cannot "
        "be shown. That is not a security outcome."
    )
    empty_delegation = (
        "Q-MCP-DELEGATION returned zero rows. This hunt requires CTRL-DELEGATION-001. "
        "Zero rows is not safe, not DENY, and not proof delegated authority was refused."
    )
    cap_what = (
        "Q-MCP-DELEGATION (data-driven What Happened). One row per run.id with caller, "
        "deputy_observation, authority.source, CTRL-DELEGATION-001, downstream MCP, and "
        "execution_observation. deputy_not_on_indexed_hop1 means hop 1 was not indexed."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision rows. executed here is the control-event field "
        "(false on ALLOW). It is not handler execution. ERROR is not DENY. "
        "MCP-006 ALLOW paths show CTRL-DELEGATION-001 then CTRL-MCP-001. Do not collapse them."
    )
    cap_delegation = (
        "Q-MCP-DELEGATION (primary MCP-006 hunt). authority.source is what the control "
        "consulted (delegated vs ambient_deputy). coded_delegated_scope is SCOPE, not tools. "
        "Do not read MCP ALLOW as proof the caller was delegated the tool."
    )
    cap_tool = "Q-MCP-TOOL mcp.started rows. Zero rows is not automatically DENY."
    cap_executed = (
        "Q-MCP-EXECUTED. Control executed stays false on ALLOW. Read has_started "
        "and execution_state for whether the handler began. Two rows can appear because "
        "this hunt groups by tool and MCP-006 has two control events for the same tool."
    )
    cap_who = (
        "Q-MCP-WHO. Hop 0 agent is the caller. Hop 1 agent is the deputy when hop 1 exists. "
        "This hunt does not label caller vs deputy. RETEST has one row (caller only)."
    )
    cap_seq = (
        "Ordered control then mcp.* events with hop.index, agent, and authority.source. "
        "CTRL-DELEGATION-001 is hop 0. CTRL-MCP-001 and mcp.started appear only after ALLOW."
    )

    add_md(
        "viz_learn",
        f"""
# Confused Deputy

Investigate whether a deputy's own authority was actually delegated by this caller.

**REPLAY SPECIMEN** · historical evidence · Schema 1.4.0 · INV-001 · CTRL-DELEGATION-001

**The deputy may possess authority — but did the caller actually delegate that authority for this operation?**

{DEPUTY_NOT_CALLER}

Not every delegated-agent workflow is a confused-deputy attack. BASELINE is legitimate delegation.

**Canonical specimens (historical)**

BASELINE `{BASELINE_ID}`

ATTACK `{ATTACK_ID}`

RETEST `{RETEST_ID}`

Ladder: MCP-001 tool → MCP-003 scope → MCP-004 resource → MCP-005 result data → **MCP-006 caller vs deputy authority**. Splunk does **not** ALLOW or DENY a deputy call.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_ident",
        """
# CALLER vs DEPUTY

**Caller:** Credit Agent `acme-agent-credit-002` — requests the operation.

**Deputy:** Compliance Agent `acme-agent-compliance-004` — performs work on behalf of the caller.

**Principal:** `applicant-web`

```text
Caller → Deputy → CTRL-DELEGATION-001 → MCP authorize → Tool handler
```

Identity is necessary and not sufficient. The deputy may possess a tool. That is not proof the caller delegated it.
""",
        title="CALLER / DEPUTY",
    )
    add_md(
        "viz_learn_auth",
        f"""
# DELEGATED vs AMBIENT

**Delegated authority (runtime):** Credit may ask Compliance for `lookup_policy` at `policy:read`.

**Ambient authority (runtime):** Compliance also possesses `lookup_customer_tier` for **its own** work.

**Indexed:** `agentsec.delegation.authority.source` = `delegated` or `ambient_deputy`.

Confused deputy: the deputy spends **ambient** authority for an operation the caller was **not** entitled to request.

{GRANT_GAP}
""",
        title="DELEGATED / AMBIENT",
    )
    add_md(
        "viz_learn_trust",
        """
# Trust boundary

```text
CALLER REQUEST
        ↓
CTRL-DELEGATION-001  (delegated authority)
        ↓ only if ALLOW
CTRL-MCP-001         (MCP authorization)
        ↓ only if ALLOW
TOOL HANDLER
```

These controls solve related but different problems. Execution after ALLOW is not proof the caller was authorized. No `gen_ai.tool.call.id`. Rejected hunts (not published): Q-MCP-AMBIENT-USE, Q-MCP-DELEGATION-CHAIN.
""",
        title="TRUST BOUNDARY",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**What the learner did:** coded Credit → Compliance invoke for granted `lookup_policy`, scope `policy:read`, resource `lending-basics`, profile defended, testbed.mode=BASELINE.

**Delegation:** CTRL-DELEGATION-001 **ALLOW** `delegation_granted`. authority.source=`delegated`.

**Downstream MCP:** CTRL-MCP-001 **ALLOW** `tool_granted`. Handler runs. `mcp.completed`.

This is legitimate delegation. Execution here does **not** prove authorization by itself — the control row is the authorization evidence.

**Evidence:** Q-MCP-DELEGATION on token **BASELINE**. Runtime policy handler **1**.

Validated reference: `{BASELINE_ID}`.

{ALLOW_NOT_EXEC}
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_what",
        "ds_what_baseline",
        "What Happened? Q-MCP-DELEGATION",
        cap_what + " Expect source delegated, ALLOW delegation_granted, MCP ALLOW, mcp.completed_observed.",
        no_data=empty_what,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_baseline",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect CTRL-DELEGATION-001 ALLOW then CTRL-MCP-001 ALLOW.",
        no_data=empty_control,
    )
    add_table(
        "viz_baseline_who",
        "ds_q_who_baseline",
        "Q-MCP-WHO",
        cap_who + " Expect credit-002 and compliance-004.",
        no_data=empty_control,
    )
    add_table(
        "viz_baseline_exec",
        "ds_q_executed_baseline",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect execution_state=mcp.completed for lookup_policy.",
        no_data=empty_tool,
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK

**The deputy could perform the operation, but that does not mean the caller was authorized to cause it.**

Same caller and deputy as BASELINE. Request: `lookup_customer_tier` / `customer:read` / `cust-001`. Profile **vulnerable**. mode=ATTACK.

```text
Credit asks Compliance for lookup_customer_tier
        ↓
CTRL-DELEGATION-001 ALLOW
reason = vulnerable_profile_fail_open:ambient_deputy_authority
authority.source = ambient_deputy
        ↓
CTRL-MCP-001 ALLOW tool_granted  (selected ambient policy)
        ↓
handler executes
```

Caller was **not** delegated this tool. Deputy **possesses** it ambiently. Vulnerable path **substitutes** ambient authority (`authority.source=ambient_deputy`). Downstream MCP ALLOW is not caller authorization. ATTACK/RETEST request hash `sha256:ea33191fceeb105e47270f6839bb98addfb7245a32534138192b23e1fab9a419`.

Runtime tier handler **1**. Splunk: `mcp.completed_observed`.

Validated: `{ATTACK_ID}`. Tables use the **ATTACK** token.
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_what",
        "ds_what_attack",
        "What Happened? Q-MCP-DELEGATION",
        cap_what + " Expect source ambient_deputy, vulnerable ALLOW, MCP ALLOW, mcp.completed_observed.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_attack",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect CTRL-DELEGATION-001 fail-open ALLOW then CTRL-MCP-001 ALLOW. MCP ALLOW is not caller grant.",
        no_data=empty_control,
    )
    add_table(
        "viz_attack_tool",
        "ds_q_tool_attack",
        "Q-MCP-TOOL",
        cap_tool + " Expect mcp.started for lookup_customer_tier.",
        no_data=empty_tool,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_executed_attack",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect has_started=1. Execution is not caller authorization.",
        no_data=empty_tool,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Use **Hunt run.id** (defaults to BASELINE). Tables are telemetry, not a story.

Read IDENTITY, AUTHORITY, CONTROL, EXECUTION as separate facts. Sequence shows hop 0 then hop 1.

{GRANT_GAP}

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_table("viz_observe_seq", "ds_observe_seq", "Control then MCP events (ordered)", cap_seq, no_data=empty_seq)
    add_table("viz_observe_who", "ds_q_who", "IDENTITY — Q-MCP-WHO", cap_who, no_data=empty_control)
    add_table("viz_observe_delegation", "ds_q_delegation", "AUTHORITY — Q-MCP-DELEGATION", cap_delegation, no_data=empty_delegation)
    add_table("viz_observe_authz", "ds_q_authz", "CONTROL — Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_observe_exec", "ds_q_executed", "EXECUTION — Q-MCP-EXECUTED", cap_executed, no_data=empty_tool)

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

**Question:** What did CTRL-DELEGATION-001 decide, for which caller/deputy/tool, which authority source was used, and what downstream MCP / execution were indexed?

**Primary hunt:** Q-MCP-DELEGATION. **Rejected / not published:** Q-MCP-AMBIENT-USE, Q-MCP-DELEGATION-CHAIN, Q-MCP-DELEGATION-EXECUTED, Q-MCP-DELEGATION-AUTHORITY (duplicates). No hunt invents `allowed_tools`.

Q-MCP-SCOPE and Q-MCP-RESOURCE-AUTHZ are not bound here. SCOPE uses equality, not subset. RESOURCE-AUTHZ on ATTACK is `other` (cust-001 vs lending-basics wire) — not the confused-deputy predicate.

{ALLOW_NOT_EXEC} {DEPUTY_NOT_CALLER}

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table("viz_hunt_delegation", "ds_q_delegation", "Q-MCP-DELEGATION (primary MCP-006 hunt)", cap_delegation, no_data=empty_delegation)
    add_table("viz_hunt_who", "ds_q_who", "Q-MCP-WHO", cap_who, no_data=empty_control)
    add_table("viz_hunt_authz", "ds_q_authz", "Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED", cap_executed, no_data=empty_tool)
    add_table("viz_hunt_tool", "ds_q_tool", "Q-MCP-TOOL", cap_tool, no_data=empty_tool)

    add_md(
        "viz_detect_md",
        """
# DETECT — DETECTION ANALYZED — NO NEW DETECTOR

No notable event. **No DET-MCP-006.** This dashboard does **not** enable DET-MCP-001.

DET-MCP-001 detects **DENY → later execution**. MCP-006 ATTACK is insufficient delegated authority → vulnerable **ALLOW → execution**. DET-MCP-001 is expected **silent**. That is not a detector failure. It is a different invariant.

Huntable evidence is not the same as a reliable detection predicate. `authority.source=ambient_deputy` is indexed, but delegated **tool** membership is not. An enum-only notable would overclaim.

**LIVE Phase 7C (MEASURED):** BASELINE **0** · ATTACK **0** · RETEST **0**. Zero rows is not "the attack did not occur."

Right table: **SIMULATED** `| makeresults`. **NOT INDEXED.** Not a LIVE MCP-006 attack. Not OBSERVED runtime.
""",
        title="STEP 5 DETECT",
    )
    add_md(
        "viz_detect_why",
        """
# Why no DET-MCP-006

A detector needs deterministic evidence, defensible fields, reliable correlation, acceptable false-positive semantics, and a clearly defined invariant. Phase 7C: **DETECTION ANALYZED — NO NEW DETECTOR.** No indexed `allowed_tools`. BASELINE deputy also possesses ambient `lookup_policy` with source=`delegated` — possession alone must not alert. A reason-string notable would be a lab-label detector. Hunt is sufficient. DET-MCP-001 stays unchanged.
""",
        title="NO NEW DETECTOR",
    )
    add_table(
        "viz_detect_live",
        "ds_q_after_deny",
        "Q-MCP-AFTER-DENY (indexed hunt)",
        "Investigation query. LIVE MCP-006 specimens: 0 rows. DET-MCP-001 silent on ATTACK vulnerable ALLOW. Zero rows is not 'the attack did not occur.'",
        no_data="No indexed detection rows matched this run. No indexed DENY followed later by mcp.started was found. That is not a security outcome and not independent non-execution proof.",
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

**THE DEPUTY MAY BE ALLOWED TO CALL THE TOOL. THE CALLER STILL MUST BE ALLOWED TO ASK.**

```text
Caller
  ↓
Deputy
  ↓
CTRL-DELEGATION-001   (delegated authority for this request)
  ↓ only if ALLOW
CTRL-MCP-001          (MCP tool/scope/resource for the selected policy)
  ↓ only if ALLOW
Tool handler
```

Defended RETEST: CTRL-DELEGATION-001 **DENY** `delegated_authority_not_granted`. Downstream MCP does not begin. Splunk did **not** prevent the action. The control did.

{GRANT_GAP}
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_defend_evidence",
        """
# Two controls, two questions

CTRL-DELEGATION-001 asks: may **this caller** have **this deputy** perform **this operation**?

CTRL-MCP-001 asks: may the **selected MCP policy** call **this tool** at **this scope**?

ATTACK MCP ALLOW answers the second question against an ambient policy object. It does not answer the first. Splunk searches do not move either control.
""",
        title="INV-001",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

Same security request as ATTACK. Same caller, deputy, tool, scope, resource, arguments hash. Profile **defended**. mode=RETEST.

SAME REQUEST + DIFFERENT SECURITY PROFILE = DIFFERENT AUTHORIZATION OUTCOME.

- CTRL-DELEGATION-001: **DENY** `delegated_authority_not_granted`
- authority.source: `delegated` (consulted the delegated set; tool not granted)
- downstream MCP: **none** (`no_downstream_mcp_control_event`)
- runtime handler count: **0** (authoritative)
- Splunk: **no indexed MCP execution-start event observed** (corroboration only)
- deputy on hop 1: `deputy_not_on_indexed_hop1` — hop 1 never started; runtime/manifest still name compliance-004

Do not say Splunk proved the handler never ran. Do not treat an empty TOOL table as DENY by itself.

Validated: `{RETEST_ID}`. Tables use the **RETEST** token.
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_what",
        "ds_what_retest",
        "What Happened? Q-MCP-DELEGATION",
        cap_what + " Expect DENY delegated_authority_not_granted, deputy_not_on_indexed_hop1, no_indexed_mcp_execution_event.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_retest",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect only CTRL-DELEGATION-001 DENY.",
        no_data=empty_control,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_retest",
        "Q-MCP-TOOL",
        "Q-MCP-TOOL. No indexed mcp.started observed. That is Splunk corroboration. Runtime handler count = 0 is authoritative.",
        no_data=empty_tool,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_executed_retest",
        "Q-MCP-EXECUTED",
        cap_executed + " Expect execution_state=no_mcp_execution_event.",
        no_data=empty_tool,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

Three-way comparison from Phase 7C LIVE evidence. Do not infer empty cells.

SAME REQUEST (ATTACK vs RETEST) + DIFFERENT SECURITY PROFILE = DIFFERENT AUTHORIZATION OUTCOME.

Delegated tools and ambient tools in the cards are **runtime/manifest** facts. Indexed comparison is `authority.source` plus control decisions. {GRANT_GAP}

{ALLOW_NOT_EXEC} {DEPUTY_NOT_CALLER}

COMPARE uses three markdown cards, not three copies of the 18-column Q-MCP-DELEGATION table. Indexed reconstruction remains on BASELINE / ATTACK / RETEST What Happened tables.
""",
        title="BEFORE / AFTER",
    )
    add_md(
        "viz_cmp_card_base",
        f"""
# BASELINE

**Profile:** defended · **Mode:** BASELINE

- Caller: credit-002
- Deputy: compliance-004 (hop 1 indexed)
- Operation: `lookup_policy` / `policy:read` / `lending-basics`
- Delegated (runtime): `lookup_policy`
- Ambient (runtime): `lookup_policy`, `lookup_customer_tier`
- Source (indexed): **delegated**
- Delegation: ALLOW `delegation_granted`
- MCP: ALLOW `tool_granted`
- Execution began: YES (indexed mcp.completed)
- Runtime handler: **1**
- Terminal: completed_allowed

Validated: `{BASELINE_ID}`
""",
        title="BASELINE",
    )
    add_md(
        "viz_cmp_card_atk",
        f"""
# ATTACK

**Profile:** vulnerable · **Mode:** ATTACK

- Caller: credit-002
- Deputy: compliance-004 (hop 1 indexed)
- Operation: `lookup_customer_tier` / `customer:read` / `cust-001`
- Delegated (runtime): `lookup_policy` (**not this tool**)
- Ambient (runtime): includes `lookup_customer_tier`
- Source (indexed): **ambient_deputy**
- Delegation: ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority`
- MCP: ALLOW `tool_granted` (not caller grant)
- Execution began: YES
- Runtime handler: **1**
- Terminal: completed_allowed

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

- Caller: credit-002
- Deputy: compliance-004 (runtime; hop 1 not indexed)
- Operation: **same as ATTACK**
- Delegated / ambient (runtime): same sets as ATTACK
- Source (indexed): **delegated**
- Delegation: DENY `delegated_authority_not_granted`
- MCP: none
- Execution began: NO indexed start
- Runtime handler: **0** (authoritative)
- Terminal: completed_denied

Splunk: no indexed MCP execution-start event observed.

Validated: `{RETEST_ID}`
""",
        title="RETEST",
    )

    add_md(
        "viz_prove",
        f"""
# PROVE

Evidence hierarchy. Splunk does not manufacture runtime truth.

```text
RUNTIME  →  LOCAL EVIDENCE  →  OTLP  →  SPLUNK  →  HUNT  →  SECURITY EVIDENCE
```

1. **RUNTIME.** Handler counts. Authoritative for execution / non-execution in this lab.

{RUNTIME_AUTH}

2. **LOCAL.** artifacts/<run-id>/events.jsonl

3. **EXPORT.** export.json (`otlp.ok` is not Splunk success; packs keep `splunk.verified=false`)

4. **SPLUNK.** Completeness = local count vs `dc(_raw)`

5. **SEARCH.** Q-MCP-DELEGATION. Zero rows follow no-data semantics.

6. **DETECTION.** DET-MCP-001: no indexed DENY→start found. Silent on vulnerable ALLOW. 0 hits ≠ system is secure. **NO NEW DETECTOR.**

LIVE A/B/C are OBSERVED/MEASURED. DETECT right table is **SIMULATED**.

## Knowledge checks (not scored)

1. Who was the caller?
2. Who acted as deputy?
3. What operation was requested?
4. What authority did the caller actually delegate? (runtime grant — not indexed tools)
5. What authority did the deputy possess? (runtime ambient — not indexed as a set)
6. Which authority source was used? (indexed)
7. What did CTRL-DELEGATION-001 decide?
8. What did downstream MCP authorization decide?
9. Did execution begin? What evidence?
10. Why is deputy authority not proof of caller authorization?
11. Why does successful execution not prove valid delegation?
12. Why does an empty Splunk execution table not independently prove prevention?
13. Why might DET-MCP-001 remain silent?
14. What would the SOC hunt next?

Answers: on this tab.

## Correlation limitation

No `gen_ai.tool.call.id`. This lab is one operation per run. Repeated same-tool calls would need stronger per-invocation correlation.

## Limitations

- no indexed allowed_tools
- RETEST deputy not first-class on hop 1
- 200-character bounded preview (not used as grant proof)
- Q-MCP-EXECUTED may show two control rows for one tool
- Splunk absence of mcp.started is corroboration only
- Q-MCP-AMBIENT-USE rejected / not published
- no DET-MCP-006

Validated: BASELINE `{BASELINE_ID}` · ATTACK `{ATTACK_ID}` · RETEST `{RETEST_ID}`.
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_what",
        "ds_q_delegation",
        "What Happened? Q-MCP-DELEGATION (Hunt run.id)",
        cap_what,
        no_data=empty_what,
    )

    definition = {
        "title": "Confused Deputy",
        "description": (
            "WS-MCP-006 Dashboard Studio workshop. Reuses validated Q-MCP investigation SPL "
            "plus Q-MCP-DELEGATION. Saved search DET-MCP-001 is packaged disabled; this "
            "dashboard does not enable it. No DET-MCP-006. Splunk does not ALLOW or DENY a deputy call."
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
                        block("viz_learn", 0, 0, FULL, 500),
                        block("viz_learn_ident", 0, 500, THIRD, 460),
                        block("viz_learn_auth", THIRD, 500, THIRD, 460),
                        block("viz_learn_trust", THIRD * 2, 500, THIRD, 460),
                    ],
                    980,
                ),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 340),
                        block("viz_baseline_what", 0, 340, FULL, 300),
                        block("viz_baseline_authz", 0, 640, FULL, 340),
                        block("viz_baseline_who", 0, 980, HALF, 280),
                        block("viz_baseline_exec", HALF, 980, HALF, 280),
                    ],
                    1280,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 420),
                        block("viz_attack_what", 0, 420, FULL, 300),
                        block("viz_attack_authz", 0, 720, FULL, 340),
                        block("viz_attack_tool", 0, 1060, HALF, 280),
                        block("viz_attack_exec", HALF, 1060, HALF, 280),
                    ],
                    1360,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, FULL, 240),
                        block("viz_observe_seq", 0, 240, FULL, 360),
                        block("viz_observe_who", 0, 600, HALF, 260),
                        block("viz_observe_delegation", HALF, 600, HALF, 260),
                        block("viz_observe_authz", 0, 860, HALF, 260),
                        block("viz_observe_exec", HALF, 860, HALF, 260),
                    ],
                    1140,
                ),
                "layout_hunt": layout(
                    [
                        block("viz_hunt_md", 0, 0, FULL, 340),
                        block("viz_hunt_delegation", 0, 340, FULL, 280),
                        block("viz_hunt_who", 0, 620, HALF, 260),
                        block("viz_hunt_authz", HALF, 620, HALF, 260),
                        block("viz_hunt_exec", 0, 880, HALF, 260),
                        block("viz_hunt_tool", HALF, 880, HALF, 260),
                    ],
                    1160,
                ),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, FULL, 300),
                        block("viz_detect_why", 0, 300, FULL, 260),
                        block("viz_detect_live", 0, 560, HALF, 360),
                        block("viz_detect_sim", HALF, 560, HALF, 360),
                    ],
                    940,
                ),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 540),
                        block("viz_defend_evidence", 0, 540, FULL, 320),
                    ],
                    880,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 420),
                        block("viz_retest_what", 0, 420, FULL, 300),
                        block("viz_retest_authz", 0, 720, FULL, 340),
                        block("viz_retest_tool", 0, 1060, HALF, 280),
                        block("viz_retest_exec", HALF, 1060, HALF, 280),
                    ],
                    1360,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 320),
                        block("viz_cmp_card_base", 0, 320, THIRD, 560),
                        block("viz_cmp_card_atk", THIRD, 320, THIRD, 560),
                        block("viz_cmp_card_rt", THIRD * 2, 320, THIRD, 560),
                    ],
                    900,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 980),
                        block("viz_prove_what", 0, 980, FULL, 280),
                    ],
                    1280,
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
        "  <label>Confused Deputy</label>\n"
        "  <description>LIVE Confused Deputy workshop. LAB-MCP-006. Splunk does not ALLOW or DENY.</description>\n"
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
