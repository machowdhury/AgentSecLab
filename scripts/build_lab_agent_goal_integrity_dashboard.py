#!/usr/bin/env python3
"""Build the LAB-AGENT-GOAL-INTEGRITY-001 Dashboard Studio workshop.

Reuses validated Q-GOAL-INTEGRITY-AUTHORITY (one run.id token) and Q-MCP-*
hunts. Bind tokens only. DET-MCP-001.spl is not modified. No DET-GOAL.
CTRL-GOAL-INTEGRITY-001 is not the MCP tool PDP.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
GOAL_DIR = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_agent_goal_integrity.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

# Phase 13C LIVE IDs — not Phase 13B local packs.
BASELINE = "0aced342-1295-4820-b807-9a8718d9e847"
ATTACK = "fd994587-7e1c-4a70-8013-54cb2c85254d"
RETEST = "605ba7c1-449b-4338-92df-7da3b704b08e"
TASK_ID = "summarize_lending_policy_options"
TASK_HASH = "sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c"
INSTRUCTION_HASH = "sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2"
PROPOSED_HASH = "sha256:6326e3be47ecf73831a06be2b718f42219e0c950d4c989de23aa558bfdc01b34"
GOAL_SNAPSHOT = "sha256:56ebf3bf964a45b39931007bfa4e3d3de20535d42c44cfabf7635bf421ed8b3d"
ATTACK_URL = "http://127.0.0.1:5001/labs/LAB-AGENT-GOAL-INTEGRITY-001"
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
INV_PATH = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001" / "investigations.json"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_EVENT = (
    "No indexed event matched this evidence question. That is not SAFE, not TRUSTED, "
    "not blocked, not prevented, and not proof there was no attack."
)
EMPTY_GOAL = (
    "No indexed event matched this evidence question. Q-GOAL-INTEGRITY-AUTHORITY "
    "returned zero rows. Zero rows means no indexed CTRL-GOAL-INTEGRITY-001 row for "
    "this run.id. That is not SAFE, not DENY, and not a TRUSTED verdict."
)
EMPTY_CONTROL = (
    "No indexed event matched this evidence question. Missing control.decision is "
    "not DENY. It can be a wrong run.id or an incomplete copy."
)
EMPTY_TOOL = (
    "No indexed event matched this evidence question. Missing mcp.started is not "
    "automatically DENY, blocked, or prevented. Runtime handler count remains "
    "authoritative."
)
EMPTY_AFTER = (
    "No indexed event matched this evidence question. DET-MCP-001 / Q-MCP-AFTER-DENY "
    "look for DENY then later mcp.started for the same tool. Zero rows is not SAFE."
)
EMPTY_SEQ = (
    "No indexed event matched this evidence question. Sequence cannot be shown. "
    "That is not a security outcome."
)
EMPTY_HUNT = (
    "Investigate specimen defaults to the REPLAY BASELINE copy. Choose Attack or "
    "Retest from the dropdown. Canonical BASELINE / ATTACK / RETEST pages bind "
    "REPLAY IDs automatically. Fresh LIVE run.ids come from Attack Service Search. Empty tables are missing indexed rows, not security "
    "outcomes. If Search returns zero rows, wait until Attack Service says EVIDENCE READY. Empty is not DENY. "
    "A non-canonical run.id is an advanced Search workflow — Dashboard "
    "Studio cannot safely share one hunt token between a dropdown and a free-text "
    "field without wiping the default."
)
ALLOW_NOT_EXEC = (
    "ALLOW is the control decision. Tool execution begins at mcp.started. "
    "Do not read ALLOW as execution. mcp.completed is success of a begun call. "
    "mcp.failed is execution then error, not prevention."
)
RUNTIME_AUTH = (
    "Runtime handler count is authoritative proof of non-execution for the "
    "prohibited action. Missing indexed mcp.started is corroboration only, and "
    "only on a complete copy. Splunk does not prove prevention."
)
TOOL_NOT_GOAL = (
    "AUTHORIZED TOOL != AUTHORIZED GOAL. AUTHORIZED TOOL != AUTHORIZED USE OF TOOL. "
    "REQUEST != GRANT. OBSERVE != ALLOW. ALLOW != EXECUTION. SPLUNK != ENFORCEMENT."
)


SPL_TEACHING = {
    "Q-GOAL-INTEGRITY-AUTHORITY": (
        "Constrains agentsec_telemetry. Filters quoted run.id. Surfaces task, instruction trust, "
        "proposed goal, CTRL-GOAL-INTEGRITY-001, and joined MCP grant/execution fields. It does not authorize."
    ),
    "Q-MCP-AUTHZ": (
        "Lists control.decision rows. Hop 0 is GOAL. Hop 1 is CTRL-MCP-001 when lookup_policy is requested. "
        "ALLOW tool_granted is expected on ATTACK and RETEST."
    ),
    "Q-MCP-TOOL": "mcp.started rows only. Start is execution evidence, not authorization.",
    "Q-MCP-EXECUTED": "Joins control + mcp.* into execution_state. Handler labels remain runtime authoritative.",
    "Q-MCP-WHO": "Actor, agent, tool, and hop identity. Identity is not a grant.",
}
TABLE_BIND = {
    "GOAL-I1-FIND-THE-RUN": [("ds_q_goal", "Q-GOAL-INTEGRITY-AUTHORITY (REPLAY specimen)", "One GOAL row. run.id is correlation, not authorization.")],
    "GOAL-I2-FIND-THE-AUTHORITATIVE-TASK": [("ds_q_goal", "TASK plane (REPLAY)", "task.id summarize_lending_policy_options. Same hash A/B/C.")],
    "GOAL-I3-INSPECT-THE-UNTRUSTED-INSTRUCTION": [("ds_q_goal", "INSTRUCTION plane (REPLAY)", "untrusted_instruction is classification, not malice.")],
    "GOAL-I4-RECONSTRUCT-THE-PROPOSED-GOAL": [("ds_q_goal", "PROPOSED GOAL (REPLAY)", "ATTACK/RETEST propose extract_full_policy. Proposal != authorization.")],
    "GOAL-I5-EVALUATE-GOAL-INTEGRITY": [("ds_q_goal", "CTRL-GOAL-INTEGRITY-001 (REPLAY)", "Hop 0 task plane. Not the MCP tool PDP.")],
    "GOAL-I6-EVALUATE-TOOL-AUTHORIZATION": [("ds_q_authz", "Q-MCP-AUTHZ (REPLAY)", "Hop 1 ALLOW tool_granted on ATTACK and RETEST.")],
    "GOAL-I7-DETERMINE-WHAT-EXECUTED": [
        ("ds_q_executed", "Q-MCP-EXECUTED (REPLAY)", "lookup_policy started. Handler labels are runtime."),
        ("ds_q_tool", "Q-MCP-TOOL (REPLAY)", "mcp.started rows only."),
    ],
}


def fingerprint_block(h: str) -> str:
    """Split sha256:<64 hex> so Studio markdown can show the full digest in a card."""
    algo, digest = h.split(":", 1)
    return f"{algo}:\n{digest[:32]}\n{digest[32:]}"


def load_hunt_spl(name: str) -> str:
    goal = GOAL_DIR / name
    if goal.is_file():
        return goal.read_text(encoding="utf-8").strip()
    return (SEARCH_DIR / name).read_text(encoding="utf-8").strip()


def question_md(inv: dict, number: int) -> str:
    return f"""
# Investigation {number} — {inv["title"]}

**QUESTION**

{inv["security_question"]}

**WHAT AM I TRYING TO PROVE?**

{inv["learning_objective"]}

**YOUR TASK (Path A — try it yourself)**

{inv["starter_guidance"]}

1. Copy the fresh LIVE run.id from Attack Service, or use Investigate specimen for canonical REPLAY.
2. [Open Splunk Search]({SEARCH_URL})
3. Constrain `index=agentsec_telemetry sourcetype=otel:agentic:json`.
4. Filter quoted `agentsec.run.id`. Execute. Read the fields yourself.

Studio cannot receive a fresh LIVE run.id. That handoff is Search, not a token write.

Starter (paste your LIVE run.id; do not search `index=*`):

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="PASTE-LIVE-RUN-ID"
```

Need help? Scroll to **Hint 1**, then **Hint 2**, then the Path B solution. Do not skip Path A.
"""


def hint_md(inv: dict, number: int, which: str) -> str:
    body = inv["hint_1"] if which == "hint_1" else inv["hint_2"]
    label = "HINT 1" if which == "hint_1" else "HINT 2"
    return f"""
# {label} — Investigation {number}

{body}

Path A is still Search. This is not the full solution.
"""


def solution_md(inv: dict, number: int) -> str:
    hunt = inv["related_hunt"]
    spl_file = f"{hunt}.spl"
    spl = load_hunt_spl(spl_file)
    bound = spl.replace("__RUN_ID__", '"$run_id$"')
    teach = SPL_TEACHING[hunt]
    nxt = inv["next_investigation"] or "PROVE — classify what you can actually conclude."
    return f"""
# Solution — Investigation {number} {inv["title"]}

This is **Path B — show solution**. Open it only after you tried Path A in Search. It is an answer key, not policy. Splunk does not enforce. Path A remains Search with your LIVE run.id.

**SOLUTION SPL** (`{hunt}`)

Copy this into Search. Replace `$run_id$` with the LIVE UUID, or leave the token for Investigate specimen REPLAY.

```
{bound}
```

**WHY THESE STAGES**

{teach}

**EXPECTED RESULT SHAPE**

{inv["expected_result_shape"]}

**WHAT YOU ARE SEEING**

{inv["result_explanation"]}

**WHAT IT MEANS**

{inv["security_interpretation"]}

**WHAT IT DOES NOT MEAN**

{inv["does_not_prove"]}

**SECURITY CONNECTION**

Control `{inv["related_control"]}` · invariant `{inv["related_invariant"]}` · hunt `{hunt}`. Splunk does **not** ALLOW or DENY.

**NEXT CHALLENGE**

{nxt}
"""


def load_spl(name: str, *, goal: bool = False) -> str:
    directory = GOAL_DIR if goal else SEARCH_DIR
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
    """Studio-only sequence view of already-validated indexed fields. Not a new hunt file."""
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"={bound_run(token)} ("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval hop=mvindex(mvdedup('agentsec.hop.index'),0)
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval task_id=mvindex(mvdedup('agentsec.task.id'),0)
| eval task_hash=mvindex(mvdedup('agentsec.task.hash'),0)
| eval task_provenance=mvindex(mvdedup('agentsec.task.provenance'),0)
| eval instruction_trust=mvindex(mvdedup('agentsec.instruction.trust'),0)
| eval goal_proposed=mvindex(mvdedup('agentsec.goal.proposed'),0)
| eval content_hash=mvindex(mvdedup('agentsec.content.hash'),0)
| eval preview=mvindex(mvdedup('agentsec.content.preview'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval resource_id=mvindex(mvdedup('agentsec.mcp.resource.id'),0)
| eval profile=mvindex(mvdedup('agentsec.security.profile'),0)
| table sequence, run_id, event_name, hop, control_id, decision, reason, task_id, task_hash, task_provenance, instruction_trust, goal_proposed, content_hash, preview, tool, requested_scope, allowed_scope, resource_id, profile
| sort sequence"""


def build() -> dict:
    q_goal = bind_run_id(load_spl("Q-GOAL-INTEGRITY-AUTHORITY.spl", goal=True), "run_id")
    q_who = bind_run_id(load_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_goal_b = bind_literal(load_spl("Q-GOAL-INTEGRITY-AUTHORITY.spl", goal=True), BASELINE)
    q_goal_a = bind_literal(load_spl("Q-GOAL-INTEGRITY-AUTHORITY.spl", goal=True), ATTACK)
    q_goal_r = bind_literal(load_spl("Q-GOAL-INTEGRITY-AUTHORITY.spl", goal=True), RETEST)
    q_authz_b = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), BASELINE)
    q_authz_a = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), ATTACK)
    q_authz_r = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), RETEST)
    q_tool_a = bind_literal(load_spl("Q-MCP-TOOL.spl"), ATTACK)
    q_tool_r = bind_literal(load_spl("Q-MCP-TOOL.spl"), RETEST)
    q_exec_b = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), BASELINE)
    q_exec_a = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), ATTACK)
    q_exec_r = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), RETEST)
    q_after_b = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), BASELINE)
    q_after_a = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), ATTACK)
    q_after_r = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), RETEST)

    data_sources = dict(
        (
            search_ds("ds_q_goal", "Q-GOAL-INTEGRITY-AUTHORITY", q_goal),
            search_ds("ds_q_who", "Q-MCP-WHO", q_who),
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_goal_b", "Q-GOAL-INTEGRITY-AUTHORITY BASELINE", q_goal_b),
            search_ds("ds_q_goal_a", "Q-GOAL-INTEGRITY-AUTHORITY ATTACK", q_goal_a),
            search_ds("ds_q_goal_r", "Q-GOAL-INTEGRITY-AUTHORITY RETEST", q_goal_r),
            search_ds("ds_q_authz_b", "Q-MCP-AUTHZ BASELINE", q_authz_b),
            search_ds("ds_q_authz_a", "Q-MCP-AUTHZ ATTACK", q_authz_a),
            search_ds("ds_q_authz_r", "Q-MCP-AUTHZ RETEST", q_authz_r),
            search_ds("ds_q_tool_a", "Q-MCP-TOOL ATTACK", q_tool_a),
            search_ds("ds_q_tool_r", "Q-MCP-TOOL RETEST", q_tool_r),
            search_ds("ds_q_exec_b", "Q-MCP-EXECUTED BASELINE", q_exec_b),
            search_ds("ds_q_exec_a", "Q-MCP-EXECUTED ATTACK", q_exec_a),
            search_ds("ds_q_exec_r", "Q-MCP-EXECUTED RETEST", q_exec_r),
            search_ds("ds_q_after_b", "Q-MCP-AFTER-DENY BASELINE", q_after_b),
            search_ds("ds_q_after_a", "Q-MCP-AFTER-DENY ATTACK", q_after_a),
            search_ds("ds_q_after_r", "Q-MCP-AFTER-DENY RETEST", q_after_r),
            search_ds("ds_observe_seq", "Goal-integrity sequence", observe_sequence_spl("run_id")),
            search_ds(
                "ds_det_mcp_001_sim",
                "DET-MCP-001-POSITIVE-CONTROL",
                load_spl("DET-MCP-001-POSITIVE-CONTROL.spl"),
            ),
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

    cap_goal = (
        "Q-GOAL-INTEGRITY-AUTHORITY. Reconstructs task, instruction trust, proposed "
        "goal, CTRL-GOAL-INTEGRITY-001, MCP grant, and indexed execution observation. "
        "Bind one run.id. Effective action is in bounded MCP content.preview, not a "
        "first-class field. Do not hunt AGENT NOTE with a regex."
    )
    cap_authz = (
        "Q-MCP-AUTHZ. Expect extra GOAL + MCP rows because gen_ai.tool.name on the "
        "GOAL event can equal the proposed action id. Q-MCP answers tool authorization. "
        "It does not independently prove task or goal authorization."
    )
    cap_tool = (
        "Q-MCP-TOOL. Hop-1 mcp.started for lookup_policy means execution began. "
        "mcp.started is not successful completion and is not proof of the effective action."
    )
    cap_exec = (
        "Q-MCP-EXECUTED. Read has_started and execution_state. " + ALLOW_NOT_EXEC
    )
    cap_who = (
        "Q-MCP-WHO. Principal / agent identity. Extra GOAL rows are expected when the "
        "proposed action id is copied onto gen_ai.tool.name. That is not a second tool grant."
    )
    cap_seq = (
        "Indexed sequence for Investigate specimen. TASK, INSTRUCTION, GOAL DECISION, "
        "TOOL AUTHORIZATION, and EXECUTION stay in separate columns. No `_raw`. "
        "No full instruction. Studio view, not a new hunt file."
    )
    cap_after = (
        "Q-MCP-AFTER-DENY. Hunt form of DET-MCP-001. LIVE goal specimens: 0 rows. "
        "Zero rows is CORRECT and is not SAFE. RETEST goal DENY uses a different "
        "gen_ai.tool.name than hop-1 lookup_policy start."
    )

    add_md(
        "viz_header",
        f"""
# Goal / Instruction Integrity

Investigate why authorization to use a tool does not authorize every goal the agent may pursue with that tool.

**LIVE vs REPLAY** · Goal / Instruction Integrity · Schema 1.9.0

**LIVE** — Attack Service mints a fresh run.id. Investigate in Splunk Search: [Launch]({ATTACK_URL})

**REPLAY** — Canonical Phase 13C Investigate specimen ids bound in Studio tables below.

Workshop: LEARN · PREDICT · LIVE ATTACK · INVESTIGATE · DEFEND · LIVE RETEST · COMPARE · PROVE
""",
        title="WORKSHOP",
    )
    add_md(
        "viz_question",
        """
# Security question

Can an untrusted instruction redefine a server-owned task even when the underlying tool is legitimately authorized?
""",
        title="SECURITY QUESTION",
    )
    add_md(
        "viz_learn_flow",
        """
# Decision path

```text
SERVER-OWNED TASK
        ↓
UNTRUSTED INSTRUCTION
        ↓
PROPOSED GOAL
        ↓
GOAL INTEGRITY
        ↓
TOOL AUTHORIZATION
        ↓
EXECUTION
```

Task authority comes from the server-owned task contract.

Tool authority comes from CTRL-MCP-001.

They are related but distinct. MCP ALLOW does not mean the agent's goal was authorized.
""",
        title="PATH",
    )
    add_md(
        "viz_learn",
        """
# Distinctions (read every line)

AUTHORIZED TOOL != AUTHORIZED GOAL

AUTHORIZED TOOL != AUTHORIZED USE OF TOOL

REQUEST != GRANT

OBSERVE != ALLOW

ALLOW != EXECUTION

SPLUNK != ENFORCEMENT

BASELINE != SAFE

DET-MCP-001 silence != SAFE

An LLM must not be treated as an authorization authority.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_ids",
        f"""
# Evidence identity (complete values)

**REPLAY** Phase 13C specimens. These are evidence identity for bound Studio tables, not the LIVE run you just launched.

Launch **LIVE** from [Attack Service]({ATTACK_URL}). Do not treat these UUIDs as your fresh execution.

BASELINE (defended / normal)

`{BASELINE}`

ATTACK (vulnerable / malicious)

`{ATTACK}`

RETEST (defended / malicious)

`{RETEST}`

Authoritative task `{TASK_ID}`

Task hash (Splunk OBSERVED)

{fingerprint_block(TASK_HASH)}

Instruction hash (13B local OBSERVED; Splunk PARTIALLY SUPPORTED via GOAL preview)

`{INSTRUCTION_HASH}`

Proposed-change fingerprint (13B local OBSERVED; Splunk PARTIALLY SUPPORTED via MCP preview)

`{PROPOSED_HASH}`

ATTACK/RETEST GOAL snapshot (Splunk OBSERVED)

{fingerprint_block(GOAL_SNAPSHOT)}

Do not upgrade PARTIALLY SUPPORTED Splunk evidence to OBSERVED.
""",
        title="EVIDENCE IDENTITY",
    )
    add_md(
        "viz_learn_planes",
        """
# Five evidence planes

1 **TASK** — server-owned contract. Example: summarize_lending_policy_options. Label: CONTROL EVIDENCE.

2 **INSTRUCTION** — untrusted_instruction. Classification, not malice. Hash / bounded preview. Label: CONTEXT.

3 **GOAL DECISION** — CTRL-GOAL-INTEGRITY-001 OBSERVE or DENY. This control is not the MCP tool PDP. Label: CONTROL EVIDENCE.

4 **TOOL AUTHORIZATION** — CTRL-MCP-001 ALLOW lookup_policy on A/B/C. Label: CONTROL EVIDENCE.

5 **EXECUTION** — mcp.started / completed. Handler counts are runtime authoritative. Label: EXECUTION EVIDENCE.

Do not collapse these into one prompt-injection event.
""",
        title="PLANES",
    )
    add_md(
        "viz_learn_vs",
        """
# Tool grant vs task grant

**MCP labs** taught: was lookup_policy granted?

**This lab** teaches: was lookup_policy used for the authorized task?

The same lookup_policy grant is required for summarize_lending_policy. Defense is not “block the tool.”

Statuses in TEXT: LIVE · OBSERVE · ALLOW · DENY · CONTEXT · HUNT · DETECTION · FUTURE · SIMULATED

Identity Studio / A2A transport / rug-pull / Phase 14 are later. Not this workshop.
""",
        title="MCP vs GOAL",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE · REPLAY specimen

**DEFENDED PROFILE** · mode BASELINE

- **Input / task:** `{TASK_ID}`
- **Profile:** defended
- **Instruction trust:** untrusted_instruction — label, not malice
- **Proposed action:** none / original task retained
- **Goal integrity:** **OBSERVE** · untrusted_instruction_cannot_redefine_task
- **Tool authorization:** **ALLOW** lookup_policy · CTRL-MCP-001
- **Effective action:** summarize_lending_policy
- **Execution:** in-task handler **1** · wrong-goal handler **0** (runtime authoritative)
- **Evidence run.id:** `{BASELINE}`

Task hash (Splunk OBSERVED)

{fingerprint_block(TASK_HASH)}

Conclusion: an untrusted instruction can be present without producing an unauthorized task expansion.

Do **not** label this SAFE, TRUSTED, APPROVED, or BENIGN.
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_goal",
        "ds_q_goal_b",
        "What Happened? Q-GOAL-INTEGRITY-AUTHORITY",
        cap_goal + " Expect OBSERVE cannot-redefine, summarize, MCP ALLOW. Not SAFE.",
        no_data=EMPTY_GOAL,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_b",
        "PLANE 4 Q-MCP-AUTHZ",
        cap_authz + " Expect hop-1 CTRL-MCP-001 ALLOW lookup_policy.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_baseline_exec",
        "ds_q_exec_b",
        "PLANE 5 Q-MCP-EXECUTED",
        cap_exec + " Expect hop-1 lookup_policy started. Handler evidence is runtime.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK · REPLAY specimen

Predict **before** you launch. Launching is not the investigation.

**WHY ARE WE DOING THIS?**

We want to test whether an untrusted instruction can redefine a server-owned task even when the tool itself remains granted. AUTHORIZED TOOL != AUTHORIZED GOAL.

**WHAT DOES THE ATTACKER CONTROL?**

The closed malicious instruction bytes. Not the task contract, not the MCP grant, not the profile.

**WHAT DOES THE SERVER OWN?**

The authorized task, CTRL-GOAL-INTEGRITY-001, CTRL-MCP-001, and whether the vulnerable overlay applies.

**WHAT DO YOU PREDICT?**

CTRL-GOAL-INTEGRITY-001 OBSERVE (labeled overlay). CTRL-MCP-001 ALLOW lookup_policy. Wrong-goal handler 1. MCP ALLOW does not mean the expanded goal was authorized.

**THEN:** Open Attack Service, launch LIVE ATTACK, copy the fresh run.id, wait until **EVIDENCE READY**, then hunt in Search. Studio tokens are not this launch.

[Open Attack Service (LIVE launch)]({ATTACK_URL})

**INTENTIONALLY VULNERABLE LAB PROFILE** · mode ATTACK

The table below is canonical REPLAY `{ATTACK}`.

- **Input / task:** SAME `{TASK_ID}`
- **Profile:** intentionally vulnerable lab profile
- **Instruction trust:** untrusted_instruction (untrusted != malicious as a class)
- **Proposed goal:** extract_full_policy
- **Goal integrity:** **OBSERVE** · lab-only overlay `vulnerable_profile_fail_open:untrusted_instruction_derived_task_authority`
- **Tool authorization:** **ALLOW** lookup_policy · CTRL-MCP-001
- **Effective action:** extract_full_policy
- **Execution:** wrong-goal handler **1** · in-task handler **0** (runtime authoritative)
- **Evidence run.id:** `{ATTACK}`

Task hash (Splunk OBSERVED)

{fingerprint_block(TASK_HASH)}

Conclusion: the tool was authorized. The expanded goal was not server-authorized. The vulnerable profile allowed the task expansion.

Do not claim the tool itself was compromised. Do not claim the MCP grant check failed. Do not claim Splunk allowed execution. Overlay reason is **LAB-ONLY**, not a production IOC.
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_goal",
        "ds_q_goal_a",
        "What Happened? Q-GOAL-INTEGRITY-AUTHORITY",
        cap_goal + " Expect OBSERVE overlay, extract_full_policy, MCP ALLOW.",
        no_data=EMPTY_GOAL,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_a",
        "PLANE 4 Q-MCP-AUTHZ",
        cap_authz + " Expect hop-1 ALLOW. MCP ALLOW is not goal authorization.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_attack_tool",
        "ds_q_tool_a",
        "PLANE 5 Q-MCP-TOOL",
        cap_tool + " Expect hop-1 mcp.started for lookup_policy.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_exec_a",
        "PLANE 5 Q-MCP-EXECUTED",
        cap_exec + " Expect has_started=1. mcp.started != SUCCESS of extract_full_policy.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Use **Investigate specimen** (defaults BASELINE). Five planes. Indexed structured fields only. No `_raw`. No full instruction. Hash + bounded preview.

{EMPTY_HUNT}

Statuses in TEXT: LIVE · OBSERVE · ALLOW · DENY · CONTEXT · HUNT
""",
        title="STEP 3 OBSERVE",
    )
    add_md(
        "viz_observe_planes",
        """
# Plane map

**TASK** — task.id, task.hash, provenance. What was the server-authorized task?

**INSTRUCTION** — instruction.trust, bounded GOAL preview. Untrusted != malicious.

**GOAL DECISION** — proposed, OBSERVE/DENY, reason. CTRL-GOAL-INTEGRITY-001 is not the MCP PDP.

**TOOL AUTHORIZATION** — CTRL-MCP-001, lookup_policy, scope, resource, ALLOW.

**EXECUTION** — mcp.started / completed. Runtime handler counts are authoritative. Do not infer successful execution merely from ALLOW.
""",
        title="PLANES",
    )
    add_table(
        "viz_observe_seq",
        "ds_observe_seq",
        "Indexed sequence (Investigate specimen) — five planes as columns",
        cap_seq,
        no_data=EMPTY_SEQ,
    )
    add_table(
        "viz_observe_goal",
        "ds_q_goal",
        "TASK + INSTRUCTION + GOAL DECISION + TOOL + EXECUTION — Q-GOAL-INTEGRITY-AUTHORITY",
        cap_goal,
        no_data=EMPTY_GOAL,
    )
    add_table(
        "viz_observe_authz",
        "ds_q_authz",
        "TOOL AUTHORIZATION — Q-MCP-AUTHZ",
        cap_authz,
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_observe_exec",
        "ds_q_executed",
        "EXECUTION — Q-MCP-EXECUTED",
        cap_exec,
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_hunt_md",
        f"""
# HUNT — guided investigation

Two paths. Path A is the default. Path B is an answer key, not a replacement.

**Path A — Try it yourself:** question, starter guidance, [Open Splunk Search]({SEARCH_URL}). Construct the hunt.

**Path B — Show solution (optional):** copyable SPL from existing Q-GOAL / Q-MCP hunts, bound REPLAY table, explanation, limitations. Open it only after Path A. It is an answer key, not policy.

Investigate specimen is canonical **REPLAY**. Fresh LIVE run.id comes from Attack Service Search handoff. Studio tokens are not auto-bound.

Do not search until Attack Service reports **EVIDENCE READY** (or you have measured searchable events). HEC success is not ready.

**Primary hunt:** Q-GOAL-INTEGRITY-AUTHORITY. Supporting: Q-MCP-WHO · Q-MCP-AUTHZ · Q-MCP-TOOL · Q-MCP-EXECUTED. No Q-GOAL-TASK. No DET-GOAL.

Five planes stay separate: TASK · INSTRUCTION · GOAL DECISION · TOOL AUTHORIZATION · EXECUTION.

Do **not** hunt a regex for AGENT NOTE. Overlay reason is a lab artifact, not a production IOC.

This tab is a **stacked notebook**: Path A, then optional hints, then Path B. Custom browser scripts are not used.

{TOOL_NOT_GOAL}

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table(
        "viz_hunt_goal",
        "ds_q_goal",
        "Q-GOAL-INTEGRITY-AUTHORITY (primary goal hunt)",
        cap_goal,
        no_data=EMPTY_GOAL,
    )
    add_table("viz_hunt_authz", "ds_q_authz", "Q-MCP-AUTHZ (tool grant only)", cap_authz, no_data=EMPTY_CONTROL)
    add_table("viz_hunt_tool", "ds_q_tool", "Q-MCP-TOOL (execution began?)", cap_tool, no_data=EMPTY_TOOL)
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED", cap_exec, no_data=EMPTY_TOOL)
    add_table("viz_hunt_who", "ds_q_who", "Q-MCP-WHO", cap_who, no_data=EMPTY_CONTROL)

    inv_doc = json.loads(INV_PATH.read_text(encoding="utf-8"))
    hunt_investigations = [
        row for row in inv_doc["investigations"] if row.get("studio_tab", "HUNT") == "HUNT"
    ]
    hunt_structure = [
        block("viz_hunt_md", 0, 0, FULL, 520),
        block("viz_hunt_goal", 0, 520, FULL, 260),
        block("viz_hunt_authz", 0, 780, HALF, 220),
        block("viz_hunt_tool", HALF, 780, HALF, 220),
        block("viz_hunt_exec", 0, 1000, HALF, 220),
        block("viz_hunt_who", HALF, 1000, HALF, 220),
    ]
    q_h, h1_h, h2_h, sol_h, tbl_h = 300, 160, 160, 520, 280
    y_cursor = 1240
    for index, inv in enumerate(hunt_investigations, start=1):
        ident = inv["investigation_id"]
        q_id = f"viz_i{index}_q"
        h1_id = f"viz_i{index}_h1"
        h2_id = f"viz_i{index}_h2"
        sol_id = f"viz_i{index}_sol"
        add_md(q_id, question_md(inv, index), title=f"I{index} question")
        add_md(h1_id, hint_md(inv, index, "hint_1"), title=f"I{index} hint 1")
        add_md(h2_id, hint_md(inv, index, "hint_2"), title=f"I{index} hint 2")
        add_md(sol_id, solution_md(inv, index), title=f"I{index} solution")
        q_y = y_cursor
        h1_y = q_y + q_h
        h2_y = h1_y + h1_h
        sol_y = h2_y + h2_h
        tbl_y = sol_y + sol_h
        hunt_structure.extend(
            [
                block(q_id, 0, q_y, FULL, q_h),
                block(h1_id, 0, h1_y, FULL, h1_h),
                block(h2_id, 0, h2_y, FULL, h2_h),
                block(sol_id, 0, sol_y, FULL, sol_h),
            ]
        )
        binds = TABLE_BIND[ident]
        if len(binds) == 1:
            ds, title, desc = binds[0]
            tbl_id = f"viz_i{index}_tbl"
            add_table(tbl_id, ds, title, desc, no_data=EMPTY_GOAL)
            hunt_structure.append(block(tbl_id, 0, tbl_y, FULL, tbl_h))
        else:
            width = FULL // len(binds)
            for col, (ds, title, desc) in enumerate(binds):
                tbl_id = f"viz_i{index}_tbl_{col}"
                add_table(tbl_id, ds, title, desc, no_data=EMPTY_GOAL)
                hunt_structure.append(block(tbl_id, col * width, tbl_y, width, tbl_h))
        y_cursor = tbl_y + tbl_h
    hunt_height = y_cursor + 40

    add_md(
        "viz_detect_md",
        """
# DETECTION ANALYZED — NO NEW GOAL DETECTOR

No notable. **No DET-GOAL.** This dashboard does **not** enable DET-MCP-001.

DET-MCP-001 detects **DENY then later mcp.started** for the same run.id + tool. It is **not** a goal-integrity detector.

LIVE Phase 13C runs (MEASURED):

- BASELINE = 0 because there was no tool DENY
- ATTACK = 0 because the path was MCP ALLOW — no tool DENY
- RETEST = 0 because goal DENY used extract_full_policy as gen_ai.tool.name, while hop-1 mcp.started is lookup_policy

0 rows is **CORRECT**. 0 rows != **SAFE**.

Right table: **SIMULATED** `| makeresults`. **NOT INDEXED.** Not a LIVE goal attack. Not OBSERVED runtime. Not DET-GOAL.
""",
        title="STEP 5 DETECT",
    )
    add_md(
        "viz_detect_class",
        """
# Classification (Phase 13D)

untrusted_instruction → **CONTEXT**

proposed action outside normal task → **HUNT**

goal DENY → **HUNT / defended control outcome**

vulnerable overlay reason → **REJECT AS PRODUCTION SIGNAL**

authorized tool + out-of-task effective action → **FUTURE RESEARCH / TELEMETRY DEPENDENT**

rare sequences → **FUTURE RESEARCH**

DENY then later tool start → **DET-MCP-001 / separate invariant**

AGENT NOTE regex → **REJECT AS PRODUCTION SIGNAL**

No DET-GOAL.
""",
        title="CONTEXT / HUNT / DETECTION / FUTURE",
    )
    add_table(
        "viz_detect_b",
        "ds_q_after_b",
        "DET-MCP-001 / Q-MCP-AFTER-DENY BASELINE",
        cap_after + " BASELINE 0: no tool DENY.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_a",
        "ds_q_after_a",
        "DET-MCP-001 / Q-MCP-AFTER-DENY ATTACK",
        cap_after + " ATTACK 0: MCP ALLOW path.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_r",
        "ds_q_after_r",
        "DET-MCP-001 / Q-MCP-AFTER-DENY RETEST",
        cap_after + " RETEST 0: goal DENY != lookup_policy start.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_sim",
        "ds_det_mcp_001_sim",
        "DET-MCP-001-POSITIVE-CONTROL (SIMULATED)",
        "Always one fixture row labeled SIMULATED. DENY then mcp.started. Do not treat as a live incident. Not DET-GOAL.",
        no_data="SIMULATED search returned no fixture row. Re-check DET-MCP-001-POSITIVE-CONTROL.spl (makeresults).",
    )
    add_md(
        "viz_detect_future",
        """
# FUTURE — NOT IMPLEMENTED

Behavioral analytics may later rank hunts:

- rare goal transitions
- novel proposed actions
- task → tool sequence deviation
- out-of-task tool-use patterns
- per-agent goal drift
- new instruction provenance
- unusual task-expansion frequency

Possible later tools: statistical SPL · Splunk MLTK · behavioral baselining · sequence analysis.

**ANOMALY != INCIDENT**

**ML MAY PRIORITIZE INVESTIGATION.**

**ML MUST NOT GRANT OR DENY AUTHORITY.**

Do not treat this panel as a detector. No MLTK model is running here.
""",
        title="FUTURE — NOT IMPLEMENTED",
    )
    add_md(
        "viz_detect_gaps",
        """
# WHAT WE CANNOT PROVE YET

- first-class effective_action
- first-class permitted-action id
- grant snapshot (allowed_tools) absent
- gen_ai.tool.call.id absent
- planner state absent
- broader action taxonomy absent

Do not invent these fields. Until a first-class effective action exists: **TELEMETRY GAP — QUERY NOT DEFENSIBLE** for a production out-of-task-use detector.
""",
        title="TELEMETRY GAPS",
    )

    add_md(
        "viz_defend",
        f"""
# DEFEND

Untrusted instruction may propose a change. It cannot redefine the server-owned task. Goal integrity evaluates expansion. Tool PDP remains CTRL-MCP-001.

```text
SERVER-OWNED TASK CONTRACT
      ↓
UNTRUSTED INSTRUCTION
      ↓
PROPOSED EXPANSION
      ↓
CTRL-GOAL-INTEGRITY-001
      ↓
DENY unauthorized_task_expansion
      ↓
RETAIN ORIGINAL TASK
      ↓
CTRL-MCP-001
      ↓
ALLOW lookup_policy
      ↓
EXECUTE summarize_lending_policy
```

Defense does NOT mean blocking lookup_policy.

Defense means preventing untrusted instructions from redefining the authorized task while still allowing legitimate use of the authorized tool.

Do **not** teach: block lookup_policy, sanitize every prompt, trust a scanner, let Splunk decide, let an LLM decide authorization, or that MCP solved the problem.

CTRL-GOAL-INTEGRITY-001 and CTRL-MCP-001 solve DIFFERENT security problems.

Launch **LIVE RETEST** from [Attack Service]({ATTACK_URL}) after you have investigated LIVE ATTACK.

Incorrect defenses (reject these):

- block every untrusted instruction
- deny lookup_policy
- trust the LLM to know the correct goal
- let Splunk authorize the task
- treat every goal change as malicious
- use prompt filtering as the authorization boundary

{TOOL_NOT_GOAL}
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_defend_evidence",
        """
# What actually changed the RETEST

SAME task. SAME malicious instruction. SAME proposed extract_full_policy. SAME lookup_policy grant.

DIFFERENT: CTRL-GOAL-INTEGRITY-001 DENY unauthorized_task_expansion. Effective action stays summarize_lending_policy. Wrong-goal handler 0. In-task handler 1.

Do not say MCP blocked the attack. MCP ALLOWED lookup_policy in BASELINE, ATTACK, and RETEST.
""",
        title="INV-002 / INV-006",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST · REPLAY specimen

**WHY RETEST?**

Same malicious instruction. Different server-owned profile. The question is whether the unauthorized goal is refused while the granted tool still runs for the original task.

**PREDICT:** CTRL-GOAL-INTEGRITY-001 DENY unauthorized_task_expansion. CTRL-MCP-001 still ALLOW lookup_policy. Wrong-goal handler 0. In-task handler 1. MCP ALLOW on RETEST does not mean the expanded goal was authorized.

**THEN:** Open Attack Service, launch LIVE RETEST, copy the fresh run.id, wait until **EVIDENCE READY**.

[Open Attack Service (LIVE RETEST)]({ATTACK_URL})

**DEFENDED PROFILE** · mode RETEST

Same malicious bytes. Different ExperimentContext (defended). MCP still ALLOWs lookup_policy. The table below is canonical REPLAY `{RETEST}`.

- **Input / task:** SAME `{TASK_ID}`
- **Profile:** defended
- **Instruction:** SAME malicious instruction (hash PARTIALLY SUPPORTED in Splunk)
- **Proposed goal:** SAME extract_full_policy
- **Goal integrity:** **DENY** unauthorized_task_expansion · CTRL-GOAL-INTEGRITY-001
- **Tool authorization:** **ALLOW** lookup_policy · CTRL-MCP-001
- **Effective action:** summarize_lending_policy
- **Execution:** wrong-goal handler **0** · in-task handler **1** (runtime authoritative)
- **Evidence run.id:** `{RETEST}`

Task hash (Splunk OBSERVED)

{fingerprint_block(TASK_HASH)}

Conclusion: the unauthorized goal did not execute. The authorized tool still executed for the original legitimate task.

Do not say MCP blocked the attack.

Do not use absence of a Splunk row as the sole proof.
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_goal",
        "ds_q_goal_r",
        "What Happened? Q-GOAL-INTEGRITY-AUTHORITY",
        cap_goal + " Expect DENY unauthorized_task_expansion, MCP ALLOW, summarize effective action.",
        no_data=EMPTY_GOAL,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_r",
        "PLANE 4 Q-MCP-AUTHZ",
        cap_authz + " Expect hop-1 ALLOW lookup_policy. Goal DENY is a different control.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_r",
        "PLANE 5 Q-MCP-TOOL",
        cap_tool + " Expect hop-1 mcp.started for lookup_policy (legitimate use).",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_exec_r",
        "PLANE 5 Q-MCP-EXECUTED",
        cap_exec + " lookup_policy started. Wrong-goal handler 0 is runtime authoritative.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

Primary visual proof of the lab.

**SAME TASK. SAME MALICIOUS INSTRUCTION. SAME PROPOSED GOAL. SAME AUTHORIZED TOOL.**

**DIFFERENT GOAL-INTEGRITY DECISION. DIFFERENT EFFECTIVE ACTION.**

ATTACK: MCP ALLOW + wrong-goal handler = 1

RETEST: MCP ALLOW + wrong-goal handler = 0 + legitimate handler = 1

Task hash (Splunk OBSERVED)

{fingerprint_block(TASK_HASH)}
""",
        title="BEFORE / AFTER",
    )
    add_md(
        "viz_cmp_card_base",
        f"""
# BASELINE

**REPLAY** · defended / normal

- **Profile:** defended
- **Input / fingerprint:** `{TASK_ID}`
- **Trust:** untrusted_instruction
- **Proposed action:** summarize_lending_policy
- **Security decision:** **OBSERVE** untrusted_instruction_cannot_redefine_task
- **Tool authorization:** **ALLOW** lookup_policy
- **Effective action:** summarize_lending_policy
- **Execution:** mcp.started observed
- **Handler count:** in-task **1** · wrong-goal **0**
- **Evidence run.id:** `{BASELINE}`

Do not label SAFE.
""",
        title="BASELINE",
    )
    add_md(
        "viz_cmp_card_atk",
        f"""
# ATTACK

**REPLAY** · **INTENTIONALLY VULNERABLE LAB PROFILE**

- **Profile:** vulnerable
- **Input / fingerprint:** SAME `{TASK_ID}`
- **Trust:** untrusted_instruction
- **Proposed action:** SAME extract_full_policy
- **Security decision:** **OBSERVE** overlay (lab-only)
- **Tool authorization:** **ALLOW** lookup_policy
- **Effective action:** **DIFFERENT** extract_full_policy
- **Execution:** mcp.started observed
- **Handler count:** in-task **0** · wrong-goal **1**
- **Evidence run.id:** `{ATTACK}`

MCP ALLOW + wrong-goal execution. Overlay is LAB-ONLY, not a production IOC.
""",
        title="ATTACK",
    )
    add_md(
        "viz_cmp_card_rt",
        f"""
# RETEST

**REPLAY** · defended / malicious instruction

- **Profile:** defended
- **Input / fingerprint:** SAME `{TASK_ID}`
- **Trust:** untrusted_instruction
- **Proposed action:** SAME extract_full_policy
- **Security decision:** **DIFFERENT DENY** unauthorized_task_expansion
- **Tool authorization:** **ALLOW** lookup_policy
- **Effective action:** **DIFFERENT** summarize_lending_policy
- **Execution:** mcp.started observed
- **Handler count:** in-task **1** · wrong-goal **0**
- **Evidence run.id:** `{RETEST}`

MCP ALLOW + wrong-goal 0 + legitimate handler 1. Do not say MCP blocked the attack.
""",
        title="RETEST",
    )
    add_table(
        "viz_cmp_base",
        "ds_q_goal_b",
        "BASELINE Q-GOAL-INTEGRITY-AUTHORITY",
        cap_goal + " Expect OBSERVE cannot-redefine.",
        no_data=EMPTY_GOAL,
    )
    add_table(
        "viz_cmp_atk",
        "ds_q_goal_a",
        "ATTACK Q-GOAL-INTEGRITY-AUTHORITY",
        cap_goal + " Expect SAME task hash as RETEST plus overlay OBSERVE.",
        no_data=EMPTY_GOAL,
    )
    add_table(
        "viz_cmp_rt",
        "ds_q_goal_r",
        "RETEST Q-GOAL-INTEGRITY-AUTHORITY",
        cap_goal + " Expect SAME task hash as ATTACK plus DENY.",
        no_data=EMPTY_GOAL,
    )

    add_md(
        "viz_prove",
        f"""
# PROVE

Evidence hierarchy. Splunk does not manufacture runtime truth.

## WHAT WE CAN PROVE

**YOU JUST LEARNED** — AUTHORIZED TOOL != AUTHORIZED GOAL. CTRL-GOAL-INTEGRITY-001 and CTRL-MCP-001 solve different problems. RETEST is not MCP DENY.

**THIS CONNECTS TO** — identity/delegation claims, which also cannot mint grants.

**NEXT** — Agent Identity / Delegation (LIVE). Then Confused Deputy (REPLAY) so you do not collapse deputy into identity.

- Authoritative task `{TASK_ID}` (same A/B/C). Task hash Splunk OBSERVED.
- Instruction trust `untrusted_instruction` (classification, not malice).
- ATTACK/RETEST proposed extract_full_policy. BASELINE retained the original task.
- CTRL-GOAL-INTEGRITY-001: BASELINE OBSERVE · ATTACK OBSERVE overlay · RETEST DENY.
- CTRL-MCP-001 ALLOW lookup_policy on A/B/C.
- Runtime handlers: ATTACK wrong-goal 1; RETEST wrong-goal 0 and in-task 1.
- DET-MCP-001 0/0/0 is CORRECT and is not SAFE.

## SUPPORTED

- same authoritative task
- same malicious instruction
- same proposed expansion
- lookup_policy was tool-authorized in both experiments
- vulnerable run executed the wrong goal
- defended run did not execute the wrong goal
- defended run executed the original task

## CORROBORATED

- complete indexed sequence agrees with runtime evidence

## NOT PROVEN

- every prompt injection is prevented
- lookup_policy is universally safe
- the instruction was malicious merely because it was untrusted
- that the SIEM stopped execution
- that MCP stopped the RETEST attack

## INCORRECT

- MCP ALLOW means the goal was authorized
- tool authorization and task authorization are the same thing
- goal DENY means lookup_policy was denied
- Splunk is the enforcement point

## WHAT WE CANNOT PROVE

- Instruction hash / proposed-change hash as first-class Splunk fields (PARTIALLY SUPPORTED via preview).
- First-class effective_action / permitted-action id.
- That Splunk enforced RETEST (Splunk does not enforce).
- That MCP blocked the attack (MCP ALLOWED lookup_policy).

## AUTHORITATIVE EVIDENCE

Runtime handler counts. Local pack / events.jsonl. Completeness = local count vs dc(_raw).

## CORROBORATIVE EVIDENCE

Q-GOAL-INTEGRITY-AUTHORITY. Q-MCP hunts. Studio tables. Zero rows follow no-data semantics.

## KNOWLEDGE CHECK

Answer from evidence on this tab.

1. What was the authoritative task?
2. Where did task authority originate?
3. What was the instruction trust classification?
4. Does untrusted_instruction mean malicious?
5. What action did the instruction propose?
6. Was that proposed action automatically authorized?
7. What did CTRL-GOAL-INTEGRITY-001 decide?
8. Is CTRL-GOAL-INTEGRITY-001 the MCP tool PDP?
9. What did CTRL-MCP-001 decide?
10. Was lookup_policy authorized in ATTACK?
11. Was lookup_policy authorized in RETEST?
12. Why does that not make ATTACK and RETEST equivalent?
13. What actually executed in ATTACK?
14. What actually executed in RETEST?
15. What is the authoritative proof the wrong goal did not execute?
16. Why is DET-MCP-001 0 for RETEST?
17. Why does DET-MCP-001 silence not mean SAFE?
18. Why is the overlay reason not a production IOC?
19. Why should a SOC reconstruct task + goal + tool + execution?
20. What does AUTHORIZED TOOL != AUTHORIZED USE OF TOOL mean?

## LIMITATIONS

LIVE Attack Service launches are OBSERVED/MEASURED with new run.ids. Studio tables are **REPLAY**. DETECT SIMULATED table is **SIMULATED**.

Canonical REPLAY: BASELINE `{BASELINE}` · ATTACK `{ATTACK}` · RETEST `{RETEST}`.

Task fingerprint `{TASK_HASH}`

No DET-GOAL. Schema 1.9.0. Identity / Delegation is the next LIVE lab. Do not start Phase 15E. No A2A. No rug-pull.
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_goal",
        "ds_q_goal",
        "What Happened? Q-GOAL-INTEGRITY-AUTHORITY (Investigate specimen)",
        cap_goal,
        no_data=EMPTY_GOAL,
    )

    definition = {
        "title": "Goal / Instruction Integrity",
        "description": (
            "WS-GOAL-INTEGRITY. LIVE vs REPLAY Goal / Instruction Integrity workshop. "
            "No DET-GOAL. Splunk does not ALLOW or DENY a tool or a task."
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
                    "defaultValue": BASELINE,
                    "items": [
                        {"label": "Baseline — defended / normal", "value": BASELINE},
                        {"label": "Attack — vulnerable / malicious", "value": ATTACK},
                        {"label": "Retest — defended / malicious", "value": RETEST},
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
                        block("viz_header", 0, 0, FULL, 200),
                        block("viz_question", 0, 200, HALF, 180),
                        block("viz_learn_flow", HALF, 200, HALF, 420),
                        block("viz_learn", 0, 380, HALF, 420),
                        block("viz_learn_ids", 0, 800, FULL, 560),
                        block("viz_learn_planes", 0, 1360, HALF, 400),
                        block("viz_learn_vs", HALF, 1360, HALF, 400),
                    ],
                    1780,
                ),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 620),
                        block("viz_baseline_goal", 0, 620, FULL, 280),
                        block("viz_baseline_authz", 0, 900, HALF, 260),
                        block("viz_baseline_exec", HALF, 900, HALF, 260),
                    ],
                    1180,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 720),
                        block("viz_attack_goal", 0, 720, FULL, 280),
                        block("viz_attack_authz", 0, 1000, HALF, 260),
                        block("viz_attack_tool", HALF, 1000, HALF, 260),
                        block("viz_attack_exec", 0, 1260, FULL, 260),
                    ],
                    1540,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, HALF, 280),
                        block("viz_observe_planes", HALF, 0, HALF, 280),
                        block("viz_observe_seq", 0, 280, FULL, 280),
                        block("viz_observe_goal", 0, 560, FULL, 280),
                        block("viz_observe_authz", 0, 840, HALF, 260),
                        block("viz_observe_exec", HALF, 840, HALF, 260),
                    ],
                    1120,
                ),
                "layout_hunt": layout(hunt_structure, hunt_height),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, HALF, 420),
                        block("viz_detect_class", HALF, 0, HALF, 420),
                        block("viz_detect_b", 0, 420, THIRD, 280),
                        block("viz_detect_a", THIRD, 420, THIRD, 280),
                        block("viz_detect_r", THIRD * 2, 420, THIRD, 280),
                        block("viz_detect_sim", 0, 700, HALF, 280),
                        block("viz_detect_future", HALF, 700, HALF, 280),
                        block("viz_detect_gaps", 0, 980, FULL, 280),
                    ],
                    1280,
                ),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 720),
                        block("viz_defend_evidence", 0, 720, FULL, 260),
                    ],
                    1000,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 720),
                        block("viz_retest_goal", 0, 720, FULL, 280),
                        block("viz_retest_authz", 0, 1000, HALF, 260),
                        block("viz_retest_tool", HALF, 1000, HALF, 260),
                        block("viz_retest_exec", 0, 1260, FULL, 260),
                    ],
                    1540,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 300),
                        block("viz_cmp_card_base", 0, 300, THIRD, 880),
                        block("viz_cmp_card_atk", THIRD, 300, THIRD, 880),
                        block("viz_cmp_card_rt", THIRD * 2, 300, THIRD, 880),
                        block("viz_cmp_base", 0, 1180, THIRD, 280),
                        block("viz_cmp_atk", THIRD, 1180, THIRD, 280),
                        block("viz_cmp_rt", THIRD * 2, 1180, THIRD, 280),
                    ],
                    1480,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 1500),
                        block("viz_prove_goal", 0, 1500, FULL, 280),
                    ],
                    1800,
                ),
            },
        },
        "applicationProperties": {
            "collapseNavigation": False,
            "downsampleVisualizations": False,
        },
    }
    _ = (TEAL, SECONDARY, BORDER, EMPTY_EVENT)
    return definition


def write_xml(definition: dict) -> None:
    payload = json.dumps(definition, indent=2, ensure_ascii=False)
    if "]]>" in payload:
        raise ValueError("definition contains CDATA terminator")
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<dashboard version="2" theme="light">\n'
        "  <label>Goal / Instruction Integrity</label>\n"
        "  <description>LIVE vs REPLAY Goal / Instruction Integrity. LAB-AGENT-GOAL-INTEGRITY-001. Splunk does not ALLOW or DENY.</description>\n"
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
