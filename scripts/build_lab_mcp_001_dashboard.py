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
INV_PATH = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "investigations.json"
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

SEARCH_URL = "/en-US/app/search/search"
ATTACK_URL = "/app/agentsec/open_attack?path=/labs/LAB-MCP-001"
EMPTY_HUNT = (
    "Evidence to investigate defaults to the BASELINE specimen so this page is not an error "
    "state. Custom run.id is available from Search. Zero rows means "
    "no matching indexed events for that id. Zero rows is not DENY and is not "
    "proof the handler never ran."
)
ALLOW_NOT_EXEC = (
    "ALLOW is the control decision. Runtime handler count is authoritative for "
    "execution. Indexed `mcp.started` (`executed=true` on that event) corroborates "
    "that the handler began on a complete copy. Do not read ALLOW as execution. "
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

def bind_literal(spl: str, run_id: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError("expected __RUN_ID__ in query")
    return spl.replace("__RUN_ID__", f'"{run_id}"')


SPL_TEACHING = {
    "Q-MCP-WHO": (
        "- **Why control.decision?** Identity of who requested which tool is on the authorization event.\n"
        "- **Why not session.id?** AgentSec correlates with run.id.\n"
        "- **Why collapse mvindex(mvdedup(...),0)?** JSON body and OTLP attributes duplicate scalars."
    ),
    "Q-MCP-AUTHZ": (
        "- **Why event.name=agentsec.control.decision?** That is the PDP copy.\n"
        "- **Why executed is false on ALLOW?** That field is the control event, not handler start.\n"
        "- Splunk did **not** evaluate CTRL-MCP-001."
    ),
    "Q-MCP-TOOL": (
        "- **Why mcp.started only?** That indexed event corroborates that the handler began on a complete copy. Runtime handler count is authoritative.\n"
        "- **Why zero rows are not DENY?** Incomplete export also yields zero rows."
    ),
    "Q-MCP-EXECUTED": (
        "- **Why has_started?** It is derived from mcp.started in this copy.\n"
        "- **Why control executed stays false?** Do not read it as handler execution.\n"
        "- Runtime handler count remains authoritative for non-execution."
    ),
    "Q-MCP-AFTER-DENY": (
        "- **Why this hunt?** It asks whether mcp.started followed DENY for the same run/tool.\n"
        "- **Why zero rows are not a detector?** No notable. Completeness first.\n"
        "- DET-MCP-001 is the disabled saved search for the same invariant. It is not an enabled operational detection."
    ),
}

TABLE_BIND = {
    "MCP-I1-FIND-THE-RUN": [
        (
            "ds_q_who",
            "Q-MCP-WHO (REPLAY specimen)",
            "Path B identity row. Fresh LIVE run.id is Search, not this table.",
        )
    ],
    "MCP-I2-FIND-THE-REQUEST": [
        (
            "ds_q_who",
            "Q-MCP-WHO tool identity (REPLAY)",
            "Requested tool. Not a grant.",
        ),
        (
            "ds_q_params",
            "Q-MCP-PARAMS (REPLAY)",
            "Preview + hash only.",
        ),
        (
            "ds_q_scope",
            "Q-MCP-SCOPE (REPLAY)",
            "requested_scope vs coded allowed_scope.",
        ),
    ],
    "MCP-I3-AUTHORIZATION-DECISION": [
        (
            "ds_q_authz",
            "Q-MCP-AUTHZ (REPLAY specimen)",
            "Control.id, decision, reason. Splunk did not make this decision.",
        )
    ],
    "MCP-I4-DID-HANDLER-START": [
        (
            "ds_q_executed",
            "Q-MCP-EXECUTED (REPLAY specimen)",
            "has_started is execution evidence in this copy. Empty is not independently prevented.",
        ),
        (
            "ds_q_tool",
            "Q-MCP-TOOL (REPLAY)",
            "mcp.started rows only.",
        ),
        (
            "ds_q_result",
            "Q-MCP-RESULT (REPLAY)",
            "Completed/failed result metadata. Empty is not trusted.",
        ),
        (
            "ds_q_result_trust",
            "Q-MCP-RESULT-TRUST (REPLAY)",
            "Expect untrusted_data when a result exists.",
        ),
    ],
    "MCP-I5-WHAT-CAN-YOU-PROVE": [
        (
            "ds_q_after_deny",
            "Q-MCP-AFTER-DENY (indexed REPLAY)",
            "Zero rows on a complete DENY copy is corroboration, not a shipped detector.",
        )
    ],
    "MCP-I6-ATTACK-VS-RETEST": [
        (
            "ds_q_authz_attack",
            "ATTACK Q-MCP-AUTHZ (canonical REPLAY)",
            "LIVE ATTACK is the vulnerable experiment. This table is REPLAY.",
        ),
        (
            "ds_q_authz_retest",
            "RETEST Q-MCP-AUTHZ (canonical REPLAY)",
            "Path B answer key. Fresh RETEST run.id is Search.",
        ),
    ],
}


def question_md(inv: dict, number: int, spl_file: str) -> str:
    del spl_file
    return f"""
# Investigation {number} — {inv["title"]}

**QUESTION**

{inv["security_question"]}

**WHAT AM I TRYING TO PROVE?**

{inv["learning_objective"]}

**YOUR TASK (Path A — try it yourself)**

{inv["starter_guidance"]}

1. Copy your LIVE run.id from the Attack Service Workbench, or use a recorded REPLAY example from the INVESTIGATE tab.
2. [Open Splunk Search]({SEARCH_URL})
3. Constrain `index=agentsec_telemetry sourcetype=otel:agentic:json`.
4. Filter quoted `agentsec.run.id`. Execute. Read the fields yourself.

The Workbench's **Investigate evidence** link fills the LIVE box on the INVESTIGATE tab for you. Splunk Search is a separate app, so here you enter the run.id yourself.

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


def solution_md(inv: dict, number: int, spl_file: str) -> str:
    spl = load_spl(spl_file)
    bound = spl.replace("__RUN_ID__", '"$run_id$"')
    hunt = inv["related_hunt"]
    teach = SPL_TEACHING[hunt]
    nxt = inv["next_investigation"] or "PROVE — classify what you can actually conclude."
    return f"""
# Solution — Investigation {number} {inv["title"]}

This is **Path B — show solution**. Open it only after you tried Path A in Search. It is an answer key, not policy. Splunk does not enforce. Path A remains Search with your LIVE run.id.

**SOLUTION SPL** (`{hunt}`)

Copy this into Search. Replace `$run_id$` with the LIVE UUID, or leave the token for Evidence to investigate REPLAY.

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


def layout(structure: list[dict], height: int, display: str = "auto-scale") -> dict:
    return {
        "type": "grid",
        "options": {
            "backgroundColor": BG,
            "display": display,
            "gutterSize": 8,
            "width": CANVAS_W,
            "height": height,
        },
        "structure": structure,
    }


def observe_sequence_spl(token: str) -> str:
    """Same control+mcp filter as Q-MCP-EXECUTED, without collapsing to one row."""
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"={bound_run(token)} ("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
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


#: What the LIVE run.id box holds until the learner replaces it.
#:
#: It cannot be empty. Dashboard Studio treats an empty token as unset, and a
#: search that references an unset token does not run at all: the panel shows
#: "Set token value to render visualization". Splunk documents this (Defaults
#: for tokens), and it was measured on the deployed dashboard twice: an empty
#: input default left every notebook panel blank (55 messages), and adding the
#: documented defaults.tokens stanza with an empty value changed nothing (60).
#: The notebook promises that a learner who has not run anything yet reads the
#: canonical REPLAY specimen, so the "no live run" state needs a real value.
#: This constant is that value. It is read by the input default AND by the SPL
#: below, so the two cannot drift. It is not a run.id and matches no event.
LIVE_RUN_NONE = "none"
INVESTIGATE_GAP = 8  # px between stacked INVESTIGATE panels
JOURNEY_H = 100  # layout units; MEASURED (content needs ~75 at 1920/1024/200%)
START_H = 560  # layout units; sized for the narrowest measured case (1024 px / 200% zoom)
INPUT_H = 100  # px; one in-canvas dropdown

#: Learner-facing names for the two evidence-source controls.
#:
#: The old title "Investigate specimen" and the options "Attack" / "Retest" read
#: like actions, and a human walkthrough showed a learner could reasonably
#: believe choosing "Attack" launches one. These controls choose which
#: evidence to READ. LIVE evidence is the learner's own run; REPLAY evidence is
#: a recorded specimen. The words LIVE and REPLAY stay in both titles because
#: the difference is the whole point.
#:
#: P0.1: Dashboard Studio truncates a control title at about 28 characters at
#: 1024 and 1920 px ("REPLAY evidence to read (rec..."), which cut off the very
#: words that said "recorded, not your run". The titles and option labels are
#: now short enough to survive, and the sentence that says which evidence is
#: CURRENT lives in the CURRENT EVIDENCE table, which Studio does not truncate.
SELECTOR_TITLE = "REPLAY example"
LIVE_TITLE = "LIVE: your run.id"
SELECTOR_LABELS = {
    "baseline": "Baseline example",
    "attack": "Attack example",
    "retest": "Retest example",
}
#: Hard ceiling for any control title or option label (characters). Pinned by a test.
CONTROL_TEXT_MAX = 24


#: The five learner phases of the P1 information architecture. Eight instructional
#: steps sit inside them (BASELINE, PREDICT, ATTACK, INVESTIGATE, DEFEND, RETEST,
#: COMPARE, EXPLAIN). OBSERVE is not a destination: ATTACK COMPLETE / EVIDENCE
#: READY is a state transition inside ATTACK.
PHASES = (
    ("UNDERSTAND", "baseline"),
    ("TEST", "predict, attack"),
    ("INVESTIGATE", "read the evidence"),
    ("IMPROVE", "defend, retest"),
    ("PROVE", "compare, explain"),
)


def phase_markdown(here: str, where: str) -> str:
    """A five-phase map with the current phase marked.

    Dashboard Studio cannot hold progress state across the AgentSec web app and
    Splunk (different origins, and Studio has no supported storage), so this is a
    surface-local MAP, not a tracker. The marker is a word and a symbol, not a
    colour, and nothing here implies a step passed or failed.
    """
    parts = []
    for name, detail in PHASES:
        parts.append(f"▶ **{name} (you are here)** ◀" if name == here else name)
        _ = detail
    if here == "START":
        parts.insert(0, "▶ **START (you are here)** ◀")
    strip = "  ›  ".join(parts)
    return f"""{strip}

{where} Your place is kept in the guided lab tab. This map is not saved progress.
"""


def notebook_base(event_filter: str = "") -> str:
    """Base search for the Investigation Notebook, bound to the selected run.

    The learner may arrive with a fresh LIVE run.id from the workbench, or with
    nothing typed and a REPLAY specimen chosen in the dropdown. Rather than add
    a third input, both existing tokens are offered to the index and the newer
    one wins. While live_run_id still holds LIVE_RUN_NONE it matches no event, so
    the OR collapses to the specimen on its own.
    """
    extra = f" {event_filter}" if event_filter else ""
    return (
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
        f' ("agentsec.run.id"="$live_run_id$" OR "agentsec.run.id"="$run_id$"){extra}\n'
        "| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)\n"
        f'| eval selected_run=if("$live_run_id$"=="{LIVE_RUN_NONE}","$run_id$","$live_run_id$")\n'
        "| where run_id==selected_run"
    )


NB_EXECUTION_EVENTS = (
    '("event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed'
    ' OR "event.name"=agentsec.mcp.failed OR "event.name"=agentsec.pipeline.stopped)'
)

#: Slot in a notebook cell body where the executed SPL is printed.
SPL_SLOT = "<<SPL>>"


def with_spls(body: str, spls: list[str]) -> str:
    """with_spl() for a cell that prints more than one query, in slot order."""
    for spl in spls:
        if SPL_SLOT not in body:
            raise ValueError("fewer SPL slots than queries")
        body = body.replace(SPL_SLOT, spl, 1)
    if SPL_SLOT in body:
        raise ValueError("an SPL slot was left unfilled")
    return body


def with_spl(body: str, spl: str) -> str:
    """Print the executed query inside the cell that runs it.

    The notebook tells the learner "this is the SPL the table below runs". That
    claim only holds if there is one string, not a hand-copied summary beside a
    real query. A summary drifts the moment either side is edited, and the
    first version of this notebook did exactly that: the printed Cell 4 query
    omitted the eval clauses, so pasting it into Search returned the right rows
    with four empty columns.

    Studio substitutes $live_run_id$ and $run_id$ in markdown the same way it
    substitutes them in a search, so the text the learner copies is the text
    that ran, with the same run selected.
    """
    if SPL_SLOT not in body:
        raise ValueError("notebook cell body has no SPL slot")
    return body.replace(SPL_SLOT, spl)


def nb_dropdown(title: str, token: str, items: list[tuple[str, str]]) -> dict:
    """An in-canvas answer control. "none" is the closed state, never an answer."""
    return {
        "type": "input.dropdown",
        "title": title,
        "options": {
            "token": token,
            "defaultValue": LIVE_RUN_NONE,
            "items": [{"label": "Choose an answer", "value": LIVE_RUN_NONE}]
            + [{"label": label, "value": value} for label, value in items],
        },
    }


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
    q_authz_b = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), BASELINE_ID)
    q_authz_a = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), ATTACK_ID)
    q_authz_r = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), RETEST_ID)
    q_tool_b = bind_literal(load_spl("Q-MCP-TOOL.spl"), BASELINE_ID)
    q_tool_a = bind_literal(load_spl("Q-MCP-TOOL.spl"), ATTACK_ID)
    q_tool_r = bind_literal(load_spl("Q-MCP-TOOL.spl"), RETEST_ID)
    q_exec_b = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), BASELINE_ID)
    q_exec_a = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), ATTACK_ID)
    q_exec_r = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), RETEST_ID)

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
# Tool Authorization

A tool request is not a tool grant. Schema **1.9.0**. CTRL-MCP-001 is the PDP.

**Tool** = named operation (`lookup_policy`, `lookup_customer_tier`) plus arguments. **MCP here** = in-process JSON-RPC `tools/call`, not a product catalog UI.

**Request** = `tool`, `requested_scope`, `arguments`, `user_id`. **Grant** = server-owned `allowed_tools` / `allowed_scopes`. An LLM cannot grant itself. **Resource** (`policy_id`) is checked only after tool ALLOW.

Authorization runs at **CTRL-MCP-001 before the handler**. AcmeBank `POST /mcp/invoke` enforces. Splunk observes the copy and does **not** ALLOW or DENY.

## Trust path (authorization boundary)

```text
USER / AGENT
        │
TOOL REQUEST  (tool, requested_scope, arguments)
        │
CTRL-MCP-001  ← authorization boundary
        │
ALLOW / DENY / ERROR
        │
HANDLER START (only after ALLOW) → COMPLETE / FAIL
        │
TELEMETRY → SPLUNK (observe only)
```

## What you should be able to say

- REQUEST != GRANT. ALLOW != EXECUTION (`mcp.started` is handler start).
- DENY != automatic proof of non-execution. Runtime `handler_invoke_count` is authoritative.
- Missing Splunk `mcp.started` is corroborative only on a complete copy.
- ATTACK != ALERT. 0 DET-MCP-001 rows != SAFE. Splunk != enforcement.

{ALLOW_NOT_EXEC}

LEARN → PREDICT → LAUNCH → INVESTIGATE (Path A or Path B) → DEFEND → LIVE RETEST → COMPARE → PROVE

## Evidence identity

Canonical REPLAY (HUNT token). Fresh LIVE ids come from Attack Service. `lookup_customer_tier` is not malware; the issue is unauthorized invocation.

- **BASELINE** `{BASELINE_ID}` — granted `lookup_policy`, ALLOW, handler=1
- **ATTACK** `{ATTACK_ID}` — ungranted `lookup_customer_tier`, labeled fail-open ALLOW, handler=1
- **RETEST** `{RETEST_ID}` — same ungranted request, DENY, handler=0
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

Do not imply ALLOW itself proves execution. Runtime handler count is authoritative. Indexed `mcp.started` corroborates a begun handler on a complete copy.
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

Predict **before** you launch. Launching is not the investigation.

**ATTACK OBJECTIVE**

Send the catalog ungranted `lookup_customer_tier` / `customer:read` request and see whether CTRL-MCP-001 runs before the handler.

**WHY ARE WE DOING THIS?**

REQUEST != GRANT. An LLM asking for a tool cannot authorize itself.

**WHAT IS THE ATTACKER TRYING TO INFLUENCE?**

The tool name, requested_scope, and arguments — treated as if they were a grant.

**WHAT SHOULD THE DEFENSE DO?**

This ATTACK specimen is the labeled vulnerable experiment. CTRL-MCP-001 fail-opens. The defense you will enable next is RETEST (server-owned `profile=defended`), not Splunk.

**WHAT DO YOU PREDICT?**

Will the request be ALLOW or DENY? Will `mcp.started` appear? If denied, what evidence should exist? Does missing `mcp.started` alone prove prevention?

**WHAT EVIDENCE SHOULD APPEAR?**

LIVE ATTACK: ALLOW with a fail-open reason, real `mcp.started`, `handler_invoke_count=1`, `testbed.mode=ATTACK`. ALLOW is not execution.

Splunk does **not** send this. Studio does **not** POST. Open Attack Service, launch ATTACK, copy LIVE RUN, wait until evidence is searchable, then HUNT Path A.

[Open Attack Service (LIVE launch)]({ATTACK_URL})

**Validated vulnerable REPLAY:** `{ATTACK_ID}`. Choose **Attack example** in the **REPLAY example** selector to read that recorded copy. Choosing it reads recorded evidence; it does not run an experiment.

**Next:** HUNT Path A on the fresh ATTACK `run.id`, then DEFEND, then Launch RETEST (LIVE).
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_what_id",
        "ds_what_attack_id",
        "What Happened? identity (indexed fields)",
        cap_what_id
        + " Read tool, profile and mode to establish which experiment this copy is,"
        " before you judge anything about its outcome.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_what_dec",
        "ds_what_attack_dec",
        "What Happened? decision (indexed fields)",
        cap_what_dec
        + " Read decision and execution_state as two separate answers. Neither one"
        " is evidence for the other.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_attack",
        "Q-MCP-AUTHZ",
        cap_authz
        + " Compare requested_scope against allowed_scope, then read decision."
        " Does the decision follow from the scopes, and what does that tell you"
        " about this profile?",
        no_data=empty_control,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_executed_attack",
        "Q-MCP-EXECUTED",
        cap_executed
        + " has_started answers whether the handler began. Answer it from this"
        " table, not from what the control decided.",
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
        "viz_hunt_intro",
        f"""
# HUNT — guided investigation

Two paths. Path A is the default. Path B is an answer key, not a replacement.

**Path A — Try it yourself:** question, starter guidance, [Open Splunk Search]({SEARCH_URL}). Construct the hunt.

**Path B — Show solution (optional):** copyable SPL from existing Q-MCP hunts, bound REPLAY table, explanation, limitations. Open it only after Path A. It is an answer key, not policy.

Evidence to investigate is canonical **REPLAY**. Fresh LIVE run.id comes from Attack Service Search handoff. Studio tokens are not auto-bound.

Do not search until Attack Service reports **EVIDENCE READY** (or you have measured searchable events). HEC success is not ready.

This tab is a **stacked notebook**: Path A, then optional hints, then Path B. Custom browser scripts are not used.

{ALLOW_NOT_EXEC}
""",
        title="STEP 4 HUNT",
    )

    inv_doc = json.loads(INV_PATH.read_text(encoding="utf-8"))
    hunt_investigations = [
        row for row in inv_doc["investigations"] if row.get("studio_tab", "HUNT") == "HUNT"
    ]
    hunt_files = {
        "Q-MCP-WHO": "Q-MCP-WHO.spl",
        "Q-MCP-AUTHZ": "Q-MCP-AUTHZ.spl",
        "Q-MCP-TOOL": "Q-MCP-TOOL.spl",
        "Q-MCP-EXECUTED": "Q-MCP-EXECUTED.spl",
        "Q-MCP-AFTER-DENY": "Q-MCP-AFTER-DENY.spl",
    }
    hunt_structure = [
        block("viz_hunt_intro", 0, 0, FULL, 280),
    ]
    q_h, h1_h, h2_h, sol_h, tbl_h = 300, 160, 160, 500, 300
    y_cursor = 288
    for index, inv in enumerate(hunt_investigations, start=1):
        ident = inv["investigation_id"]
        hunt_id = inv["related_hunt"]
        spl_file = hunt_files[hunt_id]
        q_id = f"viz_i{index}_q"
        h1_id = f"viz_i{index}_h1"
        h2_id = f"viz_i{index}_h2"
        sol_id = f"viz_i{index}_sol"
        add_md(q_id, question_md(inv, index, spl_file), title=f"I{index} question")
        add_md(h1_id, hint_md(inv, index, "hint_1"), title=f"I{index} hint 1")
        add_md(h2_id, hint_md(inv, index, "hint_2"), title=f"I{index} hint 2")
        add_md(sol_id, solution_md(inv, index, spl_file), title=f"I{index} solution")
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
            add_table(tbl_id, ds, title, desc, no_data=EMPTY_HUNT)
            hunt_structure.append(block(tbl_id, 0, tbl_y, FULL, tbl_h))
        else:
            width = FULL // len(binds)
            for col, (ds, title, desc) in enumerate(binds):
                tbl_id = f"viz_i{index}_tbl_{col}"
                add_table(tbl_id, ds, title, desc, no_data=EMPTY_HUNT)
                hunt_structure.append(block(tbl_id, col * width, tbl_y, width, tbl_h))
        y_cursor = tbl_y + tbl_h

    add_md(
        "viz_detect_md",
        """
# DETECT — investigation hunt and one disabled saved search

No notable event. No ES notable. No automatic remediation.

**Invariant:** if CTRL-MCP-001 returns DENY for a run/tool, no later `mcp.started` may occur for that same run/tool (`sequence` greater than the DENY).

## HUNT vs DETECTION

- **HUNT** (`Q-MCP-AFTER-DENY` on Hunt run.id): asks whether the violation occurred in this copy. Left table. Validated LIVE specimens: **0** rows. Zero rows is not independent proof the handler never ran.
- **DETECTION** (`DET-MCP-001`, saved search `AgentSec - MCP Execution After Authorization Deny`): the same invariant, packaged **disabled** with scheduling off. It is not continuously checking while disabled. Severity **HIGH** on the predicate means authorization already denied and execution nevertheless began. This dashboard does **not** enable it. It did **not** fire on the validated LIVE runs.

DENY alone is not an alert. ALLOW (including labeled fail-open) is not this detection. `mcp.failed` after ALLOW is execution then error, not DENY-then-start. ERROR is not DENY. Splunk detects a copy of a violation; it does not enforce authorization.

**ATTACK != ALERT.** A successful LIVE ATTACK on the vulnerable profile is fail-open ALLOW. DET-MCP-001 stays silent. **HUNT != DETECTION.** **CONTEXT != INCIDENT.** **0 detection rows != SAFE.**

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

**Control:** CTRL-MCP-001 (the tool PDP). Type `mcp_allowlist`.

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

**Action:** Open Attack Service, read the RETEST prediction, then Launch RETEST (LIVE) with the same request bytes.

[Open Attack Service RETEST](/app/agentsec/open_attack?path=/labs/LAB-MCP-001)

**SPL this step:** none. Re-read HUNT. **Next:** LIVE RETEST the same unauthorized request on the defended experiment.
""",
        title="STEP 6 DEFEND",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

Predict **before** you launch. RETEST uses the **same** `lookup_customer_tier` / `customer:read` / `cust-001` request and a **different** server-owned defense.

[Open Attack Service (Launch RETEST LIVE)]({ATTACK_URL})

**Expected:** DENY `tool_not_granted`. Control `attempted=false`, `executed=false`, `outcome=prevented`. Runtime handler count **0** is authoritative. Indexed `mcp.started` absence corroborates a complete copy; it is not independent prevention.

Validated REPLAY: `{RETEST_ID}`. Fresh LIVE ids are not this UUID.

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
        cap_what_id
        + " Read tool, profile and mode. Compare them with the ATTACK row beside"
        " this one: which fields changed, and which stayed the same?",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_what_dec",
        "ds_what_retest_dec",
        "What Happened? decision (indexed fields)",
        cap_what_dec
        + " Read decision, reason and execution_state, then compare each one"
        " against the ATTACK row. The request did not change between them.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_retest",
        "Q-MCP-AUTHZ",
        cap_authz
        + " The scopes are the same as the ATTACK row. Read decision and reason,"
        " and work out what else must have differed.",
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
        cap_executed
        + " Read has_started and execution_state. If the handler did not begin,"
        " what is this copy able to prove on its own, and what still needs the"
        " runtime handler count?",
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
2. **Local evidence.** The local evidence pack for that run (event sequence and event contract).
3. **OTLP export.** `export.json` — telemetry was emitted. `otlp.ok` is not Splunk success. Packs keep `splunk.verified=false` until a search ran.
4. **Splunk indexed.** A copy arrived. Completeness is local count vs `dc(_raw)` for that `run.id`.
5. **SPL query result.** Analytical interpretation of that copy (Q-MCP-*). Zero rows follow Phase 3C no-data semantics.

States: COMPLETE / PARTIAL / FAILED / NOT VERIFIED per layer.

{RUNTIME_AUTH}

## Knowledge check (not scored)

Questions on this tab. Sample:

- Why is `lookup_customer_tier` DENY instead of ERROR?
- Why is an unknown tool ERROR?
- Does ALLOW prove the tool executed?
- What proves the handler actually began?
- Why is `mcp.failed` not prevention?
- Why can't zero Splunk events alone prove the handler never executed?
- Why are MCP tool results `untrusted_data`?

## Connect the concepts

**YOU JUST LEARNED** — REQUEST != GRANT. CTRL-MCP-001 is the tool PDP. ALLOW is not execution.

**THIS CONNECTS TO** — grant anatomy (scope and resource, REPLAY) and later retrieved context, which can influence a request without minting a grant.

**NEXT** — Scope Escalation (REPLAY) if you need tool+scope, then RAG / Retrieved Context (LIVE).

This lab placed the trust boundary at **tool authorization**. Other AgentSec labs place it elsewhere. The chain stays the same:

```text
SOURCE → TRUST BOUNDARY → INFLUENCE / REQUEST → AUTHORIZATION → EXECUTION → TELEMETRY → SPLUNK INVESTIGATION
```

- Prompt / input trust — untrusted text before the LLM (CTRL-INPUT-001)
- Tool authorization — this lab (CTRL-MCP-001)
- MCP metadata/catalog — descriptions are data
- Tool results — untrusted_data, not a new grant
- RAG context — retrieved text is not authority
- Persistent memory — untrusted memory is not instruction
- Identity / delegation — a deputy does not inherit extra grants
- Goal / instruction integrity — task text is not a policy change
- Supply chain — a scanner finding is not a runtime ALLOW

This workshop does not run those labs and does not claim they share this control.

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

    add_md(
        "viz_journey_mission",
        phase_markdown(
            "START",
            "Step 0 · START. Nothing here is a test yet.",
        ),
        title="WHERE YOU ARE",
    )
    add_md(
        "viz_journey_investigate",
        phase_markdown(
            "INVESTIGATE",
            "Step 4 of 8 · INVESTIGATE. Five questions, one at a time.",
        ),
        title="WHERE YOU ARE",
    )
    add_md(
        "viz_workbench_mission",
        f"""
# Can an AI agent use a tool it was never granted?

## [Open the guided lab →]({ATTACK_URL})

You will test one request against AcmeBank's loan assistant. You **predict first**, then work out what happened from **evidence**. The lab runs in the AgentSec Attack Service. Your experiment's evidence arrives in this Splunk notebook, opened for you. On the normal path you never type a run.id or a search.

## Your route

UNDERSTAND (baseline) › TEST (predict, attack) › INVESTIGATE (here, in Splunk) › IMPROVE (defend, retest) › PROVE (compare, explain)

**Already ran your ATTACK?** Open the **INVESTIGATE** tab. The lab link opens it with your run loaded.

**Baseline.** The normal-behavior baseline is shown inside the guided lab as recorded (REPLAY) evidence. You do not run it. To read the full recorded baseline in Splunk, [open the recorded BASELINE example](/app/agentsec/ws_lab_mcp_001?tab=layout_investigate&form.run_id={BASELINE_ID}).

SPL, HUNT, DETECT and the answer key are under the **REFERENCE** tabs. You do not need them to finish the lab.

**REQUEST != GRANT · ALLOW != EXECUTION · SPLUNK != ENFORCEMENT**
""",
        title="START",
    )
    # Retained as PATH B reference material. The learner-facing investigation is
    # now the Investigation Notebook on INVESTIGATE, which runs the SPL for them
    # instead of telling them to retype it into Search.
    add_md(
        "viz_path_a_reference",
        f"""
# Path A — Investigation story (reference)

Use the selected REPLAY specimen below, or open Search and replace `PASTE-LIVE-RUN-ID` with the fresh UUID from Attack Service.

```text
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="PASTE-LIVE-RUN-ID"
```

Follow one reasoning path:

1. **WHO** — identify principal, agent, and requested tool.
2. **REQUEST** — compare requested scope with server-owned allowed scope.
3. **AUTHZ** — read CTRL-MCP-001 decision and reason.
4. **EXECUTION** — look for `mcp.started`; use runtime handler count as authoritative for non-execution.
5. **EVIDENCE** — establish local-count vs Splunk `dc(_raw)` completeness before interpreting absence.

[Open Splunk Search]({SEARCH_URL})

**Hint 1:** keep the same run.id and isolate `event.name=agentsec.control.decision`. Read control id, decision, reason, requested scope, and allowed scope.

**Hint 2:** separately inspect `agentsec.mcp.started`, `agentsec.mcp.completed`, and `agentsec.mcp.failed`. Start is execution evidence; completed is success after start; failed is execution then error.

The tables below are supporting evidence, not separate missions. Empty is not DENY. HEC health is not evidence completeness.
""",
        title="PATH A · INVESTIGATE",
    )
    add_md(
        "viz_workbench_evidence",
        """
# Evidence explorer — the raw structured view

**This tab is not the guided investigation.** The question-driven notebook for
your own run lives on **INVESTIGATE**. Start there. Come here when you already
know what you are looking for and want the underlying tables side by side.

What this tab adds that the notebook does not:

- The canonical **REPLAY specimens** for ATTACK and RETEST shown together, so
  you can see the shape of each outcome without running anything.
- The **Evidence to investigate** panels bound to the dropdown above.
- The **DET-MCP-001** detector panels.

Read control decision separately from handler execution. `ALLOW` does not prove start. `DENY` alone does not prove non-execution. Runtime handler count is authoritative in this lab; indexed `mcp.started` corroborates a complete copy.

The ATTACK and RETEST panels use canonical REPLAY ids, not your run. Fingerprint equality proves only equality of the canonical object represented by that hash.

DET-MCP-001 remains disabled and checks only DENY-then-start. Silence is not SAFE.
""",
        title="EVIDENCE EXPLORER",
    )

    # The five evidence-notebook cells that used to live here were replaced by
    # the real Investigation Notebook on the INVESTIGATE tab, which runs its own
    # SPL against the learner's selected run instead of narrating REPLAY tables.

    # --- Live ATTACK vs RETEST on the learner's own run ids ----------------
    # No new input: the learner's two runs are discriminated by the indexed
    # agentsec.testbed.mode, so the most recent ATTACK and RETEST line up on their own.
    live_pair_spl = """index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 ("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed) "gen_ai.tool.name"="lookup_customer_tier"
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval profile=mvindex(mvdedup('agentsec.security.profile'),0)
| eval mode=mvindex(mvdedup('agentsec.testbed.mode'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval is_started=if(event_name="agentsec.mcp.started",1,0)
| eval is_completed=if(event_name="agentsec.mcp.completed",1,0)
| eval is_failed=if(event_name="agentsec.mcp.failed",1,0)
| stats max(is_started) as has_started, max(is_completed) as has_completed, max(is_failed) as has_failed, latest(eval(if(event_name="agentsec.control.decision",decision,null()))) as decision, latest(eval(if(event_name="agentsec.control.decision",reason,null()))) as reason, latest(eval(if(event_name="agentsec.control.decision",requested_scope,null()))) as requested_scope, latest(eval(if(event_name="agentsec.control.decision",allowed_scope,null()))) as allowed_scope, latest(eval(if(event_name="agentsec.control.decision",profile,null()))) as profile, latest(eval(if(event_name="agentsec.control.decision",mode,null()))) as mode, values(tool) as tool, dc(_raw) as matched_events, latest(_time) as last_seen by run_id
| eval execution_state=case(has_completed=1,"mcp.completed",has_failed=1,"mcp.failed",has_started=1,"mcp.started",decision="ALLOW","ALLOW_execution_not_proven_in_this_copy",1=1,"no_mcp_execution_event")
| eval scope_gap=if(requested_scope==allowed_scope,"requested == allowed","requested != allowed")
| where mode="ATTACK" OR mode="RETEST"
| sort - last_seen
| dedup mode
| sort mode
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table mode, run_id, profile, tool, requested_scope, allowed_scope, scope_gap, decision, reason, execution_state, matched_events, last_seen
| transpose 0 header_field=mode column_name=field"""
    data_sources.update(
        dict((search_ds("ds_live_pair", "Q-MCP-LIVE-PAIR", live_pair_spl),))
    )

    # --- AgentSec Investigation Notebook (INVESTIGATE tab) -----------------
    # Five cells. Each one asks a question, shows the SPL that answers it,
    # renders the real result, and states the evidence boundary. Nothing here
    # asserts an outcome: the answer comes from the learner's own run.
    nb_state_spl = (
        notebook_base()
        + f"""
| eval mode=mvindex(mvdedup('agentsec.testbed.mode'),0)
| eval profile=mvindex(mvdedup('agentsec.security.profile'),0)
| stats dc(_raw) as indexed_events, values(mode) as mode, values(profile) as profile by run_id
| eval evidence_state="INDEXED EVIDENCE PRESENT"
| eval current_evidence=if("$live_run_id$"=="{LIVE_RUN_NONE}","REPLAY — recorded "+mode+" example (not your run)","LIVE — your "+mode+" experiment")
| eval selector_in_use=if("$live_run_id$"=="{LIVE_RUN_NONE}","REPLAY example selector","LIVE box (the REPLAY example selector is ignored)")
| table current_evidence, selector_in_use, run_id, mode, profile, indexed_events, evidence_state"""
    )
    nb_decision_spl = (
        notebook_base('"event.name"=agentsec.control.decision')
        + """
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| table run_id, control_id, tool, decision, reason"""
    )
    nb_execution_spl = (
        notebook_base(NB_EXECUTION_EVENTS)
        + """
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| table sequence, event_name, tool, executed
| sort sequence"""
    )
    nb_scope_spl = (
        notebook_base('"event.name"=agentsec.control.decision')
        + """
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval scope_relationship=if(requested_scope==allowed_scope,"requested == allowed","requested != allowed")
| table run_id, tool, requested_scope, allowed_scope, scope_relationship"""
    )
    nb_timeline_spl = (
        notebook_base()
        + """
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| table _time, sequence, event_name, control_id, decision, executed
| sort sequence"""
    )
    data_sources.update(
        dict(
            (
                search_ds("ds_nb_state", "Q-MCP-NB-STATE", nb_state_spl),
                search_ds("ds_nb_decision", "Q-MCP-NB-DECISION", nb_decision_spl),
                search_ds("ds_nb_execution", "Q-MCP-NB-EXECUTION", nb_execution_spl),
                search_ds("ds_nb_scope", "Q-MCP-NB-SCOPE", nb_scope_spl),
                search_ds("ds_nb_timeline", "Q-MCP-NB-TIMELINE", nb_timeline_spl),
            )
        )
    )

    nb_no_evidence = (
        "No indexed events for the selected run.id. That is NOT PROVEN either way: it means this "
        "query found nothing, not that nothing happened. Check the run.id, then evidence readiness."
    )

    # --- P1: per-question interpretation checks ---------------------------------
    # Dashboard Studio has no radio input (D-2 spike: NOT SUPPORTED) and cannot
    # conditionally hide a panel. What it does support is an in-canvas dropdown
    # whose token gates a search. Each check below runs only once the learner has
    # chosen an answer (the default "none" returns no rows, so the table shows its
    # noDataMessage), and every verdict is computed from the SAME indexed events the
    # result table above it reads. Nothing here is a hard-coded expected outcome, and
    # nothing is graded or saved.
    nb_check_pending = (
        "Choose your interpretation in the box above. The evidence check appears here after you "
        "answer. It is not graded and it is not saved."
    )
    nb_decision_fb_spl = (
        notebook_base('"event.name"=agentsec.control.decision')
        + """
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval your_answer="$nb_a1$"
| where your_answer!="none"
| eval check=case(your_answer=="UNSURE","UNSURE is a legitimate answer. Compare it with the record.",your_answer==decision,"MATCHES the control record",1=1,"DIFFERS from the control record")
| eval evidence_supports="CTRL-MCP-001 recorded decision="+coalesce(decision,"(not recorded)")+" with reason "+coalesce(reason,"(not recorded)")+" for tool "+coalesce(tool,"(not recorded)")+"."
| table your_answer, decision, reason, check, evidence_supports"""
    )
    nb_execution_fb_spl = (
        notebook_base(NB_EXECUTION_EVENTS)
        + """
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval is_started=if(event_name="agentsec.mcp.started",1,0)
| eval is_completed=if(event_name="agentsec.mcp.completed",1,0)
| eval is_failed=if(event_name="agentsec.mcp.failed",1,0)
| eval is_stopped=if(event_name="agentsec.pipeline.stopped",1,0)
| stats max(is_started) as started, max(is_completed) as completed, max(is_failed) as failed, max(is_stopped) as pipeline_stopped by run_id
| eval your_answer="$nb_a2$"
| where your_answer!="none"
| eval evidence_shows=if(started=1,"STARTED","NOT_STARTED")
| eval check=case(your_answer=="UNSURE","UNSURE is a legitimate answer. Compare it with the record.",your_answer==evidence_shows,"MATCHES the indexed execution events",1=1,"DIFFERS from the indexed execution events")
| eval evidence_supports=case(started=1,"agentsec.mcp.started is present, so the handler began.",pipeline_stopped=1,"No agentsec.mcp.started and agentsec.pipeline.stopped is present. Consistent with the run halting before the handler. Corroboration, not proof.",1=1,"Neither agentsec.mcp.started nor agentsec.pipeline.stopped matched. NOT PROVEN either way.")
| table your_answer, evidence_shows, started, completed, failed, pipeline_stopped, check, evidence_supports"""
    )
    nb_scope_fb_spl = (
        notebook_base('"event.name"=agentsec.control.decision')
        + """
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval scope_relationship=if(requested_scope==allowed_scope,"EQUAL","DIFFERENT")
| eval your_answer="$nb_a3$"
| where your_answer!="none"
| eval check=case(your_answer=="UNSURE","UNSURE is a legitimate answer. Compare it with the record.",your_answer==scope_relationship,"MATCHES the indexed scopes",1=1,"DIFFERS from the indexed scopes")
| eval evidence_supports="requested_scope="+coalesce(requested_scope,"(not recorded)")+" and allowed_scope="+coalesce(allowed_scope,"(not recorded)")+" for tool "+coalesce(tool,"(not recorded)")+". Both are OBSERVED fields on the control event."
| table your_answer, scope_relationship, requested_scope, allowed_scope, check, evidence_supports"""
    )
    data_sources.update(
        dict(
            (
                search_ds("ds_nb_decision_fb", "Q-MCP-NB-DECISION-CHECK", nb_decision_fb_spl),
                search_ds("ds_nb_execution_fb", "Q-MCP-NB-EXECUTION-CHECK", nb_execution_fb_spl),
                search_ds("ds_nb_scope_fb", "Q-MCP-NB-SCOPE-CHECK", nb_scope_fb_spl),
            )
        )
    )

    add_md(
        "viz_nb_header",
        """
# AgentSec Investigation Notebook

## LAB-MCP-001 — MCP Tool Authorization

**YOU ARE HERE: INVESTIGATE (step 4 of 8).** Five questions, one at a time. For each one you read the evidence, say what you think it shows, and then check your reasoning against the same evidence. You do not type a search.

**WHICH EVIDENCE IS BEING READ?** The **CURRENT EVIDENCE** table above says it in words: **LIVE — your own experiment**, or **REPLAY — a recorded example**. The two controls at the top only choose which evidence to read. Neither one runs an experiment. While the LIVE box holds a run.id, the REPLAY selector is ignored.

**WHICH RUN IS THIS?** Whether the run you are reading requested a granted tool is exactly what the first questions establish. Do not decide from the name of the specimen.

**HOW EACH QUESTION WORKS.** 1. Read the question. 2. Read the evidence table. 3. Choose your interpretation. 4. Read what the evidence supports and what it does **not** prove.

**Recovery only.** If the LIVE box still reads `none` after you came from the lab, click in the box, select everything in it (`Ctrl+A` / `Cmd+A`), paste your run.id and press Enter. That is not the normal path.

**Business context.** A customer applied for a home loan. The AcmeBank agent is granted exactly one tool, `lookup_policy`. Other tools, such as `lookup_customer_tier`, exist but are **not granted** to this agent. **KNOWN TOOL != GRANTED TOOL.**

Your interpretations are not saved or graded. The SPL behind every table, and native Search, are on the **REFERENCE** tab.
""",
        title="INVESTIGATION NOTEBOOK",
    )
    add_table(
        "viz_nb_state",
        "ds_nb_state",
        "CURRENT EVIDENCE: what every table on this tab reads",
        "Resolved from the LIVE and REPLAY example controls above. `mode` and `profile` are read from the "
        "indexed events themselves, not asserted by this page. `indexed_events` is how many events this "
        "run has in the index; it is a count, not a completeness guarantee.",
        no_data=nb_no_evidence,
    )

    # ---- Question 1: control decision ---------------------------------------
    add_md(
        "viz_nb1_q",
        """
# 1 of 5 — What did the control decide?

**QUESTION.** What did CTRL-MCP-001 decide for the requested tool?

**WHY THIS MATTERS.** An agent asking for a tool does not mean the request was authorized. The decision is a separate fact from the request, so it has to be read from the control's own event.

**EVIDENCE RESULT.** Read the table below. It reads the CURRENT EVIDENCE run.
""",
    )
    add_table(
        "viz_nb1_r",
        "ds_nb_decision",
        "EVIDENCE RESULT — the control's decision for this run",
        "The control fact only. Execution is answered by Question 2.",
        no_data=nb_no_evidence,
    )
    add_table(
        "viz_nb1_fb",
        "ds_nb_decision_fb",
        "CHECK — your interpretation against the control record",
        "Computed from the same indexed control event as the table above. Not graded, not saved.",
        no_data=nb_check_pending,
    )
    add_md(
        "viz_nb1_limits",
        """
**YOUR OBSERVATION.** Write the decision and the reason in your own words before you move on. Not saved by this page.

**WHAT THE EVIDENCE SUPPORTS.** The decision and reason above are what CTRL-MCP-001 returned for this run: ALLOW, DENY or ERROR. `reason` is the control's own explanation.

**WHAT THIS DOES NOT PROVE.** The decision alone does not prove the tool ran, and it says nothing about any other tool. **ALLOW != EXECUTION.** Question 2 is a separate query because it is a separate fact.

**NEXT.** Question 2 below: did anything actually start?
""",
    )

    # ---- Question 2: execution ----------------------------------------------
    add_md(
        "viz_nb2_q",
        """
# 2 of 5 — Did downstream execution occur?

**QUESTION.** Did the MCP handler actually start for this run?

**WHY THIS MATTERS.** A decision and an execution are two different events. Neither can be inferred from the other.

**EVIDENCE RESULT.** Read the table below. It reads the CURRENT EVIDENCE run, LIVE or REPLAY, as stated at the top. It is built from execution events alone. Its search never references the control's decision, and you can confirm that on the REFERENCE tab.
""",
    )
    add_table(
        "viz_nb2_r",
        "ds_nb_execution",
        "EVIDENCE RESULT — execution evidence for this run",
        "Execution events only. No row here means this query matched nothing, which is weaker "
        "than proof that the handler never ran.",
        no_data=(
            "No MCP execution event and no pipeline.stopped matched for this run.id. That is NOT "
            "PROVEN as non-execution on its own — confirm against the runtime handler count."
        ),
    )
    add_table(
        "viz_nb2_fb",
        "ds_nb_execution_fb",
        "CHECK — your interpretation against the execution events",
        "Computed from execution events only. It does not read the control's decision. Not graded, not saved.",
        no_data=nb_check_pending,
    )
    add_md(
        "viz_nb2_limits",
        """
**YOUR OBSERVATION.** Which execution events exist for this run, and what does their presence or absence let you say? Not saved by this page.

**WHAT THE EVIDENCE SUPPORTS.** `agentsec.mcp.started` is handler start. `agentsec.mcp.completed` is success after a start. `agentsec.mcp.failed` is a start followed by an error. `agentsec.pipeline.stopped` means the run was halted before the handler.

**WHAT THIS DOES NOT PROVE.** An absent `mcp.started` in Splunk is corroboration of non-execution, not proof: this is an indexed copy, and a missing event can mean a missing copy. The runtime handler count in the lab is the authoritative source. **CONTROL DECISION != EXECUTION.**

**NEXT.** Question 3 below: what was requested, and was it granted?
""",
    )

    # ---- Question 3: requested versus granted -------------------------------
    add_md(
        "viz_nb3_q",
        """
# 3 of 5 — What was requested, and was it granted?

**QUESTION.** What capability did the agent request, and was it inside the scope the server granted?

**WHY THIS MATTERS.** An agent may know a tool exists without being authorized to use it. Catalogue visibility and authority are different things.

**EVIDENCE RESULT.** Read the table below. It reads the CURRENT EVIDENCE run, LIVE or REPLAY, as stated at the top. Compare the requested scope with the allowed scope.
""",
    )
    add_table(
        "viz_nb3_r",
        "ds_nb_scope",
        "EVIDENCE RESULT — requested scope vs granted scope (OBSERVED)",
        "Both scopes are indexed runtime fields. The granted tool list itself is DOCUMENTED "
        "configuration and is described below, not queried here.",
        no_data=nb_no_evidence,
    )
    add_table(
        "viz_nb3_fb",
        "ds_nb_scope_fb",
        "CHECK — your interpretation against the indexed scopes",
        "Computed from the same control event as the table above. Not graded, not saved.",
        no_data=nb_check_pending,
    )
    add_md(
        "viz_nb3_limits",
        """
**YOUR OBSERVATION.** State the requested capability, the granted capability, and whether they match. Not saved by this page.

**WHAT THE EVIDENCE SUPPORTS.** `requested_scope` and `allowed_scope` are OBSERVED runtime fields: the runtime reported the grant it evaluated against. The grant itself is **DOCUMENTED configuration** in `src/agentsec/mcp`: the agent is allowed `lookup_policy` / `policy:read`. Other catalogue tools, such as `lookup_customer_tier` / `customer:read`, are known but not granted.

**WHAT THIS DOES NOT PROVE.** A scope mismatch does not by itself tell you what the control decided or whether anything executed. Those are Questions 1 and 2. **KNOWN TOOL != GRANTED TOOL.**

**NEXT.** Question 4 below: what was actually indexed, in order?
""",
    )

    # ---- Question 4: the ordered sequence -----------------------------------
    add_md(
        "viz_nb4_q",
        """
# 4 of 5 — What was actually indexed for this run?

**QUESTION.** What sequence of evidence exists for this run.id?

**WHY THIS MATTERS.** A conclusion should be traceable to events you can point at. Reading the whole ordered sequence is also how you notice what is *missing*, and whether a gap is meaningful or just unsearchable.

**EVIDENCE RESULT.** Read the table below. It reads the CURRENT EVIDENCE run, LIVE or REPLAY, as stated at the top. No event filter: everything indexed for the run, in order.
""",
    )
    add_table(
        "viz_nb4_r",
        "ds_nb_timeline",
        "EVIDENCE RESULT — ordered event timeline for this run",
        "Every indexed event for the selected run.id, ordered by agentsec.sequence.",
        no_data=nb_no_evidence,
    )
    add_md(
        "viz_nb4_limits",
        """
**YOUR OBSERVATION.** Write the sequence down. Which events are present, and which are absent that you expected? Not saved by this page.

**WHAT THE EVIDENCE SUPPORTS.** The ordered list above is what this run actually produced in the index. Read it rather than recalling what a run of this kind usually looks like. Different profiles produce different sequences, and that difference is the finding.

**WHAT THIS DOES NOT PROVE.** A row count is not a completeness guarantee. HEC accepting an event is not the same as the event being searchable, so an absent row may be an absent copy rather than an absent action.

**NEXT.** Question 5 below: what can you legitimately conclude?
""",
    )

    # ---- Question 5: what can you claim -------------------------------------
    add_md(
        "viz_nb5_q",
        """
# 5 of 5 — What can you legitimately conclude?

**QUESTION.** Given only the evidence, what will you claim?

**WHY THIS MATTERS.** The gap between what happened and what you can show is where incident reporting goes wrong. A claim you cannot trace to an event is an assumption wearing a conclusion's clothes.

**EVIDENCE RESULT.** The table below puts your most recent ATTACK and RETEST side by side, one column per run.id. It selects by mode and recency, so it does not follow the LIVE box. Check that the two `run_id` values are the ones the lab gave you and that they **differ**. A missing column is unsearchable evidence, not a safe result.
""",
    )
    add_table(
        "viz_live_pair",
        "ds_live_pair",
        "EVIDENCE RESULT — ATTACK ↔ RETEST (your live run.ids)",
        "One column per run.id, one row per field. `decision` is the control fact; `execution_state` is the execution "
        "fact; they are read separately. `matched_events` counts only the events this query "
        "matched, so it is smaller than the run total and is not a completeness answer.",
        no_data=(
            "No indexed events were found for the run.ids entered above. That is not DENY and not "
            "proof of prevention. Check that both ids are pasted, then re-check evidence readiness."
        ),
    )
    add_md(
        "viz_nb5_limits",
        """
**YOUR OBSERVATION.** Write four statements, each with a label: what CTRL-MCP-001 decided; whether separate evidence shows downstream execution; what changed between ATTACK and RETEST (only if both runs are present); and one thing this evidence does **not** prove. Not saved by this page.

**CLAIM VOCABULARY.** **PROVEN**: the evidence cannot be true and the claim false. **SUPPORTED**: consistent with the claim and weighing for it. **OBSERVED**: you saw this specific fact and are not generalising. **NOT PROVEN**: you cannot establish it either way.

**WHAT THE EVIDENCE SUPPORTS.** For each run, the decision, reason and execution state beside the scopes it was evaluated against. Where both runs are present, you can say what differed between two configurations for the same request.

**WHAT THIS DOES NOT PROVE.** One tool, one agent and one request shape. A DENY here says nothing about the next request, a different tool, or a different lab, and a matching pair does not show the control is correct in general. **ATTACK != UNIVERSAL COMPROMISE · RETEST != UNIVERSAL SECURITY.** Do not write "system compromised", "attack successful", "system secure" or "retest successful".

**NEXT.** Return to the guided lab tab you came from (your place is kept there) and continue with **Understand the defense**. If you closed it, [open the lab again]({ATTACK_URL}).
""",
    )

    # ---- REFERENCE: the SPL behind every table, printed verbatim ------------
    # P0 printed each query inside the learner's question cell. P1 moves it here so
    # the notebook reads as questions and evidence first. Visible SPL == executed SPL
    # is unchanged: with_spls() puts the SAME string into the panel that the data
    # source runs, and tests/splunk/test_investigation_notebook.py pins that.
    add_md(
        "viz_ref_header",
        """
# REFERENCE — the SPL behind the notebook, and advanced investigation

You do not need this tab to finish the lab. It is here so you can **reproduce** any table in Search, and so the evidence stays checkable.

Every query below is printed exactly as the table runs it, with the run selection Studio currently holds already filled in. Copy one into Splunk Search to reproduce the same table. **SPLUNK != ENFORCEMENT.** HUNT, DETECT, the raw evidence explorer and the answer key remain on the tabs under this one.
""",
        title="REFERENCE",
    )
    add_md(
        "viz_ref_state",
        with_spls(
            """
## CURRENT EVIDENCE — the query behind the first table on INVESTIGATE

```text
<<SPL>>
```
""",
            [nb_state_spl],
        ),
        title="SPL · CURRENT EVIDENCE",
    )
    add_md(
        "viz_ref_nb1",
        with_spls(
            """
## Question 1 — the control's decision

**EVIDENCE RESULT query**

```text
<<SPL>>
```

**CHECK query** (runs after you choose an interpretation; `$nb_a1$` is your choice)

```text
<<SPL>>
```
""",
            [nb_decision_spl, nb_decision_fb_spl],
        ),
        title="SPL · QUESTION 1",
    )
    add_md(
        "viz_ref_nb2",
        with_spls(
            """
## Question 2 — execution

These queries never reference `agentsec.control.decision`. Execution is established from execution events alone.

**EVIDENCE RESULT query**

```text
<<SPL>>
```

**CHECK query** (`$nb_a2$` is your choice)

```text
<<SPL>>
```
""",
            [nb_execution_spl, nb_execution_fb_spl],
        ),
        title="SPL · QUESTION 2",
    )
    add_md(
        "viz_ref_nb3",
        with_spls(
            """
## Question 3 — requested versus granted scope

**EVIDENCE RESULT query**

```text
<<SPL>>
```

**CHECK query** (`$nb_a3$` is your choice)

```text
<<SPL>>
```
""",
            [nb_scope_spl, nb_scope_fb_spl],
        ),
        title="SPL · QUESTION 3",
    )
    add_md(
        "viz_ref_nb4",
        with_spls(
            """
## Question 4 — the ordered event timeline

Every column in the table is created by a line you can see here.

```text
<<SPL>>
```
""",
            [nb_timeline_spl],
        ),
        title="SPL · QUESTION 4",
    )
    add_md(
        "viz_live_pair_intro",
        with_spls(
            """
## Question 5 — the ATTACK ↔ RETEST comparison

This is the whole query the comparison table runs. It takes no run.id: it selects by mode and recency, so pasted into Splunk Search it returns the latest ATTACK and RETEST as of the moment you run it, which is your pair unless you have launched more since. It ends in `transpose`, so each field is a row and each run is a column.

```text
<<SPL>>
```
""",
            [live_pair_spl],
        ),
        title="SPL · QUESTION 5",
    )
    add_md(
        "viz_nb_advanced",
        f"""
## Advanced investigation — open in Splunk Search

The notebook is the classroom. Native Search is the analyst workbench, and you should move to it once you want to ask a question the notebook does not.

Start from the base search and add your own clauses:

```text
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="YOUR-RUN-ID"
```

[Open Splunk Search]({SEARCH_URL}) · [Run another experiment in the Attack Service]({ATTACK_URL})

Native Search is an addition to this notebook, not a replacement for it. Nothing you do there changes a control decision: **SPLUNK != ENFORCEMENT.**
""",
        title="ADVANCED",
    )
    # viz_flow_diagram is not created here. scripts/apply_workshop_flows.py owns it
    # for every workshop and must run after this script.
    mission_structure = [
        block("viz_journey_mission", 0, 0, FULL, JOURNEY_H),
        block("viz_workbench_mission", 0, JOURNEY_H + INVESTIGATE_GAP, FULL, START_H),
    ]
    # INVESTIGATE is the guided notebook, one question at a time:
    #   QUESTION -> WHY IT MATTERS -> EVIDENCE RESULT -> YOUR INTERPRETATION
    #   -> WHAT THE EVIDENCE SUPPORTS -> WHAT THIS DOES NOT PROVE -> NEXT
    # The SPL is not here any more: it is printed verbatim on REFERENCE.
    # Panels are stacked, not hand-positioned: every offset follows from the
    # heights above it, so raising one panel can no longer overlap the next or
    # leave the canvas too short. Heights below were MEASURED on the deployed
    # Splunk 10.2 page at a 1024px window and at genuine 200% browser zoom (the
    # narrowest cases that still reflow text); see
    # tests/splunk/test_investigation_notebook.py::MEASURED_MIN_HEIGHT_NARROW.
    investigate_panels = [
        # P0.1: CURRENT EVIDENCE comes first so the learner sees whether this tab
        # reads LIVE or REPLAY before any prose or journey text.
        ("viz_nb_state", 220, "block"),
        ("viz_journey_investigate", JOURNEY_H, "block"),
        ("viz_nb_header", 440, "block"),
        ("viz_nb1_q", 180, "block"),
        ("viz_nb1_r", 320, "block"),
        ("input_nb1", INPUT_H, "input"),
        ("viz_nb1_fb", 390, "block"),
        ("viz_nb1_limits", 170, "block"),
        ("viz_nb2_q", 180, "block"),
        ("viz_nb2_r", 190, "block"),
        ("input_nb2", INPUT_H, "input"),
        ("viz_nb2_fb", 260, "block"),
        ("viz_nb2_limits", 210, "block"),
        ("viz_nb3_q", 180, "block"),
        ("viz_nb3_r", 180, "block"),
        ("input_nb3", INPUT_H, "input"),
        ("viz_nb3_fb", 320, "block"),
        ("viz_nb3_limits", 200, "block"),
        ("viz_nb4_q", 180, "block"),
        # 650 (P1 measurement at 1024px and genuine 200%: needs ~643); was 600, 380 before: at 1280px this table needed 43px more than its box and at
        # 1024px 163px more, so the learner had to scroll inside the panel to reach
        # the later events of the very timeline Cell 4 asks them to read in order.
        ("viz_nb4_r", 650, "block"),
        ("viz_nb4_limits", 180, "block"),
        ("viz_nb5_q", 210, "block"),
        # The comparison is transposed (one column per run, one row per field), so
        # every field and every full value stays on screen at any width.
        ("viz_live_pair", 580, "block"),
        ("viz_nb5_limits", 290, "block"),
    ]
    investigate_structure = []
    _y = 0
    for _item, _h, _kind in investigate_panels:
        investigate_structure.append(
            {"item": _item, "type": _kind, "position": {"x": 0, "y": _y, "w": FULL, "h": _h}}
        )
        _y += _h + INVESTIGATE_GAP
    investigate_height = _y - INVESTIGATE_GAP
    # REFERENCE: the SPL behind the notebook, advanced Search, and (below that) the
    # raw explorer: the canonical REPLAY specimens side by side, plus the detector
    # panels. INVESTIGATE answers "what happened on my run"; this tab answers "how
    # can I reproduce it, and what does the evidence look like in general".
    reference_panels = [
        ("viz_ref_header", 220),
        ("viz_ref_state", 360),
        ("viz_ref_nb1", 760),
        ("viz_ref_nb2", 920),
        ("viz_ref_nb3", 760),
        ("viz_ref_nb4", 500),
        ("viz_live_pair_intro", 800),
        ("viz_nb_advanced", 380),
    ]
    evidence_structure = []
    _ry = 0
    for _item, _h in reference_panels:
        evidence_structure.append(block(_item, 0, _ry, FULL, _h))
        _ry += _h + INVESTIGATE_GAP
    _raw = [
        ("viz_workbench_evidence", 0, 0, FULL, 360),
        ("viz_attack_what_id", 0, 308, HALF, 240),
        ("viz_retest_what_id", HALF, 308, HALF, 240),
        ("viz_attack_what_dec", 0, 556, HALF, 280),
        ("viz_retest_what_dec", HALF, 556, HALF, 280),
        ("viz_attack_authz", 0, 844, HALF, 280),
        ("viz_retest_authz", HALF, 844, HALF, 280),
        ("viz_attack_exec", 0, 1132, HALF, 300),
        ("viz_retest_exec", HALF, 1132, HALF, 300),
        ("viz_prove_what_id", 0, 1440, FULL, 230),
        ("viz_prove_what_dec", 0, 1678, FULL, 260),
        ("viz_observe_seq", 0, 1946, FULL, 380),
        ("viz_observe_authz", 0, 2334, HALF, 300),
        ("viz_observe_tool", HALF, 2334, HALF, 300),
        ("viz_detect_live", 0, 2642, HALF, 340),
        ("viz_detect_sim", HALF, 2642, HALF, 340),
    ]
    # P1: the explorer intro grew 60 units (measured: its text needs ~350 at 1024px and at
    # 200% zoom); every raw-explorer panel below it moves down by the same amount.
    _RAW_SHIFT = 60
    for _item, _x, _y0, _w, _h in _raw:
        evidence_structure.append(block(_item, _x, _ry + _y0 + (_RAW_SHIFT if _y0 else 0), _w, _h))
    evidence_height = _ry + 2982 + _RAW_SHIFT
    # Studio cannot conditionally hide a panel, so this tab cannot be gated by
    # the platform. The gate it can have is an honest one: the tab is named
    # ANSWERS, nothing links here before prediction, and this banner is the
    # first thing on the page.
    add_md(
        "viz_path_b_gate",
        """
# Stop — this tab contains the answers

Everything below is an **answer key**. It states what CTRL-MCP-001 decides and
what the execution evidence shows for each mode.

Reading it before you predict and run removes the only part of this lab that
teaches anything. A prediction you already know the answer to is not a
prediction.

## Do these first

1. Record your prediction in the Attack Service workbench.
2. Launch ATTACK, then RETEST.
3. Work through the five questions on **INVESTIGATE** using your own `run.id`.

Come back here afterwards to check your reasoning, or if you are stuck and have
already committed to an answer.

**This tab cannot lock itself.** Dashboard Studio has no supported mechanism to
hide a panel until a condition is met, and faking one with injected JavaScript
is not a supported extension. The gate is the warning you are reading.
""",
        title="ANSWER KEY — READ AFTER PREDICTING",
    )
    primary_ids = {
        row["item"]
        for row in mission_structure + investigate_structure + evidence_structure
    }
    path_b_structure: list[dict] = [block("viz_path_b_gate", 0, 0, FULL, 560)]
    path_b_y = 560
    for viz_id, viz in visualizations.items():
        if viz_id in primary_ids or viz_id == "viz_path_b_gate":
            continue
        is_table = viz["type"] == "splunk.table"
        height = 300 if is_table else 520
        path_b_structure.append(block(viz_id, 0, path_b_y, FULL, height))
        path_b_y += height

    definition = {
        "title": "Tool Authorization",
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
            },
        },
        "inputs": {
            "input_run_id": {
                "type": "input.dropdown",
                # This control SELECTS recorded evidence. It does not run an
                # experiment, and "Attack" in an option label names which recorded
                # run to read, not an action.
                "title": SELECTOR_TITLE,
                "options": {
                    "token": "run_id",
                    "defaultValue": BASELINE_ID,
                    "items": [
                        {"label": SELECTOR_LABELS["baseline"], "value": BASELINE_ID},
                        {"label": SELECTOR_LABELS["attack"], "value": ATTACK_ID},
                        {"label": SELECTOR_LABELS["retest"], "value": RETEST_ID},
                    ],
                },
            },
            # In-canvas interpretation controls (D-2 spike: input.radio is NOT SUPPORTED;
            # an in-canvas input.dropdown IS). Each is bound to one question and defaults
            # to the "none" sentinel, which keeps its CHECK table closed.
            "input_nb1": nb_dropdown("Q1 · What did it decide?", "nb_a1", [
                ("ALLOW", "ALLOW"), ("DENY", "DENY"), ("ERROR", "ERROR"), ("UNSURE", "UNSURE")]),
            "input_nb2": nb_dropdown("Q2 · Did the tool start?", "nb_a2", [
                ("Handler started", "STARTED"), ("Handler did not start", "NOT_STARTED"), ("UNSURE", "UNSURE")]),
            "input_nb3": nb_dropdown("Q3 · Scope vs grant?", "nb_a3", [
                ("Scopes are equal", "EQUAL"), ("Scopes differ", "DIFFERENT"), ("UNSURE", "UNSURE")]),
            # Defined here, not left to apply_guided_learning, because that shared
            # injector defaults every LIVE lab's box to empty and only adds the
            # input when it is absent. See LIVE_RUN_NONE for why empty is wrong here.
            "input_live_run": {
                "type": "input.text",
                "title": LIVE_TITLE,
                "options": {"token": "live_run_id", "defaultValue": LIVE_RUN_NONE},
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
                "input_live_run",
            ],
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    # P1 D-3: the learner journey is START then INVESTIGATE. The two
                    # REFERENCE tabs keep HUNT, DETECT, the raw SPL, advanced Search and
                    # the answer key reachable without being learner destinations.
                    # Layout ids are kept so existing deep links and pins still resolve.
                    {"layoutId": "layout_mission", "label": "START"},
                    {"layoutId": "layout_investigate", "label": "INVESTIGATE"},
                    {"layoutId": "layout_evidence", "label": "REFERENCE"},
                    {"layoutId": "layout_path_b", "label": "REFERENCE · ANSWERS"},
                ],
            },
            "layoutDefinitions": {
                "layout_mission": layout(mission_structure, JOURNEY_H + INVESTIGATE_GAP + START_H),
                "layout_investigate": layout(investigate_structure, investigate_height),
                "layout_evidence": layout(evidence_structure, evidence_height),
                "layout_path_b": layout(path_b_structure, path_b_y + 40, display="fit-to-width"),
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
        "  <label>Tool Authorization</label>\n"
        "  <description>WS-MCP-001. Validated Q-MCP SPL. DET-MCP-001 packaged disabled. Not a notable-event pack. LAB-MCP-001. Splunk does not ALLOW or DENY a tool.</description>\n"
        "  <definition><![CDATA[\n"
        f"{payload}\n"
        "  ]]></definition>\n"
        "</dashboard>\n"
    )
    OUT_XML.parent.mkdir(parents=True, exist_ok=True)
    OUT_XML.write_text(xml, encoding="utf-8")


def main() -> None:
    definition = build()
    definition.setdefault("title", "Tool Authorization")
    definition.setdefault(
        "description",
        "WS-MCP-001. Validated Q-MCP SPL. DET-MCP-001 packaged disabled. Not a notable-event pack. LAB-MCP-001. Splunk does not ALLOW or DENY a tool.",
    )
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
