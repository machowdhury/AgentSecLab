#!/usr/bin/env python3
"""Build the LAB-AGENT-DELEGATION-001 Dashboard Studio workshop.

Reuses validated Q-AGENT-DELEGATION-AUTHORITY and Q-MCP-* hunts. Bind tokens only.
DET-MCP-001.spl is not modified. No DET-A2A. No Q-A2A family.
CTRL-IDENTITY-001 OBSERVE only. CTRL-MCP-001 is the sole tool PDP.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
ID_DIR = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_agent_delegation.xml"
)
INV_PATH = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001" / "investigations.json"
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
ATTACK_URL = "http://127.0.0.1:5001/labs/LAB-AGENT-DELEGATION-001"

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

BASELINE_ID = "b419465c-84d8-4639-8449-34dd99841ba9"
ATTACK_ID = "f846be88-1f9d-4dde-ac80-193c01b47660"
RETEST_ID = "271695f5-4739-44f2-8bf4-0749d04f4b03"
PRINCIPAL = "applicant-web"
CALLER = "acme-agent-advisor-005"
BASELINE_HASH = "sha256:93f1e257a7d6c7660aa8b1d1b980f1509b7da69e215b385ac79c222e1058b3eb"
ATTACK_HASH = "sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd"


def fingerprint_block(h: str) -> str:
    """Split sha256:<64 hex> so Studio markdown can show the full digest in a 4-col card."""
    algo, digest = h.split(":", 1)
    return f"{algo}:\n{digest[:32]}\n{digest[32:]}"


CALLEE = "acme-agent-fulfillment-006"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_EVENT = (
    "No indexed event matched this evidence question. That is not SAFE, not TRUSTED, "
    "not blocked, not prevented, and not proof there was no attack."
)
EMPTY_ID = (
    "Q-AGENT-DELEGATION-AUTHORITY returned zero rows. Zero rows means no indexed "
    "CTRL-IDENTITY-001 for this run.id. That is not SAFE, not DENY, and not "
    "proof the claim was trusted or that anyone authenticated."
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
    "look for DENY then later mcp.started. Zero rows is not SAFE."
)
EMPTY_SEQ = (
    "No indexed event matched this evidence question. Sequence cannot be shown. "
    "That is not a security outcome."
)
EMPTY_HUNT = (
    "Investigate specimen defaults to BASELINE. Custom run.id is available from Search. "
    "Empty tables are missing indexed rows, not security outcomes."
)
ALLOW_NOT_EXEC = (
    "ALLOW is the control decision. Tool execution begins at mcp.started. "
    "Do not read ALLOW as execution. mcp.completed is success of a begun call. "
    "mcp.failed is execution then error, not prevention."
)
RUNTIME_AUTH = (
    "Runtime handler count is authoritative proof of non-execution. Missing "
    "indexed mcp.started is corroboration only, and only on a complete copy. "
    "Splunk does not prove prevention."
)
DATA_NOT_AUTHORITY = (
    "INV-001 / INV-002 / INV-005: a caller/delegation claim cannot independently authorize privileged actions. "
    "IDENTITY CLAIM IS DATA. DELEGATION CLAIM != AUTHORIZATION. REQUEST != GRANT. OBSERVE != ALLOW."
)

SPL_TEACHING = {
    "Q-AGENT-DELEGATION-AUTHORITY": (
        "- Reconstructs principal → caller → callee → claimed delegation → IDENTITY OBSERVE → request → MCP.\n"
        "- Request fingerprint is identity_claim_hash on the IDENTITY hop, not hop-1 MCP hash.\n"
        "- OBSERVE is not ALLOW. Follow-on tool is a REQUEST."
    ),
    "Q-MCP-AUTHZ": (
        "- Control.decision rows only. Hop 0 is CTRL-IDENTITY-001. Hop 1 is CTRL-MCP-001 when a follow-on exists.\n"
        "- Splunk did not make the decision."
    ),
    "Q-MCP-EXECUTED": (
        "- Joins control + mcp.* into execution_state.\n"
        "- Runtime handler count remains authoritative for non-execution."
    ),
    "Q-MCP-TOOL": (
        "- mcp.started rows only. Presence means the handler began."
    ),
    "Q-MCP-WHO": (
        "- Principal / agent / tool identity on control.decision. Attribution is not authentication."
    ),
}

TABLE_BIND = {
    "IDENTITY-I1-FIND-THE-EXPERIMENT": [
        (
            "ds_q_id",
            "Q-AGENT-DELEGATION-AUTHORITY (REPLAY specimen)",
            "Path B identity row. Fresh LIVE run.id is Search, not this table.",
        ),
        (
            "ds_q_who",
            "Q-MCP-WHO (REPLAY)",
            "Identity row. Attribution is not authentication.",
        ),
    ],
    "IDENTITY-I2-IDENTIFY-THE-ACTORS": [
        (
            "ds_q_id",
            "Q-AGENT-DELEGATION-AUTHORITY actors (REPLAY)",
            "Expect applicant-web / acme-agent-advisor-005 / acme-agent-fulfillment-006.",
        )
    ],
    "IDENTITY-I3-INSPECT-THE-DELEGATION-CLAIM": [
        (
            "ds_q_id",
            "Q-AGENT-DELEGATION-AUTHORITY claim (REPLAY)",
            "BASELINE claims policy:read. ATTACK/RETEST claim customer:read.",
        )
    ],
    "IDENTITY-I4-EVALUATE-IDENTITY-TRUST": [
        (
            "ds_q_authz",
            "Q-MCP-AUTHZ (REPLAY specimen)",
            "Hop 0 IDENTITY OBSERVE. OBSERVE is not ALLOW.",
        )
    ],
    "IDENTITY-I5-INSPECT-ACTUAL-CODED-AUTHORITY": [
        (
            "ds_q_id",
            "Q-AGENT-DELEGATION-AUTHORITY coded scope (REPLAY)",
            "Coded allowed scope is not the claimed scope. A + B != NEW AUTHORITY.",
        )
    ],
    "IDENTITY-I6-FIND-THE-PRIVILEGED-REQUEST": [
        (
            "ds_q_id",
            "Q-AGENT-DELEGATION-AUTHORITY request (REPLAY)",
            "REQUEST != GRANT. lookup_customer_tier on ATTACK/RETEST.",
        )
    ],
    "IDENTITY-I7-WHO-AUTHORIZED-IT": [
        (
            "ds_q_authz",
            "Q-MCP-AUTHZ tool PDP (REPLAY)",
            "Hop 1 is CTRL-MCP-001. IDENTITY did not grant the tool.",
        )
    ],
    "IDENTITY-I8-DETERMINE-WHETHER-EXECUTION-OCCURRED": [
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
    ],
}


def load_hunt_spl(name: str) -> str:
    rag = ID_DIR / name
    if rag.is_file():
        return rag.read_text(encoding="utf-8").strip()
    return (SEARCH_DIR / name).read_text(encoding="utf-8").strip()


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


def solution_md(inv: dict, number: int, spl_file: str) -> str:
    spl = load_hunt_spl(spl_file)
    bound = spl.replace("__RUN_ID__", '"$run_id$"')
    hunt = inv["related_hunt"]
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


def load_spl(name: str, *, identity: bool = False) -> str:
    directory = ID_DIR if identity else SEARCH_DIR
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
| eval principal=mvindex(mvdedup('agentsec.principal.id'),0)
| eval caller=mvindex(mvdedup('agentsec.identity.caller_agent_id'),0)
| eval callee=mvindex(mvdedup('agentsec.identity.callee_agent_id'),0)
| eval claim_trust=mvindex(mvdedup('agentsec.identity.claim.trust'),0)
| eval claimed_scope=mvindex(mvdedup('agentsec.delegation.claimed_scope'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| table sequence, run_id, event_name, hop, control_id, decision, reason, principal, caller, callee, claim_trust, claimed_scope, tool, requested_scope, allowed_scope
| sort sequence"""


def build() -> dict:
    q_rag = bind_run_id(load_spl("Q-AGENT-DELEGATION-AUTHORITY.spl", identity=True), "run_id")
    q_who = bind_run_id(load_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_rag_b = bind_literal(load_spl("Q-AGENT-DELEGATION-AUTHORITY.spl", identity=True), BASELINE_ID)
    q_rag_a = bind_literal(load_spl("Q-AGENT-DELEGATION-AUTHORITY.spl", identity=True), ATTACK_ID)
    q_rag_r = bind_literal(load_spl("Q-AGENT-DELEGATION-AUTHORITY.spl", identity=True), RETEST_ID)
    q_authz_b = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), BASELINE_ID)
    q_authz_a = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), ATTACK_ID)
    q_authz_r = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), RETEST_ID)
    q_tool_a = bind_literal(load_spl("Q-MCP-TOOL.spl"), ATTACK_ID)
    q_tool_r = bind_literal(load_spl("Q-MCP-TOOL.spl"), RETEST_ID)
    q_exec_b = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), BASELINE_ID)
    q_exec_a = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), ATTACK_ID)
    q_exec_r = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), RETEST_ID)
    q_after_b = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), BASELINE_ID)
    q_after_a = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), ATTACK_ID)
    q_after_r = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), RETEST_ID)

    data_sources = dict(
        (
            search_ds("ds_q_id", "Q-AGENT-DELEGATION-AUTHORITY", q_rag),
            search_ds("ds_q_who", "Q-MCP-WHO", q_who),
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_id_b", "Q-AGENT-DELEGATION-AUTHORITY BASELINE", q_rag_b),
            search_ds("ds_q_id_a", "Q-AGENT-DELEGATION-AUTHORITY ATTACK", q_rag_a),
            search_ds("ds_q_id_r", "Q-AGENT-DELEGATION-AUTHORITY RETEST", q_rag_r),
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
            search_ds("ds_observe_seq", "Identity observe sequence", observe_sequence_spl("run_id")),
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

    cap_rag = (
        "Q-AGENT-DELEGATION-AUTHORITY. Reconstructs principal, caller, callee, claimed "
        "scope, IDENTITY OBSERVE, privileged request, MCP decision, and indexed execution "
        "observation. Overlay reason is a lab display helper, not a production IOC. "
        "WHO AUTHENTICATED is not proven."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision rows. IDENTITY OBSERVE is classification, "
        "not a grant. Hop-1 CTRL-MCP-001 is authorization. executed on the control "
        "row is not handler execution."
    )
    cap_tool = (
        "Q-MCP-TOOL. IDENTITY hop may list the requested tool without mcp.started. "
        "Zero mcp.started rows is not automatically DENY."
    )
    cap_exec = (
        "Q-MCP-EXECUTED. Read has_started and execution_state for whether the "
        "handler began. " + ALLOW_NOT_EXEC
    )
    cap_who = (
        "Q-MCP-WHO. Principal / agent identity. Attribution is not authentication. "
        "WHO AUTHENTICATED is not proven."
    )
    cap_seq = (
        "Ordered control then mcp.* events with hop.index, sequence, principal, "
        "caller, callee, claim trust, and claimed scope. This is a Studio "
        "view of indexed fields, not a new hunt file."
    )
    cap_after = (
        "Q-MCP-AFTER-DENY. Hunt form of DET-MCP-001. LIVE identity specimens: 0 rows. "
        "Zero rows is CORRECT and is not SAFE."
    )

    add_md(
        "viz_learn",
        f"""
# Agent Identity / Delegation

**QUESTION**

Can Agent A claim that authority was delegated to Agent B and thereby cause Agent B to perform something neither agent was actually granted?

**ANSWER THE LAB DEFENDS**

NO. A caller/delegation claim is DATA. It does not mint authority. IDENTITY CLAIM != AUTHENTICATION. DELEGATION CLAIM != AUTHORIZATION. CALLER ID != GRANT. AGENT ID STRING != CRYPTOGRAPHIC IDENTITY.

```text
PRINCIPAL
       ↓
CALLER
       ↓
CALLEE
       ↓
DELEGATION CLAIM (DATA)
       ↓
CTRL-IDENTITY-001 OBSERVE
       ↓
REQUESTED CAPABILITY
       ↓
CTRL-MCP-001
       ↓
EXECUTION
```

**IDENTITY CLAIM IS DATA**

**DELEGATION CLAIM != AUTHORIZATION**

**REQUEST != GRANT** · **OBSERVE != ALLOW** · **ALLOW != EXECUTION** · **SPLUNK != ENFORCEMENT**

The lab knows identifiers such as principal.id, caller_agent_id, and callee_agent_id. That is **attribution**. **WHO AUTHENTICATED = NOT PROVEN / NOT MODELED**. Trust here is `untrusted_claim`. That label is not malice. **Authorization** is CTRL-MCP-001. **Execution** is handler start.

**LIVE vs REPLAY**

- **LIVE** — Attack Service mints a fresh run.id. Investigate in Splunk Search.
- **REPLAY** — Investigate specimen below is canonical validated evidence. It is not the LIVE run you just launched.

Schema **1.9.0** emitters. CTRL-IDENTITY-001 observes. CTRL-MCP-001 grants or denies the tool.

Canonical REPLAY Investigate specimen ids are on the cards below. They are not your LIVE run.id.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_flow",
        """
# Delegation path

```text
PRINCIPAL
     ↓
CALLER CLAIM
     ↓
CALLEE
     ↓
CTRL-IDENTITY-001 OBSERVE
     ↓
PRIVILEGED REQUEST
     ↓
CTRL-MCP-001
     ↓
HANDLER
```

The trust boundary is **before** the grant. A claim may shape a REQUEST. It does not become a GRANT. A + B != NEW AUTHORITY.
""",
        title="PATH",
    )
    add_md(
        "viz_learn_planes",
        """
# Seven evidence PLANES

1 PRINCIPAL — agentsec.principal.id. Attribution, not authentication.

2 CALLER / CALLEE — caller_agent_id and callee_agent_id.

3 DELEGATION CLAIM — claimed scope / tool / resource.

4 IDENTITY CLAIM TRUST — CTRL-IDENTITY-001 OBSERVE untrusted_claim.

5 TOOL REQUEST — lookup_customer_tier / customer:read / cust-001.

6 TOOL AUTHORIZATION — CTRL-MCP-001 ALLOW or DENY.

7 EXECUTION — mcp.started / handler count.

Do not collapse these into one agent identity result.
""",
        title="PLANES",
    )
    add_md(
        "viz_learn_ladder",
        """
# AgentSec is not only MCP or identity

identifier != authenticated identity

claim != grant

observe != allow

request != grant

allow != execution

**This lab: identity / delegation (INV-001 / INV-002 / INV-005)**

Prompt/Input · Tool Authorization · RAG · Memory · Goal Integrity

No OAuth. No OIDC. No JWT validation. No SPIFFE. No real A2A transport.
""",
        title="PROGRESSION",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**REPLAY specimen** · profile defended · mode BASELINE · lookup_policy handler **1** · lookup_customer_tier **0**

Launch **LIVE BASELINE** from [Attack Service]({ATTACK_URL}) when you want a fresh run.id. The table below is canonical REPLAY `{BASELINE_ID}`.

NORMAL claim lookup_policy / policy:read

principal `{PRINCIPAL}` · caller `{CALLER}` · callee `{CALLEE}`

request fingerprint `{BASELINE_HASH}`

CTRL-IDENTITY-001 **OBSERVE** `identity_claim_is_not_grant`

classification `untrusted_claim` — that is a label, not malice

lookup_policy handler 1 · lookup_customer_tier handler 0

Do **not** label this SAFE, TRUSTED, APPROVED, AUTHENTICATED, or BENIGN.

Zero suspicious follow-on behavior is an observation, not proof that the content is safe.

Validated: `{BASELINE_ID}`
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_rag",
        "ds_q_id_b",
        "What Happened? Q-AGENT-DELEGATION-AUTHORITY",
        cap_rag + " Expect OBSERVE, NORMAL hash, no_followon. Not SAFE.",
        no_data=EMPTY_ID,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_b",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect IDENTITY OBSERVE. Hop-1 CTRL-MCP-001 ALLOW tool_granted.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_baseline_exec",
        "ds_q_exec_b",
        "Q-MCP-EXECUTED",
        cap_exec + " Expect no privileged follow-on execution.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK

**INTENTIONALLY VULNERABLE LAB PROFILE** · mode ATTACK

**WHY ARE WE LAUNCHING THIS?**

To see whether a caller/delegation claim can mint a tool grant neither agent possesses. They must not. On this labeled vulnerable experiment, CTRL-MCP-001 fail-opens after IDENTITY OBSERVE.

**WHAT DOES THE ATTACKER CONTROL?**

The closed adversarial delegation fixture. Hash `{ATTACK_HASH}`. Not grants, profile, identity_verified, authenticated, or an A2A body via the browser.

**WHAT SHOULD HAPPEN IN THE VULNERABLE PROFILE?**

retrieve → CTRL-IDENTITY-001 **OBSERVE** → REQUEST `lookup_customer_tier` / `customer:read` → CTRL-MCP-001 **ALLOW** `vulnerable_profile_fail_open:caller_identity_derived_authority` → mcp.started → handler 1

**PREDICT BEFORE LAUNCH.** Then open Attack Service.

[Launch ATTACK (LIVE)]({ATTACK_URL})

Copy the fresh run.id. Wait until evidence is searchable. Investigate in Splunk Search. Studio tokens are **not** that LIVE id.

Tables on this tab are **REPLAY** canonical evidence (`{ATTACK_ID}`), not the LIVE run.

{DATA_NOT_AUTHORITY}
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_rag",
        "ds_q_id_a",
        "What Happened? Q-AGENT-DELEGATION-AUTHORITY",
        cap_rag + " Expect MALICIOUS hash, followon ALLOW overlay, mcp.completed_observed.",
        no_data=EMPTY_ID,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_a",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect OBSERVE then hop-1 ALLOW. Hop-1 ALLOW is not a server grant of the tool.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_attack_tool",
        "ds_q_tool_a",
        "Q-MCP-TOOL",
        cap_tool + " Expect hop-1 mcp.started for lookup_customer_tier.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_exec_a",
        "Q-MCP-EXECUTED",
        cap_exec + " Expect has_started=1 on follow-on. mcp.started != SUCCESS.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Use **Hunt** (defaults to BASELINE). Seven planes. Indexed structured fields only. No `_raw`. No dumped A2A JSON. Fingerprint + identifiers.

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_md(
        "viz_observe_planes",
        """
# Plane map

**PRINCIPAL** — applicant-web. Attribution, not authentication.

**CALLER / CALLEE** — advisor-005 / fulfillment-006

**DELEGATION CLAIM** — claimed scope vs coded grant

**IDENTITY CLAIM TRUST** — CTRL-IDENTITY-001 OBSERVE untrusted_claim

**TOOL REQUEST** — lookup_customer_tier / customer:read

**TOOL AUTHORIZATION** — CTRL-MCP-001 ALLOW or DENY

**EXECUTION** — mcp.started. Handler count is authoritative.

Labels in text: IDENTITY · HUNT · DETECTION · LIVE · OBSERVE · ALLOW · DENY
""",
        title="PLANES",
    )
    add_table(
        "viz_observe_seq",
        "ds_observe_seq",
        "IDENTITY + sequence (indexed fields)",
        cap_seq,
        no_data=EMPTY_SEQ,
    )
    add_table(
        "viz_observe_rag",
        "ds_q_id",
        "TRUST / INFLUENCE + AUTHORIZATION + EXECUTION — Q-AGENT-DELEGATION-AUTHORITY",
        cap_rag,
        no_data=EMPTY_ID,
    )
    add_table(
        "viz_observe_authz",
        "ds_q_authz",
        "AUTHORIZATION — Q-MCP-AUTHZ",
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

**Path B — Show solution (optional):** copyable SPL from existing Q-AGENT-DELEGATION-AUTHORITY / Q-MCP hunts, bound REPLAY table, explanation, limitations. Open it only after Path A. It is an answer key, not policy.

Investigate specimen is canonical **REPLAY**. Fresh LIVE run.id comes from Attack Service Search handoff. Studio tokens are not auto-bound.

Do not search until Attack Service reports **EVIDENCE READY** (or you have measured searchable events). HEC success is not ready.

Primary hunt: **Q-AGENT-DELEGATION-AUTHORITY**. Reuse Q-MCP-AUTHZ / Q-MCP-EXECUTED. No Q-A2A-WHO. **No DET-A2A.**

Do **not** hunt a regex for AGENT NOTE. Overlay reason is a lab artifact, not a production IOC.

This tab is a **stacked notebook**: Path A, then optional hints, then Path B. Custom browser scripts are not used.

{DATA_NOT_AUTHORITY}
""",
        title="STEP 4 HUNT",
    )

    inv_doc = json.loads(INV_PATH.read_text(encoding="utf-8"))
    hunt_investigations = [
        row for row in inv_doc["investigations"] if row.get("studio_tab", "HUNT") == "HUNT"
    ]
    hunt_files = {
        "Q-AGENT-DELEGATION-AUTHORITY": "Q-AGENT-DELEGATION-AUTHORITY.spl",
        "Q-MCP-AUTHZ": "Q-MCP-AUTHZ.spl",
        "Q-MCP-EXECUTED": "Q-MCP-EXECUTED.spl",
        "Q-MCP-TOOL": "Q-MCP-TOOL.spl",
        "Q-MCP-WHO": "Q-MCP-WHO.spl",
    }
    hunt_structure = [
        block("viz_hunt_md", 0, 0, FULL, 400),
    ]
    q_h, h1_h, h2_h, sol_h, tbl_h = 300, 160, 160, 520, 300
    y_cursor = 408
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
# DETECTION ANALYZED — NO NEW IDENTITY DETECTOR

No notable. **No DET-A2A.** This dashboard does **not** enable DET-MCP-001.

DET-MCP-001 detects **DENY then later mcp.started** for the same run.id + tool.

LIVE Phase 12C (MEASURED):

- BASELINE = 0 because there was no DENY
- ATTACK = 0 because the path was ALLOW — no DENY
- RETEST = 0 because DENY was respected — no later start

0 rows is **CORRECT**. 0 rows != **SAFE**.

Right table: **SIMULATED** `| makeresults`. **NOT INDEXED.** Not a LIVE identity attack. Not OBSERVED runtime.
""",
        title="STEP 5 DETECT",
    )
    add_md(
        "viz_detect_class",
        """
# Classification (Phase 12D)

untrusted identity/delegation claim → **CONTEXT** (CTRL-IDENTITY-001 OBSERVE)

identity string / caller_agent_id → **NOT AUTHENTICATION** (REJECT as detector)

claim + privileged request → **HUNT**

claim + ALLOW → not enough (REJECT as detector; overlay is labeled lab fail-open)

claim + execution → **HUNT** (handler count is authoritative)

DENY + later execution → **DETECTION** DET-MCP-001

rare privileged tool after a claim → **FUTURE** BEHAVIORAL

abnormal claim→tool sequence → **FUTURE** BEHAVIORAL / ML

Overlay reason REJECT as production. AGENT NOTE regex REJECT as production. No DET-A2A.
""",
        title="CONTEXT / HUNT / DETECTION / FUTURE",
    )
    add_table(
        "viz_detect_b",
        "ds_q_after_b",
        "DET-MCP-001 / Q-MCP-AFTER-DENY BASELINE",
        cap_after + " BASELINE 0: no DENY.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_a",
        "ds_q_after_a",
        "DET-MCP-001 / Q-MCP-AFTER-DENY ATTACK",
        cap_after + " ATTACK 0: ALLOW path.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_r",
        "ds_q_after_r",
        "DET-MCP-001 / Q-MCP-AFTER-DENY RETEST",
        cap_after + " RETEST 0: DENY respected.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_sim",
        "ds_det_mcp_001_sim",
        "DET-MCP-001-POSITIVE-CONTROL (SIMULATED)",
        "Always one fixture row labeled SIMULATED. DENY then mcp.started. Do not treat as a live incident.",
        no_data="SIMULATED search returned no fixture row. Re-check DET-MCP-001-POSITIVE-CONTROL.spl (makeresults).",
    )
    add_md(
        "viz_detect_future",
        """
# FUTURE — NOT IMPLEMENTED

Behavioral analytics may later rank hunts:

- rare privileged tool after an untrusted claim
- new claim→tool sequence
- novel claimed scope vs coded grant mismatch
- burst of caller identity strings before a sensitive tool
- per-agent behavioral deviation

Possible later tools: Splunk statistical SPL · Splunk MLTK · Cisco Time Series Model / CDTSM where appropriate.

**ANOMALY != INCIDENT**

**ML MAY PRIORITIZE INVESTIGATION.**

**ML MUST NOT GRANT OR DENY AUTHORITY.**

Do not treat this panel as a detector. No MLTK model is running here.
""",
        title="FUTURE — NOT IMPLEMENTED",
    )

    add_md(
        "viz_defend",
        f"""
# DEFEND

Identity/delegation claims are **inputs**. Server-owned policy determines actual authority. Delegation must not amplify authority beyond the legitimate grant model.

Not the defense: block all delegation · trust agent names · trust a caller-provided role · trust an LLM · trust Splunk · trust an identity string · trust a scanner.

```text
DELEGATION CLAIM
        ↓
CTRL-IDENTITY-001 OBSERVE
        ↓
REQUEST lookup_customer_tier
        ↓
CTRL-MCP-001
        ↓
DENY tool_not_granted
        ↓
HANDLER DOES NOT START
```

CTRL-IDENTITY-001 stays OBSERVE. Classification is not the grant. Splunk does not DENY the tool. The runtime control does.

{DATA_NOT_AUTHORITY}
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_defend_evidence",
        """
# What actually changed the RETEST

Same IDENTITY CLAIM. Same DELEGATION CLAIM. Same PRIVILEGED REQUEST. Different **server-owned experiment/authorization configuration**.

What does **not** change: principal, caller, callee, claimed scope, requested tool, requested scope, requested resource, request fingerprint, IDENTITY OBSERVE, Splunk search.

Defended CTRL-MCP-001 DENY `tool_not_granted`. Runtime handler count 0.

Do not claim an identity string or a scanner decided the grant. Do not treat Splunk as independent non-execution proof. Do not teach "trust the caller id and the problem is solved."
""",
        title="INV-002",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

**LIVE RETEST** is launched from [Attack Service]({ATTACK_URL}). Same privileged claim. Different ExperimentContext (defended). Fresh run.id.

Tables on this tab are **REPLAY** `{RETEST_ID}`, not your LIVE id.

SAME principal `{PRINCIPAL}`

SAME caller `{CALLER}`

SAME callee `{CALLEE}`

SAME request fingerprint `{ATTACK_HASH}`

SAME follow-on request `lookup_customer_tier`

SAME requested scope `customer:read`

Then: CTRL-IDENTITY-001 still **OBSERVE**. CTRL-MCP-001 **DENY** `tool_not_granted`

handler count = **authoritative**

missing indexed start = **corroboration**

Do not claim RETEST makes every delegation attack prevented. Do not treat Splunk as independent non-execution proof.

```text
claim → OBSERVE → REQUEST → DENY → no START
```
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_rag",
        "ds_q_id_r",
        "What Happened? Q-AGENT-DELEGATION-AUTHORITY",
        cap_rag + " Expect SAME MALICIOUS hash as ATTACK, followon DENY, no_indexed_followon_execution_event.",
        no_data=EMPTY_ID,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_r",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect hop-1 DENY tool_not_granted.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_r",
        "Q-MCP-TOOL",
        "Q-MCP-TOOL. No indexed hop-1 mcp.started observed. That is Splunk corroboration. Runtime handler count = 0 is authoritative.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_exec_r",
        "Q-MCP-EXECUTED",
        cap_exec + " Expect follow-on has_started=0.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

**SAME IDENTITY CLAIM. SAME DELEGATION CLAIM. SAME PRIVILEGED REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

ATTACK and RETEST share (request fingerprint, not hop-1 MCP hash):

- principal `{PRINCIPAL}`
- caller `{CALLER}`
- callee `{CALLEE}`
- request fingerprint `{ATTACK_HASH}`
- follow-on tool `lookup_customer_tier`
- requested scope `customer:read`

**DIFFERENT:** experiment/profile · CTRL-MCP-001 decision · execution · handler count · run.id

Cards below are **REPLAY** specimens. Compare your LIVE ATTACK vs LIVE RETEST in Splunk Search.

Malicious-looking content is not authorization bypass. Authorization bypass is not automatically successful execution. One RETEST is not universal resistance.
""",
        title="BEFORE / AFTER",
    )
    add_md(
        "viz_cmp_card_base",
        f"""
# BASELINE

**Profile:** defended · **Mode:** BASELINE · **REPLAY specimen**

- Principal: `{PRINCIPAL}`
- Caller: `{CALLER}`
- Callee: `{CALLEE}`
- Fingerprint (full):

{fingerprint_block(BASELINE_HASH)}

- Trust: untrusted_claim
- Control: CTRL-IDENTITY-001 **OBSERVE**
- Request: `lookup_policy` / `policy:read`
- Authz: CTRL-MCP-001 **ALLOW** tool_granted
- Execution: lookup_policy handler **1** · lookup_customer_tier **0**

Do not label SAFE.

Validated: `{BASELINE_ID}`
""",
        title="BASELINE",
    )
    add_md(
        "viz_cmp_card_atk",
        f"""
# ATTACK

**INTENTIONALLY VULNERABLE LAB PROFILE** · **REPLAY specimen**

- Principal: `{PRINCIPAL}`
- Caller: `{CALLER}`
- Callee: `{CALLEE}`
- Fingerprint (full):

{fingerprint_block(ATTACK_HASH)}

- Trust: untrusted_claim · **OBSERVE**
- Request: `lookup_customer_tier` / `customer:read`
- Authz: CTRL-MCP-001 **ALLOW** overlay
- Execution: mcp.started + mcp.completed (handler **1**)

The identity claim did not grant the tool. Overlay is labeled vulnerable.

Validated: `{ATTACK_ID}`
""",
        title="ATTACK",
    )
    add_md(
        "viz_cmp_card_rt",
        f"""
# RETEST

**Profile:** defended · **Mode:** RETEST · **REPLAY specimen**

- Principal: `{PRINCIPAL}`
- Caller: `{CALLER}`
- Callee: `{CALLEE}`
- Fingerprint (full):

{fingerprint_block(ATTACK_HASH)}

- Trust: untrusted_claim · **OBSERVE**
- Request: `lookup_customer_tier` / `customer:read`
- Authz: CTRL-MCP-001 **DENY** `tool_not_granted`
- Execution: no mcp.started (handler **0**)

SAME hash as ATTACK.

Validated: `{RETEST_ID}`
""",
        title="RETEST",
    )
    add_table(
        "viz_cmp_base",
        "ds_q_id_b",
        "BASELINE Q-AGENT-DELEGATION-AUTHORITY",
        cap_rag + " Expect no_followon.",
        no_data=EMPTY_ID,
    )
    add_table(
        "viz_cmp_atk",
        "ds_q_id_a",
        "ATTACK Q-AGENT-DELEGATION-AUTHORITY",
        cap_rag + " Expect SAME MALICIOUS hash as RETEST plus ALLOW.",
        no_data=EMPTY_ID,
    )
    add_table(
        "viz_cmp_rt",
        "ds_q_id_r",
        "RETEST Q-AGENT-DELEGATION-AUTHORITY",
        cap_rag + " Expect SAME MALICIOUS hash as ATTACK plus DENY.",
        no_data=EMPTY_ID,
    )

    add_md(
        "viz_prove",
        f"""
# PROVE

Evidence hierarchy. Splunk does not manufacture runtime truth.

```text
RUNTIME  →  LOCAL EVIDENCE  →  OTLP  →  SPLUNK  →  HUNT  →  SECURITY EVIDENCE
```

1. **RUNTIME.** Handler counts. Authoritative for execution / non-execution. {RUNTIME_AUTH}
2. **LOCAL.** artifacts pack / events.jsonl
3. **EXPORT.** export.json (`otlp.ok` is not Splunk success)
4. **SPLUNK.** Completeness = local count vs dc(_raw)
5. **SEARCH.** Q-AGENT-DELEGATION-AUTHORITY. Zero rows follow no-data semantics.
6. **DETECTION.** DET-MCP-001: 0/0/0. Silent is correct. Not SAFE. **NO NEW IDENTITY DETECTOR.**

LIVE A/B/C **packs** are historical OBSERVED/MEASURED **REPLAY**. Your Attack Service launches are **LIVE** with new run.ids. DETECT SIMULATED table is **SIMULATED**.

**WHAT WE CAN PROVE**

**YOU JUST LEARNED** — IDENTITY CLAIM != AUTHENTICATION. DELEGATION CLAIM != AUTHORIZATION. CTRL-IDENTITY-001 OBSERVE. CTRL-MCP-001 is the tool PDP.

**THIS CONNECTS TO** — the integrated capstone, where you must decide whether identity is even required to explain an incident.

**NEXT** — Confused Deputy (REPLAY) if you have not separated deputy ambient authority from identity claims, then Lending Assistant Investigation (LIVE capstone).

- Principal / caller / callee identifiers present in telemetry.
- The delegation claim and request fingerprint.
- CTRL-IDENTITY-001 classified the claim as untrusted (OBSERVE identity_claim_is_not_grant).
- The requested privileged capability.
- CTRL-MCP-001 decision.
- Handler execution / non-execution (runtime authoritative).
- Same request across ATTACK and RETEST.

**WHAT WE CAN CORROBORATE**

- Splunk copy of those fields when dc(_raw) matches local count.
- Absence of mcp.started on a complete RETEST copy.

**WHAT WE CANNOT PROVE / NOT PROVEN**

- Cryptographic caller identity. OAuth. OIDC. SPIFFE. Human identity. Tenant identity.
- That every delegation attack is prevented.
- Prevention from an empty search alone.

**INCORRECT CLAIMS**

- caller_agent_id proves authentication.
- Delegation claim grants authority.
- CTRL-IDENTITY-001 granted the tool.
- Splunk denied the request.
- Agent A + Agent B automatically inherit the union of imagined permissions.
- Treating DET-MCP-001 zero rows as SAFE.
- Treating missing `mcp.started` as independent prevention.

Authoritative: runtime decision + handler count. Corroborative: Splunk. Splunk is not enforcement.

Knowledge check:

1. Who is the principal, caller, and callee?
2. Does caller_agent_id prove authentication?
3. What authority is being claimed?
4. Why is the claim not a grant?
5. What did CTRL-IDENTITY-001 conclude?
6. What authority did the agents really possess?
7. What privileged request was formed?
8. Which control authorized or denied the tool?
9. Did lookup_customer_tier execute on ATTACK?
10. Did lookup_customer_tier execute on RETEST?
11. What stayed the same across ATTACK and RETEST?
12. What changed?
13. Why is OBSERVE not ALLOW?
14. Why is Splunk not the PDP?
15. Why are identity/delegation and tool authorization separate boundaries?
16. Why is DET-MCP-001 empty?
17. Does DET-MCP-001 silence mean SAFE?
18. What does A + B != NEW AUTHORITY mean?
19. Where could behavioral analytics help later?
20. Can ML grant or deny authority?

Validated: BASELINE `{BASELINE_ID}` · ATTACK `{ATTACK_ID}` · RETEST `{RETEST_ID}`.

BASELINE fingerprint `{BASELINE_HASH}`

ATTACK/RETEST fingerprint `{ATTACK_HASH}` (ATTACK and RETEST share this hash)

No DET-A2A. Schema 1.9.0 emitters. No OAuth. No OIDC. No SPIFFE. No real A2A transport.
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_rag",
        "ds_q_id",
        "What Happened? Q-AGENT-DELEGATION-AUTHORITY (Hunt run.id)",
        cap_rag,
        no_data=EMPTY_ID,
    )

    definition = {
        "title": "Agent Identity / Delegation",
        "description": (
            "WS-AGENT-DELEGATION Dashboard Studio workshop. Reuses validated "
            "Q-AGENT-DELEGATION-AUTHORITY and Q-MCP investigation SPL. Saved search "
            "DET-MCP-001 is packaged disabled; this dashboard does not enable it. "
            "No DET-A2A. Splunk does not ALLOW or DENY a tool."
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
                        block("viz_learn", 0, 0, FULL, 780),
                        block("viz_learn_flow", 0, 780, THIRD, 500),
                        block("viz_learn_planes", THIRD, 780, THIRD, 500),
                        block("viz_learn_ladder", THIRD * 2, 780, THIRD, 500),
                    ],
                    1300,
                ),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 400),
                        block("viz_baseline_rag", 0, 400, FULL, 280),
                        block("viz_baseline_authz", 0, 680, HALF, 260),
                        block("viz_baseline_exec", HALF, 680, HALF, 260),
                    ],
                    960,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 640),
                        block("viz_attack_rag", 0, 640, FULL, 280),
                        block("viz_attack_authz", 0, 920, HALF, 260),
                        block("viz_attack_tool", HALF, 920, HALF, 260),
                        block("viz_attack_exec", 0, 1180, FULL, 260),
                    ],
                    1460,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, HALF, 280),
                        block("viz_observe_planes", HALF, 0, HALF, 280),
                        block("viz_observe_seq", 0, 280, FULL, 360),
                        block("viz_observe_rag", 0, 640, FULL, 280),
                        block("viz_observe_authz", 0, 920, HALF, 260),
                        block("viz_observe_exec", HALF, 920, HALF, 260),
                    ],
                    1200,
                ),
                "layout_hunt": layout(hunt_structure, y_cursor + 40, display="fit-to-width"),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, HALF, 380),
                        block("viz_detect_class", HALF, 0, HALF, 380),
                        block("viz_detect_b", 0, 380, THIRD, 280),
                        block("viz_detect_a", THIRD, 380, THIRD, 280),
                        block("viz_detect_r", THIRD * 2, 380, THIRD, 280),
                        block("viz_detect_sim", 0, 660, HALF, 280),
                        block("viz_detect_future", HALF, 660, HALF, 280),
                    ],
                    960,
                ),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 480),
                        block("viz_defend_evidence", 0, 480, FULL, 320),
                    ],
                    820,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 560),
                        block("viz_retest_rag", 0, 560, FULL, 280),
                        block("viz_retest_authz", 0, 840, HALF, 260),
                        block("viz_retest_tool", HALF, 840, HALF, 260),
                        block("viz_retest_exec", 0, 1100, FULL, 260),
                    ],
                    1380,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 400),
                        block("viz_cmp_card_base", 0, 400, THIRD, 540),
                        block("viz_cmp_card_atk", THIRD, 400, THIRD, 540),
                        block("viz_cmp_card_rt", THIRD * 2, 400, THIRD, 540),
                        block("viz_cmp_base", 0, 960, THIRD, 280),
                        block("viz_cmp_atk", THIRD, 960, THIRD, 280),
                        block("viz_cmp_rt", THIRD * 2, 960, THIRD, 280),
                    ],
                    1260,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 1200),
                        block("viz_prove_rag", 0, 1200, FULL, 280),
                    ],
                    1500,
                ),
            },
        },
        "applicationProperties": {
            "collapseNavigation": False,
            "downsampleVisualizations": False,
        },
    }
    add_md(
        "viz_ws_mission",
        f"""
# MISSION · IDENTITY / DELEGATION AUTHORITY

**Question:** What identity and delegation are merely claimed, what authority is evaluated, and what authentication is not modeled?

Selected specimen: `$run_id$` · canonical **REPLAY** until replaced with a fresh LIVE run.id in Splunk Search.

```text
CLAIM → DELEGATION → CLAIM CLASSIFICATION → PRIVILEGED REQUEST → TOOL AUTHORIZATION → EXECUTION
```

**CLAIMED:** principal `{PRINCIPAL}` · caller `{CALLER}` · callee `{CALLEE}` · delegation request

**ESTABLISHED IN LAB:** closed request fingerprint · coded policy · control decisions · handler count

**NOT MODELED:** cryptographic authentication · OAuth/OIDC · signed delegation · production A2A identity

[Launch a fresh LIVE experiment]({ATTACK_URL})
""",
        title="MISSION",
    )
    add_md(
        "viz_ws_investigate",
        f"""
# INVESTIGATE · PATH A

Establish claim provenance, requested authority, the control that decides authority, and what actually executed.

**Starting search**

```spl
index=agentsec_telemetry run.id="$run_id$"
| sort 0 agentsec.sequence
```

Use the questions and progressive hints below. Do not treat identity strings as authentication or CTRL-IDENTITY-001 OBSERVE as tool authorization.

[Open Splunk Search]({SEARCH_URL})
""",
        title="PATH A · QUESTION AND STARTING SEARCH",
    )
    add_md(
        "viz_ws_evidence",
        """
# EVIDENCE · CLAIM, AUTHORITY, EXECUTION

```text
CLAIMED PRINCIPAL / CALLER / CALLEE
        → untrusted delegation claim
        → CTRL-IDENTITY-001 OBSERVE
        → lookup_customer_tier request
        → CTRL-MCP-001 ALLOW or DENY
        → runtime handler count
```

The identity control classifies the claim. CTRL-MCP-001 is the tool PDP. Runtime handler count is authoritative for execution; a complete Splunk copy corroborates it.

**WHO AUTHENTICATED = NOT PROVEN / NOT MODELED**
""",
        title="EVIDENCE",
    )
    add_md(
        "viz_ws_answers",
        """
# PATH B · ANSWERS

Optional review after Path A. Existing validated SPL, expected shapes, interpretation, comparisons, proof limits, and REPLAY specimens follow.

An identity claim is not authentication. A delegation claim is not authorization. Splunk is not either control and missing telemetry is not prevention.
""",
        title="PATH B · ANSWERS",
    )

    mission_ids = ["viz_ws_mission"]
    investigate_ids = ["viz_ws_investigate"] + [
        viz_id
        for viz_id in visualizations
        if viz_id.startswith("viz_i") and viz_id.endswith(("_q", "_h1", "_h2"))
    ]
    evidence_ids = ["viz_ws_evidence"] + [
        viz_id for viz_id in visualizations if viz_id.startswith("viz_i") and "_tbl" in viz_id
    ]
    used = set(mission_ids + investigate_ids + evidence_ids + ["viz_ws_answers"])
    answer_ids = ["viz_ws_answers"] + [viz_id for viz_id in visualizations if viz_id not in used]

    def stacked(ids: list[str]) -> dict:
        structure = []
        y = 0
        for viz_id in ids:
            if visualizations[viz_id]["type"] == "splunk.table":
                height = 300
            elif viz_id == "viz_ws_mission":
                height = 360
            elif viz_id in {"viz_ws_investigate", "viz_ws_evidence"}:
                height = 340
            elif viz_id.startswith("viz_i") and viz_id.endswith(("_h1", "_h2")):
                height = 220
            elif viz_id.startswith("viz_i") and viz_id.endswith("_q"):
                height = 380
            else:
                height = 620
            structure.append(block(viz_id, 0, y, FULL, height))
            y += height
        return layout(structure, y + 20, display="fit-to-width")

    definition["layout"]["tabs"] = {
        "options": {"barPosition": "top"},
        "items": [
            {"layoutId": "layout_mission", "label": "MISSION"},
            {"layoutId": "layout_investigate", "label": "INVESTIGATE"},
            {"layoutId": "layout_evidence", "label": "EVIDENCE"},
            {"layoutId": "layout_answers", "label": "PATH B · ANSWERS"},
        ],
    }
    definition["layout"]["layoutDefinitions"] = {
        "layout_mission": stacked(mission_ids),
        "layout_investigate": stacked(investigate_ids),
        "layout_evidence": stacked(evidence_ids),
        "layout_answers": stacked(answer_ids),
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
        "  <label>Agent Identity / Delegation</label>\n"
        "  <description>LIVE vs REPLAY Agent Identity / Delegation. LAB-AGENT-DELEGATION-001. Splunk does not ALLOW or DENY.</description>\n"
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
