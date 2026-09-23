#!/usr/bin/env python3
"""Build the LAB-RAG-CONTEXT Dashboard Studio workshop.

Reuses validated Q-RAG-CONTEXT-AUTHORITY and Q-MCP-* hunts. Bind tokens only.
DET-MCP-001.spl is not modified. No DET-RAG. No Q-RAG-INJECTION.
Retrieved content does not feed CTRL-MCP-001 except via the labeled lab overlay.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RAG_DIR = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_rag_context.xml"
)
INV_PATH = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "investigations.json"
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
ATTACK_URL = "http://127.0.0.1:5001/labs/LAB-RAG-CONTEXT"

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

BASELINE_ID = "51f70fb9-994e-4dd4-9b36-cac6fb1e8232"
ATTACK_ID = "3a43d24f-9281-42f6-8375-1fb2efaa80ac"
RETEST_ID = "bea97bae-491b-4b36-b52f-1417d2bad01b"
NORMAL_DOC = "doc.lending-policy.normal"
MALICIOUS_DOC = "doc.lending-policy.malicious"
NORMAL_HASH = "sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e"
MALICIOUS_HASH = "sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef"


def fingerprint_block(h: str) -> str:
    """Split sha256:<64 hex> so Studio markdown can show the full digest in a 4-col card."""
    algo, digest = h.split(":", 1)
    return f"{algo}:\n{digest[:32]}\n{digest[32:]}"
PROVENANCE = "rag.local.fixture"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_EVENT = (
    "No indexed event matched this evidence question. That is not SAFE, not TRUSTED, "
    "not blocked, not prevented, and not proof there was no attack."
)
EMPTY_RAG = (
    "Q-RAG-CONTEXT-AUTHORITY returned zero rows. Zero rows means no indexed "
    "CTRL-RAG-CONTEXT-001 for this run.id. That is not SAFE, not DENY, and not "
    "proof the document was trusted."
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
    "INV-002: retrieved content cannot independently authorize privileged actions. "
    "RETRIEVED CONTENT IS DATA. REQUEST != GRANT. OBSERVE != ALLOW."
)

SPL_TEACHING = {
    "Q-RAG-CONTEXT-AUTHORITY": (
        "- Reconstructs retrieve → classification → follow-on request → MCP decision.\n"
        "- Document fingerprint is CONTEXT-001 content.hash, not the hop-1 request hash.\n"
        "- OBSERVE is not ALLOW. Follow-on tool is a REQUEST."
    ),
    "Q-MCP-AUTHZ": (
        "- Control.decision rows only. Hop 0 is CONTEXT-001. Hop 1 is CTRL-MCP-001 when a follow-on exists.\n"
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
        "- Principal / agent / tool identity on control.decision."
    ),
}

TABLE_BIND = {
    "RAG-I1-FIND-RETRIEVED-CONTEXT": [
        (
            "ds_q_rag",
            "Q-RAG-CONTEXT-AUTHORITY (REPLAY specimen)",
            "Path B retrieve row. Fresh LIVE run.id is Search, not this table.",
        ),
        (
            "ds_q_who",
            "Q-MCP-WHO (REPLAY)",
            "Identity row. CONTEXT-001 may appear without mcp.method.name.",
        ),
    ],
    "RAG-I2-TRUST-CLASSIFICATION": [
        (
            "ds_q_rag",
            "Q-RAG-CONTEXT-AUTHORITY trust columns (REPLAY)",
            "Expect OBSERVE retrieved_context_is_data. untrusted_data is not malice.",
        )
    ],
    "RAG-I3-INFLUENCE": [
        (
            "ds_q_rag",
            "Q-RAG-CONTEXT-AUTHORITY follow-on (REPLAY)",
            "BASELINE: no follow-on. ATTACK/RETEST: lookup_customer_tier request.",
        )
    ],
    "RAG-I4-WHO-AUTHORIZED": [
        (
            "ds_q_authz",
            "Q-MCP-AUTHZ (REPLAY specimen)",
            "Hop 0 OBSERVE. Hop 1 is the tool PDP. Splunk did not decide.",
        )
    ],
    "RAG-I5-DID-HANDLER-START": [
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
    rag = RAG_DIR / name
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


def load_spl(name: str, *, rag: bool = False) -> str:
    directory = RAG_DIR if rag else SEARCH_DIR
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
| eval document_id=mvindex(mvdedup('agentsec.rag.context.document.id'),0)
| eval content_hash=mvindex(mvdedup('agentsec.content.hash'),0)
| eval provenance=mvindex(mvdedup('agentsec.rag.context.provenance'),0)
| eval context_trust=mvindex(mvdedup('agentsec.rag.context.trust'),0)
| eval preview=mvindex(mvdedup('agentsec.content.preview'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| table sequence, run_id, event_name, hop, control_id, decision, reason, document_id, content_hash, provenance, context_trust, preview, tool, requested_scope, allowed_scope
| sort sequence"""


def build() -> dict:
    q_rag = bind_run_id(load_spl("Q-RAG-CONTEXT-AUTHORITY.spl", rag=True), "run_id")
    q_who = bind_run_id(load_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_rag_b = bind_literal(load_spl("Q-RAG-CONTEXT-AUTHORITY.spl", rag=True), BASELINE_ID)
    q_rag_a = bind_literal(load_spl("Q-RAG-CONTEXT-AUTHORITY.spl", rag=True), ATTACK_ID)
    q_rag_r = bind_literal(load_spl("Q-RAG-CONTEXT-AUTHORITY.spl", rag=True), RETEST_ID)
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
            search_ds("ds_q_rag", "Q-RAG-CONTEXT-AUTHORITY", q_rag),
            search_ds("ds_q_who", "Q-MCP-WHO", q_who),
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_rag_b", "Q-RAG-CONTEXT-AUTHORITY BASELINE", q_rag_b),
            search_ds("ds_q_rag_a", "Q-RAG-CONTEXT-AUTHORITY ATTACK", q_rag_a),
            search_ds("ds_q_rag_r", "Q-RAG-CONTEXT-AUTHORITY RETEST", q_rag_r),
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
            search_ds("ds_observe_seq", "RAG observe sequence", observe_sequence_spl("run_id")),
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
        "Q-RAG-CONTEXT-AUTHORITY. Reconstructs retrieval classification, document "
        "fingerprint, follow-on request, authorization, and indexed execution "
        "observation. derived_authority is a lab display helper, not a production IOC. "
        "Do not hunt AGENT NOTE with a regex."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision rows. CONTEXT-001 OBSERVE is classification, "
        "not a grant. Hop-1 CTRL-MCP-001 is authorization. executed on the control "
        "row is not handler execution."
    )
    cap_tool = (
        "Q-MCP-TOOL. Empty tool on CONTEXT-001 is observation, not lookup_policy. "
        "Zero mcp.started rows is not automatically DENY."
    )
    cap_exec = (
        "Q-MCP-EXECUTED. Read has_started and execution_state for whether the "
        "handler began. " + ALLOW_NOT_EXEC
    )
    cap_who = (
        "Q-MCP-WHO. Principal / agent identity. CONTEXT-001 may appear without "
        "mcp.method.name. That is retrieval observation, not a tool grant."
    )
    cap_seq = (
        "Ordered control then mcp.* events with hop.index, sequence, document id, "
        "hash, and bounded preview. Full documents are not shown. This is a Studio "
        "view of indexed fields, not a new hunt file."
    )
    cap_after = (
        "Q-MCP-AFTER-DENY. Hunt form of DET-MCP-001. LIVE RAG specimens: 0 rows. "
        "Zero rows is CORRECT and is not SAFE."
    )

    add_md(
        "viz_learn",
        f"""
# RAG / Retrieved Context

**QUESTION**

Can retrieved content cause an agent to acquire authority that server-owned policy did not grant?

**ANSWER THE LAB DEFENDS**

NO. Retrieved content may influence reasoning and may cause a REQUEST. It cannot mint tools, scopes, resources, identity, delegation, approvals, profiles, or authorization configuration.

```text
RETRIEVED CONTENT
       ↓
UNTRUSTED DATA
       ↓
MAY INFLUENCE REQUEST
       ↓
SERVER AUTHORIZATION (CTRL-MCP-001)
       ↓
EXECUTION
```

**RETRIEVED CONTENT IS DATA**

**RETRIEVED CONTENT != AUTHORITY**

**REQUEST != GRANT** · **OBSERVE != ALLOW** · **ALLOW != EXECUTION** · **SPLUNK != ENFORCEMENT**

A **retriever** returns a **document/chunk** with **provenance** (source identity, not trust). **Trust** here is the label `untrusted_data`. That label is not malice. The document may influence **prompt/context**. **Authorization** is CTRL-MCP-001. **Execution** is handler start. **Telemetry** is the copy you hunt in Splunk.

**LIVE vs REPLAY**

- **LIVE** — Attack Service mints a fresh run.id. Investigate in Splunk Search.
- **REPLAY** — Investigate specimen below is canonical validated evidence. It is not the LIVE run you just launched.

Schema **1.9.0** emitters. CTRL-RAG-CONTEXT-001 observes. CTRL-MCP-001 grants or denies the tool.

Canonical REPLAY ids: BASELINE `{BASELINE_ID}` · ATTACK `{ATTACK_ID}` · RETEST `{RETEST_ID}`

NORMAL `{NORMAL_DOC}`

{fingerprint_block(NORMAL_HASH)}

MALICIOUS `{MALICIOUS_DOC}`

{fingerprint_block(MALICIOUS_HASH)}

Provenance `{PROVENANCE}` is source identity. Provenance is not trust. Known knowledge base is not authorization.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_flow",
        """
# Retrieval path

```text
USER QUESTION
     ↓
RETRIEVER
     ↓
DOCUMENT / CHUNK
     ↓
AGENT CONTEXT
     ↓
AGENT MAY FORM REQUEST
     ↓
AUTHORIZATION CONTROL
     ↓
HANDLER
```

The trust boundary is **before** the grant. Retrieved bytes may shape a REQUEST. They do not become a GRANT.
""",
        title="PATH",
    )
    add_md(
        "viz_learn_planes",
        """
# Four evidence planes

1 RETRIEVAL — document.id, content.hash, provenance, run.id, sequence. Label: CONTEXT.

2 TRUST / INFLUENCE — CTRL-RAG-CONTEXT-001 OBSERVE, untrusted_data, follow-on REQUEST. Label: CONTEXT / HUNT.

3 AUTHORIZATION — CTRL-MCP-001 ALLOW or DENY. Label: DETECTION only if DENY then later start.

4 EXECUTION — mcp.started / completed / failed. Handler count is authoritative.

Do not collapse these into one RAG-attack event.
""",
        title="PLANES",
    )
    add_md(
        "viz_learn_ladder",
        """
# AgentSec is not only MCP or RAG

retrieval provenance != content trust

content trust != authorization

request != grant

authorization != execution

**This lab: retrieved context (INV-002)**

Prompt/Input · Tool Authorization · later: Persistent Memory

Memory and identity workshops exist later in the curriculum. This lesson is RAG only. No embeddings. No A2A transport. No rug-pull.
""",
        title="PROGRESSION",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**REPLAY specimen** · profile defended · mode BASELINE · handler **0**

Launch **LIVE BASELINE** from [Attack Service]({ATTACK_URL}) when you want a fresh run.id. The table below is canonical REPLAY `{BASELINE_ID}`.

NORMAL document `{NORMAL_DOC}`

document.id `{NORMAL_DOC}`

content.hash `{NORMAL_HASH}`

provenance `{PROVENANCE}` — source identity, not trust

CTRL-RAG-CONTEXT-001 **OBSERVE** `retrieved_context_is_data`

classification `untrusted_data` — that is a label, not malice

no privileged follow-on

Do **not** label this SAFE, TRUSTED, APPROVED, or BENIGN.

Zero suspicious follow-on behavior is an observation, not proof that the content is safe.

Validated: `{BASELINE_ID}`
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_rag",
        "ds_q_rag_b",
        "What Happened? Q-RAG-CONTEXT-AUTHORITY",
        cap_rag + " Expect OBSERVE, NORMAL hash, no_followon. Not SAFE.",
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_b",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect CONTEXT-001 OBSERVE. No hop-1 CTRL-MCP-001.",
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

To see whether malicious retrieved bytes can mint a tool grant. They must not. On this labeled vulnerable experiment, CTRL-MCP-001 fail-opens after the same OBSERVE.

**WHAT DOES THE ATTACKER CONTROL?**

The closed malicious fixture (`{MALICIOUS_DOC}`). Hash `{MALICIOUS_HASH}`. Not grants, profile, trust labels, or document body via the browser.

**WHAT SHOULD HAPPEN IN THE VULNERABLE PROFILE?**

retrieve → CTRL-RAG-CONTEXT-001 **OBSERVE** → REQUEST `lookup_customer_tier` / `customer:read` → CTRL-MCP-001 **ALLOW** `vulnerable_profile_fail_open:retrieved_context_derived_authority` → mcp.started → handler 1

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
        "ds_q_rag_a",
        "What Happened? Q-RAG-CONTEXT-AUTHORITY",
        cap_rag + " Expect MALICIOUS hash, followon ALLOW overlay, mcp.completed_observed.",
        no_data=EMPTY_RAG,
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

Use **Hunt** (defaults to BASELINE). Four planes. Indexed structured fields only. No `_raw`. No full retrieved document. Hash + bounded preview.

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_md(
        "viz_observe_planes",
        """
# Plane map

**RETRIEVAL** — document.id, content.hash, provenance, sequence

**TRUST / INFLUENCE** — CTRL-RAG-CONTEXT-001 OBSERVE, untrusted_data, follow-on REQUEST

**AUTHORIZATION** — CTRL-MCP-001 ALLOW or DENY, reason, requested vs coded allowed scope

**EXECUTION** — mcp.started / completed / failed. Handler count is authoritative.

Labels in text: CONTEXT · HUNT · DETECTION · LIVE · OBSERVE · ALLOW · DENY
""",
        title="PLANES",
    )
    add_table(
        "viz_observe_seq",
        "ds_observe_seq",
        "RETRIEVAL + sequence (indexed fields)",
        cap_seq,
        no_data=EMPTY_SEQ,
    )
    add_table(
        "viz_observe_rag",
        "ds_q_rag",
        "TRUST / INFLUENCE + AUTHORIZATION + EXECUTION — Q-RAG-CONTEXT-AUTHORITY",
        cap_rag,
        no_data=EMPTY_RAG,
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

**Path B — Show solution (optional):** copyable SPL from existing Q-RAG / Q-MCP hunts, bound REPLAY table, explanation, limitations. Open it only after Path A. It is an answer key, not policy.

Investigate specimen is canonical **REPLAY**. Fresh LIVE run.id comes from Attack Service Search handoff. Studio tokens are not auto-bound.

Do not search until Attack Service reports **EVIDENCE READY** (or you have measured searchable events). HEC success is not ready.

Primary hunt: **Q-RAG-CONTEXT-AUTHORITY**. Reuse Q-MCP-AUTHZ / Q-MCP-EXECUTED. No Q-RAG-INJECTION. **No DET-RAG.**

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
        "Q-RAG-CONTEXT-AUTHORITY": "Q-RAG-CONTEXT-AUTHORITY.spl",
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
# DETECTION ANALYZED — NO NEW RAG DETECTOR

No notable. **No DET-RAG.** This dashboard does **not** enable DET-MCP-001.

DET-MCP-001 detects **DENY then later mcp.started** for the same run.id + tool.

LIVE Phase 10C (MEASURED):

- BASELINE = 0 because there was no DENY
- ATTACK = 0 because the path was ALLOW — no DENY
- RETEST = 0 because DENY was respected — no later start

0 rows is **CORRECT**. 0 rows != **SAFE**.

Right table: **SIMULATED** `| makeresults`. **NOT INDEXED.** Not a LIVE RAG attack. Not OBSERVED runtime.
""",
        title="STEP 5 DETECT",
    )
    add_md(
        "viz_detect_class",
        """
# Classification (Phase 10D)

untrusted retrieval → **CONTEXT**

instruction-like text → **HUNT** / weak specificity (REJECT as detector)

retrieval + privileged request → **HUNT**

retrieval + ALLOW → not enough (REJECT as detector)

retrieval + execution → **HUNT** (not unauthorized without a grant snapshot)

DENY + later execution → **DETECTION** DET-MCP-001

rare tool after retrieval → **FUTURE** BEHAVIORAL

abnormal retrieve→tool sequence → **FUTURE** BEHAVIORAL / ML

Overlay reason REJECT as production. AGENT NOTE regex REJECT as production. No DET-RAG.
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

- rare privileged tool after retrieval
- new retrieve→tool sequence
- novel retrieval provenance
- retrieval burst before sensitive operation
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

Retrieved content may influence a **REQUEST**. Server-owned authorization determines the **GRANT**.

Not the defense: sanitize everything · block every suspicious document · trust a scanner · ask Splunk whether execution is allowed · let an LLM decide authority.

```text
MALICIOUS DOCUMENT
        ↓
REQUEST lookup_customer_tier
        ↓
CTRL-MCP-001
        ↓
DENY tool_not_granted
        ↓
HANDLER DOES NOT START
```

CTRL-RAG-CONTEXT-001 stays OBSERVE. Classification is not the grant. Splunk does not DENY the tool. The runtime control does.

{DATA_NOT_AUTHORITY}
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_defend_evidence",
        """
# What actually changed the RETEST

Same MALICIOUS document. Same REQUEST. Different **server-owned experiment/authorization configuration**.

What does **not** change: malicious document, document hash, requested tool, requested scope, retriever provenance, Splunk search.

Defended CTRL-MCP-001 DENY `tool_not_granted`. Runtime handler count 0.

Do not claim a content filter or a scanner decided the grant. Do not treat Splunk as independent non-execution proof. Do not teach "sanitize the document and the problem is solved."
""",
        title="INV-002",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

**LIVE RETEST** is launched from [Attack Service]({ATTACK_URL}). Same malicious bytes. Different ExperimentContext (defended). Fresh run.id.

Tables on this tab are **REPLAY** `{RETEST_ID}`, not your LIVE id.

SAME document.id `{MALICIOUS_DOC}`

SAME content.hash `{MALICIOUS_HASH}`

SAME provenance `{PROVENANCE}`

SAME follow-on request `lookup_customer_tier`

SAME requested scope `customer:read`

Then: CTRL-MCP-001 **DENY** `tool_not_granted`

handler count = **authoritative**

missing indexed start = **corroboration**

Do not claim RETEST makes RAG universally safe. Do not treat Splunk as independent non-execution proof.

```text
retrieve → OBSERVE → REQUEST → DENY → no START
```
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_rag",
        "ds_q_rag_r",
        "What Happened? Q-RAG-CONTEXT-AUTHORITY",
        cap_rag + " Expect SAME MALICIOUS hash as ATTACK, followon DENY, no_indexed_followon_execution_event.",
        no_data=EMPTY_RAG,
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

**SAME RETRIEVED CONTENT. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

ATTACK and RETEST share (document fingerprint, not hop-1 request hash):

- document.id `{MALICIOUS_DOC}`
- content.hash `{MALICIOUS_HASH}`
- provenance `{PROVENANCE}`
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

- Document: `{NORMAL_DOC}`
- Fingerprint (full):

{fingerprint_block(NORMAL_HASH)}

- Provenance: `{PROVENANCE}`
- Trust: untrusted_data
- Control: CTRL-RAG-CONTEXT-001 **OBSERVE**
- Follow-on: none
- Authz: n/a
- Execution: none (handler **0**)

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

- Document: `{MALICIOUS_DOC}`
- Fingerprint (full):

{fingerprint_block(MALICIOUS_HASH)}

- Provenance: `{PROVENANCE}`
- Trust: untrusted_data · **OBSERVE**
- Request: `lookup_customer_tier` / `customer:read`
- Authz: CTRL-MCP-001 **ALLOW** overlay
- Execution: mcp.started + mcp.completed (handler **1**)

Retrieved text did not grant the tool.

Validated: `{ATTACK_ID}`
""",
        title="ATTACK",
    )
    add_md(
        "viz_cmp_card_rt",
        f"""
# RETEST

**Profile:** defended · **Mode:** RETEST · **REPLAY specimen**

- Document: `{MALICIOUS_DOC}`
- Fingerprint (full):

{fingerprint_block(MALICIOUS_HASH)}

- Provenance: `{PROVENANCE}`
- Trust: untrusted_data · **OBSERVE**
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
        "ds_q_rag_b",
        "BASELINE Q-RAG-CONTEXT-AUTHORITY",
        cap_rag + " Expect no_followon.",
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_cmp_atk",
        "ds_q_rag_a",
        "ATTACK Q-RAG-CONTEXT-AUTHORITY",
        cap_rag + " Expect SAME MALICIOUS hash as RETEST plus ALLOW.",
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_cmp_rt",
        "ds_q_rag_r",
        "RETEST Q-RAG-CONTEXT-AUTHORITY",
        cap_rag + " Expect SAME MALICIOUS hash as ATTACK plus DENY.",
        no_data=EMPTY_RAG,
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
5. **SEARCH.** Q-RAG-CONTEXT-AUTHORITY. Zero rows follow no-data semantics.
6. **DETECTION.** DET-MCP-001: 0/0/0. Silent is correct. Not SAFE. **NO NEW RAG DETECTOR.**

LIVE A/B/C **packs** are historical OBSERVED/MEASURED **REPLAY**. Your Attack Service launches are **LIVE** with new run.ids. DETECT SIMULATED table is **SIMULATED**.

**YOU JUST LEARNED** — retrieved content is data. CTRL-RAG-CONTEXT-001 OBSERVE is not a grant. CTRL-MCP-001 is the tool PDP.

**THIS CONNECTS TO** — persistent memory, which can store those same untrusted bytes for a later run.

**NEXT** — Persistent Memory (LIVE).

**WHAT WE CAN PROVE**

- Retrieved content was classified untrusted_data (CONTEXT-001 OBSERVE).
- Retrieved content influenced a privileged REQUEST on ATTACK/RETEST.
- CTRL-MCP-001 allowed the ATTACK follow-on on the labeled vulnerable experiment.
- RETEST handler count 0 for lookup_customer_tier (runtime authoritative).
- ATTACK and RETEST share document.id and content.hash.

**WHAT WE CAN CORROBORATE**

- Splunk copy of those fields when dc(_raw) matches local count.
- Absence of mcp.started on a complete RETEST copy.

**WHAT WE CANNOT PROVE**

- Universal RAG resistance.
- That sanitizing documents would have been the control.
- Prevention from an empty search alone.

**INCORRECT CLAIMS**

- Treating the SIEM copy as the enforcement point that stopped the tool.
- Calling the document SAFE or TRUSTED from one RETEST.
- Equating `untrusted_data` with malice.
- Treating a known catalog hash as proof of compromise.
- Treating missing `mcp.started` as independent prevention.
- Treating DET-MCP-001 zero rows as SAFE.
- Claiming retrieved content granted the tool.

Authoritative: runtime decision + handler count. Corroborative: Splunk. Splunk is not enforcement.

Knowledge check (answer from evidence on this tab):

1. What document was retrieved?
2. What was its provenance?
3. Was provenance equivalent to trust?
4. What was its content classification?
5. Did OBSERVE authorize anything?
6. Did retrieved text directly grant a tool?
7. What follow-on request occurred?
8. Which control decided authorization?
9. Why did ATTACK execute?
10. Why did RETEST not execute?
11. What proves handler non-execution?
12. Why is missing Splunk execution only corroboration?
13. Why is DET-MCP-001 empty?
14. Does DET-MCP-001 silence mean SAFE?
15. Why is instruction-like text not a production detector?
16. What telemetry is missing for a stronger detector?
17. Why are ATTACK and RETEST comparable?
18. What does INV-002 mean here?
19. Where could behavioral analytics help later?
20. Can ML grant or deny authority?

Validated: BASELINE `{BASELINE_ID}` · ATTACK `{ATTACK_ID}` · RETEST `{RETEST_ID}`.

NORMAL fingerprint `{NORMAL_HASH}`

MALICIOUS fingerprint `{MALICIOUS_HASH}` (ATTACK and RETEST share this hash)

No DET-RAG. Schema 1.9.0 emitters. No embeddings. No A2A transport. No rug-pull. Memory is a later lab, not this workshop.
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_rag",
        "ds_q_rag",
        "What Happened? Q-RAG-CONTEXT-AUTHORITY (Hunt run.id)",
        cap_rag,
        no_data=EMPTY_RAG,
    )

    add_md(
        "viz_workbench_mission",
        f"""
# MISSION · RETRIEVED CONTEXT

## Can retrieved untrusted context influence agent behavior without becoming authority?

**Specimen selector:** choose the server-owned run.id above. The canonical ATTACK and RETEST use the same malicious document bytes (`{MALICIOUS_HASH}`).

**SOURCE → RETRIEVAL → CONTEXT → CTRL-RAG-CONTEXT-001 OBSERVE → AGENT EFFECT → CTRL-MCP-001 AUTHORIZATION → EXECUTION EVIDENCE**

`RETRIEVED != TRUSTED` · `PROVENANCE != AUTHORITY` · `OBSERVE != ALLOW` · `ALLOW != EXECUTION`

Attack Service launches. AcmeBank/runtime decides. Splunk investigates emitted evidence; it does not authorize or block the operation.
""",
        title="MISSION",
    )
    add_md(
        "viz_workbench_investigate",
        """
# INVESTIGATE · PATH A

## Question

Where did the untrusted context enter, what effect followed, and did the requested tool actually execute?

## Starting search

```spl
index=agentsec_telemetry run.id="$run_id$"
```

## Progressive hints

1. Find the RAG retrieval and `rag.context.evaluated` evidence first.
2. Distinguish the context control's OBSERVE from CTRL-MCP-001's authorization decision.
3. Use `mcp.started`, `mcp.completed` / `mcp.failed`, and operation outcome together. A decision alone does not establish execution.

Open Splunk Search when you are ready to modify the starting search. Path B contains the validated answer searches.
""",
        title="INVESTIGATE · PATH A",
    )
    add_md(
        "viz_workbench_evidence",
        """
# EVIDENCE

Read the selected run in order: **SOURCE → RETRIEVAL → CONTEXT → CONTROL → EFFECT → EXECUTION**.

The RAG control classifies retrieved context as data and emits OBSERVE. It is not the tool PDP. CTRL-MCP-001 makes the later tool-authorization decision, and runtime MCP/operation events establish what executed.

Splunk corroborates indexed runtime evidence. An empty table is missing evidence, not proof of prevention. Fingerprint equality applies only to the canonical retrieved document bytes.
""",
        title="EVIDENCE",
    )

    mission_ids = ["viz_workbench_mission"]
    investigate_ids = ["viz_workbench_investigate"] + [
        viz_id
        for viz_id in visualizations
        if viz_id.startswith("viz_i")
        and (viz_id.endswith("_q") or viz_id.endswith("_h1") or viz_id.endswith("_h2"))
    ]
    evidence_ids = [
        "viz_workbench_evidence",
        "viz_observe_seq",
        "viz_observe_rag",
        "viz_observe_authz",
        "viz_observe_exec",
        "viz_cmp_card_atk",
        "viz_cmp_card_rt",
    ]
    allocated = set(mission_ids + investigate_ids + evidence_ids)
    answer_ids = [viz_id for viz_id in visualizations if viz_id not in allocated]

    def stacked(ids: list[str], markdown_height: int = 420, table_height: int = 300) -> tuple[list[dict], int]:
        structure: list[dict] = []
        y = 0
        for viz_id in ids:
            height = markdown_height if visualizations[viz_id]["type"] == "splunk.markdown" else table_height
            structure.append(block(viz_id, 0, y, FULL, height))
            y += height
        return structure, y + 20

    mission_structure, mission_height = stacked(mission_ids, markdown_height=420)
    investigate_structure, investigate_height = stacked(investigate_ids, markdown_height=330)
    evidence_structure, evidence_height = stacked(evidence_ids, markdown_height=300)
    answers_structure, answers_height = stacked(answer_ids, markdown_height=520)

    definition = {
        "title": "RAG / Retrieved Context",
        "description": (
            "WS-RAG-CONTEXT Dashboard Studio workshop. Reuses validated "
            "Q-RAG-CONTEXT-AUTHORITY and Q-MCP investigation SPL. Saved search "
            "DET-MCP-001 is packaged disabled; this dashboard does not enable it. "
            "No DET-RAG. Splunk does not ALLOW or DENY a tool."
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
                    {"layoutId": "layout_mission", "label": "MISSION"},
                    {"layoutId": "layout_investigate", "label": "INVESTIGATE"},
                    {"layoutId": "layout_evidence", "label": "EVIDENCE"},
                    {"layoutId": "layout_answers", "label": "PATH B · ANSWERS"},
                ],
            },
            "layoutDefinitions": {
                "layout_mission": layout(mission_structure, mission_height, display="fit-to-width"),
                "layout_investigate": layout(
                    investigate_structure, investigate_height, display="fit-to-width"
                ),
                "layout_evidence": layout(evidence_structure, evidence_height, display="fit-to-width"),
                "layout_answers": layout(answers_structure, answers_height, display="fit-to-width"),
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
        "  <label>RAG / Retrieved Context</label>\n"
        "  <description>LIVE RAG / Retrieved Context workshop. LAB-RAG-CONTEXT. Splunk does not ALLOW or DENY.</description>\n"
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
