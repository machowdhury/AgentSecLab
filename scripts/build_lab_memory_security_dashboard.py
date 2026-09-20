#!/usr/bin/env python3
"""Build the LAB-MEMORY-001 Dashboard Studio workshop.

Reuses validated Q-MEMORY-CONTEXT-AUTHORITY (two run.id tokens) and Q-MCP-*
hunts. Bind tokens only. DET-MCP-001.spl is not modified. No DET-MEMORY.
Memory does not feed CTRL-MCP-001 except via the labeled lab overlay.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
MEMORY_DIR = ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_memory_security.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

# Phase 11C LIVE IDs — not Phase 11B local packs.
BASELINE_WRITE = "a8407246-7992-4ad8-bd02-cb701e150f30"
BASELINE_RECALL = "914c41ce-5123-49eb-892c-c948295dbc46"
ATTACK_WRITE = "05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464"
ATTACK_RECALL = "b8737cd9-9b6b-48f2-acfa-178ae1446ddc"
RETEST_WRITE = "060a0a72-ceb5-4b99-8330-98de81d8ae5e"
RETEST_RECALL = "5d5b9d1b-092d-4ddb-8422-4092d289cd49"
NORMAL_MEM = "mem.lending-preference.normal"
MALICIOUS_MEM = "mem.lending-preference.malicious"
NORMAL_HASH = "sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b"
MALICIOUS_HASH = "sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9"
PROVENANCE = "agentsec.memory.fixture"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_EVENT = (
    "No indexed event matched this evidence question. That is not SAFE, not TRUSTED, "
    "not blocked, not prevented, and not proof there was no attack."
)
EMPTY_MEM = (
    "No indexed event matched this evidence question. Q-MEMORY-CONTEXT-AUTHORITY "
    "returned zero rows. Zero rows means no indexed write+recall pair for these two "
    "run.id values. That is not SAFE, not DENY, and not a TRUSTED verdict."
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
    "Investigate write specimen defaults to BASELINE write. Investigate recall specimen "
    "defaults to BASELINE recall. Custom run.id is available from Search. Empty tables are "
    "missing indexed rows, not security outcomes."
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
    "INV-003: untrusted memory cannot silently become trusted instruction. "
    "PERSISTED MEMORY != TRUSTED INSTRUCTION. MEMORY RECALL != AUTHORIZATION. "
    "REQUEST != GRANT. OBSERVE != ALLOW."
)


def fingerprint_block(h: str) -> str:
    """Split sha256:<64 hex> so Studio markdown can show the full digest in a card."""
    algo, digest = h.split(":", 1)
    return f"{algo}:\n{digest[:32]}\n{digest[32:]}"


def load_spl(name: str, *, memory: bool = False) -> str:
    directory = MEMORY_DIR if memory else SEARCH_DIR
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


def bind_memory_literal(spl: str, write_id: str, recall_id: str) -> str:
    if "__WRITE_RUN_ID__" not in spl or "__RECALL_RUN_ID__" not in spl:
        raise ValueError("expected __WRITE_RUN_ID__ and __RECALL_RUN_ID__")
    return spl.replace("__WRITE_RUN_ID__", f'"{write_id}"').replace(
        "__RECALL_RUN_ID__", f'"{recall_id}"'
    )



def bind_memory(spl: str, write_token: str, recall_token: str) -> str:
    if "__WRITE_RUN_ID__" not in spl or "__RECALL_RUN_ID__" not in spl:
        raise ValueError("expected __WRITE_RUN_ID__ and __RECALL_RUN_ID__")
    return spl.replace("__WRITE_RUN_ID__", f'"${write_token}$"').replace(
        "__RECALL_RUN_ID__", f'"${recall_token}$"'
    )


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
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"={bound_run(token)} ("event.name"=agentsec.memory.written OR "event.name"=agentsec.memory.recalled OR "event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval hop=mvindex(mvdedup('agentsec.hop.index'),0)
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval memory_id=mvindex(mvdedup('agentsec.memory.id'),0)
| eval source_run_id=mvindex(mvdedup('agentsec.memory.source_run_id'),0)
| eval content_hash=mvindex(mvdedup('agentsec.content.hash'),0)
| eval provenance=mvindex(mvdedup('agentsec.memory.provenance'),0)
| eval memory_trust=mvindex(mvdedup('agentsec.memory.trust'),0)
| eval preview=mvindex(mvdedup('agentsec.content.preview'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval agent=mvindex(mvdedup('gen_ai.agent.id'),0)
| table sequence, run_id, event_name, hop, control_id, decision, reason, memory_id, source_run_id, content_hash, provenance, memory_trust, preview, tool, requested_scope, allowed_scope, agent
| sort sequence"""


def build() -> dict:
    q_mem = bind_memory(
        load_spl("Q-MEMORY-CONTEXT-AUTHORITY.spl", memory=True),
        "write_run_id",
        "run_id",
    )
    q_who = bind_run_id(load_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_mem_b = bind_memory_literal(
        load_spl("Q-MEMORY-CONTEXT-AUTHORITY.spl", memory=True),
        BASELINE_WRITE,
        BASELINE_RECALL,
    )
    q_mem_a = bind_memory_literal(
        load_spl("Q-MEMORY-CONTEXT-AUTHORITY.spl", memory=True),
        ATTACK_WRITE,
        ATTACK_RECALL,
    )
    q_mem_r = bind_memory_literal(
        load_spl("Q-MEMORY-CONTEXT-AUTHORITY.spl", memory=True),
        RETEST_WRITE,
        RETEST_RECALL,
    )
    q_authz_b = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), BASELINE_RECALL)
    q_authz_a = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), ATTACK_RECALL)
    q_authz_r = bind_literal(load_spl("Q-MCP-AUTHZ.spl"), RETEST_RECALL)
    q_tool_a = bind_literal(load_spl("Q-MCP-TOOL.spl"), ATTACK_RECALL)
    q_tool_r = bind_literal(load_spl("Q-MCP-TOOL.spl"), RETEST_RECALL)
    q_exec_b = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), BASELINE_RECALL)
    q_exec_a = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), ATTACK_RECALL)
    q_exec_r = bind_literal(load_spl("Q-MCP-EXECUTED.spl"), RETEST_RECALL)
    q_after_b = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), BASELINE_RECALL)
    q_after_a = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), ATTACK_RECALL)
    q_after_r = bind_literal(load_spl("Q-MCP-AFTER-DENY.spl"), RETEST_RECALL)

    data_sources = dict(
        (
            search_ds("ds_q_mem", "Q-MEMORY-CONTEXT-AUTHORITY", q_mem),
            search_ds("ds_q_who", "Q-MCP-WHO", q_who),
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_mem_b", "Q-MEMORY-CONTEXT-AUTHORITY BASELINE", q_mem_b),
            search_ds("ds_q_mem_a", "Q-MEMORY-CONTEXT-AUTHORITY ATTACK", q_mem_a),
            search_ds("ds_q_mem_r", "Q-MEMORY-CONTEXT-AUTHORITY RETEST", q_mem_r),
            search_ds("ds_q_authz_b", "Q-MCP-AUTHZ BASELINE recall", q_authz_b),
            search_ds("ds_q_authz_a", "Q-MCP-AUTHZ ATTACK recall", q_authz_a),
            search_ds("ds_q_authz_r", "Q-MCP-AUTHZ RETEST recall", q_authz_r),
            search_ds("ds_q_tool_a", "Q-MCP-TOOL ATTACK recall", q_tool_a),
            search_ds("ds_q_tool_r", "Q-MCP-TOOL RETEST recall", q_tool_r),
            search_ds("ds_q_exec_b", "Q-MCP-EXECUTED BASELINE recall", q_exec_b),
            search_ds("ds_q_exec_a", "Q-MCP-EXECUTED ATTACK recall", q_exec_a),
            search_ds("ds_q_exec_r", "Q-MCP-EXECUTED RETEST recall", q_exec_r),
            search_ds("ds_q_after_b", "Q-MCP-AFTER-DENY BASELINE recall", q_after_b),
            search_ds("ds_q_after_a", "Q-MCP-AFTER-DENY ATTACK recall", q_after_a),
            search_ds("ds_q_after_r", "Q-MCP-AFTER-DENY RETEST recall", q_after_r),
            search_ds("ds_observe_write", "Memory write-run sequence", observe_sequence_spl("write_run_id")),
            search_ds("ds_observe_recall", "Memory recall-run sequence", observe_sequence_spl("run_id")),
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

    cap_mem = (
        "Q-MEMORY-CONTEXT-AUTHORITY. Reconstructs write → later recall, SHA-256, "
        "trust classification, follow-on request, authorization, and indexed "
        "execution observation. Bind BOTH write and recall run.id. "
        "derived_authority is a lab display helper, not a production IOC. "
        "Do not hunt AGENT MEMORY NOTE with a regex."
    )
    cap_authz = (
        "Q-MCP-AUTHZ on the RECALL run. CONTEXT-001 OBSERVE is classification, "
        "not a grant. Hop-1 CTRL-MCP-001 is authorization. Write runs return 0 "
        "Q-MCP rows because they have no control.decision. executed on the "
        "control row is not handler execution."
    )
    cap_tool = (
        "Q-MCP-TOOL on the RECALL run. Empty tool on CONTEXT-001 is observation, "
        "not lookup_policy. Zero mcp.started rows is not automatically DENY."
    )
    cap_exec = (
        "Q-MCP-EXECUTED on the RECALL run. Read has_started and execution_state. "
        + ALLOW_NOT_EXEC
    )
    cap_who = (
        "Q-MCP-WHO on the RECALL run. Principal / agent identity. CONTEXT-001 may "
        "appear without mcp.method.name. That is recall observation, not a tool grant."
    )
    cap_seq_write = (
        "WRITE RUN sequence: persistence evidence. Indexed fields only. No `_raw`. "
        "No full memory body. Hash + bounded preview. Studio view, not a new hunt file."
    )
    cap_seq_recall = (
        "RECALL RUN sequence: trust, request, authorization, execution. Indexed "
        "fields only. No `_raw`. No full memory body. Studio view, not a new hunt file."
    )
    cap_after = (
        "Q-MCP-AFTER-DENY on the RECALL run. Hunt form of DET-MCP-001. LIVE memory "
        "recall specimens: 0 rows. Zero rows is CORRECT and is not SAFE."
    )

    add_md(
        "viz_learn",
        f"""
# Persistent Memory

Investigate why recalled memory cannot silently become trusted instruction.

**LIVE EVIDENCE** · `LAB-MEMORY-001` · Schema 1.7.0 · CTRL-MEMORY-CONTEXT-001

**What can I prove from the evidence?** Not: was malicious memory detected?

- PERSISTED MEMORY != TRUSTED INSTRUCTION
- MEMORY RECALL != AUTHORIZATION
- REQUEST != GRANT
- OBSERVE != ALLOW
- ALLOW != EXECUTION
- DENY != INDEPENDENT PROOF OF PREVENTION
- MISSING SPLUNK EVENT != BLOCKED
- ANOMALY != INCIDENT
- SPLUNK != ENFORCEMENT
- ML != AUTHORIZATION

**LIVE write and recall are different run.id values**

BASELINE WRITE `{BASELINE_WRITE}`

BASELINE RECALL `{BASELINE_RECALL}`

ATTACK WRITE `{ATTACK_WRITE}`

ATTACK RECALL `{ATTACK_RECALL}`

RETEST WRITE `{RETEST_WRITE}`

RETEST RECALL `{RETEST_RECALL}`

NORMAL memory `{NORMAL_MEM}`

{fingerprint_block(NORMAL_HASH)}

MALICIOUS memory `{MALICIOUS_MEM}`

{fingerprint_block(MALICIOUS_HASH)}

Provenance `{PROVENANCE}` is source identity. Provenance is not trust.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_flow",
        """
# Memory path (two runs)

```text
WRITE RUN
     ↓
MEMORY STORE
     ↓
LATER RECALL RUN
     ↓
CTRL-MEMORY-CONTEXT-001
     ↓
REQUEST
     ↓
CTRL-MCP-001
     ↓
HANDLER
```

Trust boundary is **before** authorization.

Stored != trusted. Recalled != approved. Recalled text may influence reasoning. Influence may produce a REQUEST. The REQUEST still requires server-owned authorization.
""",
        title="PATH",
    )
    add_md(
        "viz_learn_planes",
        """
# Five evidence planes

1 PERSISTENCE — writer run, memory.id, SHA-256, provenance. Label: CONTEXT.

2 RECALL / TRUST — destination run, source_run_id, CTRL-MEMORY-CONTEXT-001 OBSERVE `memory_context_is_data`, `untrusted_data`. Label: CONTEXT + CONTROL EVIDENCE.

3 INFLUENCE / REQUEST — follow-on tool / scope. Label: HUNT / CONTEXT. REQUEST != GRANT.

4 AUTHORIZATION — CTRL-MCP-001 ALLOW or DENY. Label: CONTROL EVIDENCE.

5 EXECUTION — mcp.started / completed / failed. Handler count is authoritative.

Do not collapse these into one memory-poisoning event.
""",
        title="PLANES",
    )
    add_md(
        "viz_learn_vs",
        """
# RAG vs MEMORY

**RAG** = retrieved external/contextual information in one run.

document → retrieval → context → request → authorization

**MEMORY** = persisted state surviving into a **later run**.

WRITE RUN → store → later RECALL RUN → recalled context → request → authorization → execution

The cross-run relationship is the new concept. These are not the only agentic-security domains.

LAB-PI-001 · MCP-001/003/004/005/006 · catalog · scanner · RAG

Identity / A2A / rug-pull are later. Not this workshop.
""",
        title="RAG vs MEMORY",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

**LIVE** · write defended · recall defended · mode BASELINE · handler **0**

WRITE `{BASELINE_WRITE}`

RECALL `{BASELINE_RECALL}`

memory.id `{NORMAL_MEM}`

content.hash `{NORMAL_HASH}`

provenance `{PROVENANCE}` — source identity, not trust

CTRL-MEMORY-CONTEXT-001 **OBSERVE** `memory_context_is_data`

classification `untrusted_data` — that is a label, not malice

no unauthorized privileged follow-on

Do **not** label this SAFE, TRUSTED, APPROVED, or BENIGN.

No privileged follow-on was observed in this specimen. That is an observation, not proof that the stored content is safe.
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_mem",
        "ds_q_mem_b",
        "What Happened? Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem + " Expect OBSERVE, NORMAL hash, no_followon. Not SAFE.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_b",
        "Q-MCP-AUTHZ (recall run)",
        cap_authz + " Expect CONTEXT-001 OBSERVE. No hop-1 CTRL-MCP-001.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_baseline_exec",
        "ds_q_exec_b",
        "Q-MCP-EXECUTED (recall run)",
        cap_exec + " Expect no privileged follow-on execution.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK

**INTENTIONALLY VULNERABLE LAB PROFILE** · **LIVE** · recall profile vulnerable · mode ATTACK · handler **1**

WRITE `{ATTACK_WRITE}` → persistent malicious fixture `{MALICIOUS_MEM}` → RECALL `{ATTACK_RECALL}`

fingerprint `{MALICIOUS_HASH}`

provenance `{PROVENANCE}`

CTRL-MEMORY-CONTEXT-001 stays **OBSERVE** `memory_context_is_data`

Follow-on **REQUEST** `lookup_customer_tier` / `customer:read`

CTRL-MCP-001 **ALLOW** `vulnerable_profile_fail_open:memory_derived_authority`

That ALLOW is a **LAB-ONLY VULNERABLE PROFILE MECHANISM**. It is not a production IOC. Recalled memory did **not** authorize the operation.

The recalled memory influenced a request. The vulnerable authorization profile granted the request. The memory itself did not grant the tool.

Then: mcp.started · mcp.completed · handler 1

```text
write → later recall → OBSERVE → REQUEST → ALLOW → START → COMPLETE
```
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_mem",
        "ds_q_mem_a",
        "What Happened? Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem + " Expect MALICIOUS hash, followon ALLOW overlay, mcp.completed_observed.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_a",
        "Q-MCP-AUTHZ (recall run)",
        cap_authz + " Expect OBSERVE then hop-1 ALLOW. Hop-1 ALLOW is not a server grant of the tool.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_attack_tool",
        "ds_q_tool_a",
        "Q-MCP-TOOL (recall run)",
        cap_tool + " Expect hop-1 mcp.started for lookup_customer_tier.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_exec_a",
        "Q-MCP-EXECUTED (recall run)",
        cap_exec + " Expect has_started=1 on follow-on. mcp.started != SUCCESS.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Use **Investigate write specimen** + **Investigate recall specimen** (defaults BASELINE pair). Five planes. Indexed structured fields only. No `_raw`. No full memory body. Hash + bounded preview.

Write run and recall run are **different** `run.id` values. Persistence lives on the write run. Trust, request, authorization, and execution live on the recall run.

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_md(
        "viz_observe_planes",
        """
# Plane map

**PERSISTENCE** — writer run, memory.id, SHA-256, provenance

**RECALL / TRUST** — destination run, source_run_id, CTRL-MEMORY-CONTEXT-001 OBSERVE, untrusted_data

**INFLUENCE / REQUEST** — follow-on tool / requested scope

**AUTHORIZATION** — CTRL-MCP-001 ALLOW or DENY, reason, requested vs coded allowed scope

**EXECUTION** — mcp.started / completed / failed. Handler count is authoritative.

Labels in text: CONTEXT · HUNT · CONTROL EVIDENCE · EXECUTION EVIDENCE · LIVE · OBSERVE · ALLOW · DENY
""",
        title="PLANES",
    )
    add_table(
        "viz_observe_write",
        "ds_observe_write",
        "PLANE 1 PERSISTENCE — write-run sequence",
        cap_seq_write,
        no_data=EMPTY_SEQ,
    )
    add_table(
        "viz_observe_recall",
        "ds_observe_recall",
        "PLANES 2–5 — recall-run sequence",
        cap_seq_recall,
        no_data=EMPTY_SEQ,
    )
    add_table(
        "viz_observe_mem",
        "ds_q_mem",
        "WRITE + RECALL join — Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem,
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_observe_authz",
        "ds_q_authz",
        "AUTHORIZATION — Q-MCP-AUTHZ (recall)",
        cap_authz,
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_observe_exec",
        "ds_q_executed",
        "EXECUTION — Q-MCP-EXECUTED (recall)",
        cap_exec,
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_hunt_md",
        f"""
# HUNT

**Question:** Which write persisted this memory, which later recall loaded it, how was it classified, and was the follow-on request authorized or executed?

**Primary hunt:** Q-MEMORY-CONTEXT-AUTHORITY. Reconstruct: WRITE → RECALL → REQUEST → AUTHORIZATION → EXECUTION.

Correlation keys that exist: memory.id + content.hash + source_run_id + destination run.id + gen_ai.agent.id + sequence.

Do **not** invent session.id, invocation.id, tenant.id, or tool.call.id.

Reuse Q-MCP-* against the **recall** run. Write runs have no control.decision.

Do **not** hunt a regex for AGENT MEMORY NOTE. Do **not** treat `vulnerable_profile_fail_open:memory_derived_authority` as a production IOC. That string is a lab overlay reason.

No Q-MEMORY-WRITE. No Q-MEMORY-POISONED. No DET-MEMORY.

{DATA_NOT_AUTHORITY}

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table(
        "viz_hunt_mem",
        "ds_q_mem",
        "Q-MEMORY-CONTEXT-AUTHORITY (primary memory hunt)",
        cap_mem,
        no_data=EMPTY_MEM,
    )
    add_table("viz_hunt_authz", "ds_q_authz", "Q-MCP-AUTHZ (recall)", cap_authz, no_data=EMPTY_CONTROL)
    add_table("viz_hunt_tool", "ds_q_tool", "Q-MCP-TOOL (recall)", cap_tool, no_data=EMPTY_TOOL)
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED (recall)", cap_exec, no_data=EMPTY_TOOL)
    add_table("viz_hunt_who", "ds_q_who", "Q-MCP-WHO (recall)", cap_who, no_data=EMPTY_CONTROL)

    add_md(
        "viz_detect_md",
        """
# DETECTION ANALYZED — NO NEW MEMORY DETECTOR

No notable. **No DET-MEMORY.** This dashboard does **not** enable DET-MCP-001.

DET-MCP-001 detects **DENY then later mcp.started** for the same run.id + tool. It is **not** a memory-poisoning detector.

LIVE Phase 11C recall runs (MEASURED):

- BASELINE = 0 because there was no DENY
- ATTACK = 0 because the path was ALLOW — no DENY
- RETEST = 0 because DENY was respected — no later start

0 rows is **CORRECT**. 0 rows != **SAFE**.

Right table: **SIMULATED** `| makeresults`. **NOT INDEXED.** Not a LIVE memory attack. Not OBSERVED runtime.
""",
        title="STEP 5 DETECT",
    )
    add_md(
        "viz_detect_class",
        """
# Classification (Phase 11D)

memory write → **CONTEXT**

memory recall → **CONTEXT**

untrusted recall → **CONTEXT**

recall + privileged request → **CONTEXT / HUNT**

recall + DENY → **CONTROL EVIDENCE**

recall + ALLOW → **REJECT AS PRODUCTION SIGNAL** by itself

recall + execution → **HUNT** / insufficient without grant snapshot

write → later recall → request → execution → **Q-MEMORY-CONTEXT-AUTHORITY HUNT** (REJECT as detector)

overlay reason `vulnerable_profile_fail_open:memory_derived_authority` → **REJECT AS PRODUCTION SIGNAL**

AGENT MEMORY NOTE regex → **REJECT AS PRODUCTION SIGNAL**

rare provenance / rare recall→tool / write burst → **FUTURE BEHAVIORAL ANALYTICS**

cross-agent / tenant mismatch → **TELEMETRY GAP / FUTURE**

No DET-MEMORY.
""",
        title="CONTEXT / HUNT / DETECTION / FUTURE",
    )
    add_table(
        "viz_detect_b",
        "ds_q_after_b",
        "DET-MCP-001 / Q-MCP-AFTER-DENY BASELINE recall",
        cap_after + " BASELINE 0: no DENY.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_a",
        "ds_q_after_a",
        "DET-MCP-001 / Q-MCP-AFTER-DENY ATTACK recall",
        cap_after + " ATTACK 0: ALLOW path.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_detect_r",
        "ds_q_after_r",
        "DET-MCP-001 / Q-MCP-AFTER-DENY RETEST recall",
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

- rare memory provenance
- new recall → tool sequence
- unusual recall frequency
- write-volume spike
- privileged request rate after recall
- memory fingerprint drift
- per-agent baseline deviation
- cross-agent recall
- cross-tenant recall

Possible later tools: statistical SPL · Splunk MLTK · Cisco Time Series Data Model / CDTSM where appropriate.

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

- grant snapshot (`allowed_tools`) absent
- gen_ai.tool.call.id absent
- writer != reader semantics incomplete
- tenant identity absent
- user/principal ownership absent
- cross-agent memory relationship absent
- cross-tenant isolation absent
- vector-memory instrumentation absent
- session/invocation correlation absent

Do not invent these fields. Identity / A2A work is later. Until a grant snapshot exists: **TELEMETRY GAP — QUERY NOT DEFENSIBLE** for unauthorized execution after untrusted recall.
""",
        title="TELEMETRY GAPS",
    )

    add_md(
        "viz_defend",
        f"""
# DEFEND

Memory may influence a **REQUEST**. Server-owned authorization determines the **GRANT**.

Not the defense: sanitize all memory · block malicious strings · trust a scanner · ask Splunk whether execution is allowed · let an LLM decide authority.

```text
MEMORY
        ↓
UNTRUSTED DATA
        ↓
MAY INFLUENCE REQUEST
        ↓
SERVER-OWNED AUTHORIZATION
        ↓
ALLOW / DENY
        ↓
HANDLER ONLY AFTER ALLOW
```

Defended path:

```text
MALICIOUS MEMORY
        ↓
RECALL
        ↓
REQUEST lookup_customer_tier
        ↓
CTRL-MCP-001
        ↓
DENY tool_not_granted
        ↓
HANDLER DOES NOT START
```

CTRL-MEMORY-CONTEXT-001 stays OBSERVE. Classification is not the grant. Splunk does not DENY the tool. The runtime control does.

{DATA_NOT_AUTHORITY}
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_defend_evidence",
        """
# What actually changed the RETEST

Same MALICIOUS memory.id. Same SHA-256. Same REQUEST. Different security profile on the **recall** run.

Defended CTRL-MCP-001 DENY `tool_not_granted`. Runtime handler count 0.

Do not claim a content filter or a scanner decided the grant. Do not treat Splunk as independent non-execution proof.
""",
        title="INV-003",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

**LIVE** · write defended · recall defended · mode RETEST · handler **0**

WRITE `{RETEST_WRITE}`

RECALL `{RETEST_RECALL}`

SAME memory.id `{MALICIOUS_MEM}`

SAME content.hash `{MALICIOUS_HASH}`

SAME provenance `{PROVENANCE}`

SAME follow-on request `lookup_customer_tier`

SAME requested scope `customer:read`

Then: CTRL-MCP-001 **DENY** `tool_not_granted`

no mcp.started on COMPLETE Splunk copy

Runtime handler count is authoritative for non-execution. Missing indexed execution is corroboration.

Do not treat Splunk as independent non-execution proof.

```text
write → later recall → OBSERVE → REQUEST → DENY → no START
```
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_mem",
        "ds_q_mem_r",
        "What Happened? Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem + " Expect SAME MALICIOUS hash as ATTACK, followon DENY, no_indexed_followon_execution_event.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_r",
        "Q-MCP-AUTHZ (recall run)",
        cap_authz + " Expect hop-1 DENY tool_not_granted.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_r",
        "Q-MCP-TOOL (recall run)",
        "Q-MCP-TOOL. No indexed hop-1 mcp.started observed. That is Splunk corroboration. Runtime handler count = 0 is authoritative.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_exec_r",
        "Q-MCP-EXECUTED (recall run)",
        cap_exec + " Expect follow-on has_started=0.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

Primary visual proof of the lab.

**SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

ATTACK and RETEST share:

- memory.id `{MALICIOUS_MEM}`
- content.hash `{MALICIOUS_HASH}`
- provenance `{PROVENANCE}`
- follow-on tool `lookup_customer_tier`
- requested scope `customer:read`

ATTACK: ALLOW + execution (handler 1)

RETEST: DENY + handler 0

Malicious stored bytes are not authorization bypass. Overlay ALLOW is not automatically successful execution.
""",
        title="BEFORE / AFTER",
    )
    add_md(
        "viz_cmp_card_base",
        f"""
# BASELINE

**LIVE · OBSERVE · no privileged follow-on · handler 0**

- Authz: n/a (no privileged request)
- Execution: none (handler **0**)
- Follow-on: none
- Trust: untrusted_data · CTRL-MEMORY-CONTEXT-001 **OBSERVE**
- Memory: `{NORMAL_MEM}`
- WRITE `{BASELINE_WRITE}`
- RECALL `{BASELINE_RECALL}`
- Fingerprint (full):

{fingerprint_block(NORMAL_HASH)}

- Provenance: `{PROVENANCE}` (identity, not trust)

Do not label SAFE.
""",
        title="BASELINE",
    )
    add_md(
        "viz_cmp_card_atk",
        f"""
# ATTACK

**INTENTIONALLY VULNERABLE LAB PROFILE** · **LIVE**

- Authz: CTRL-MCP-001 **ALLOW** overlay
- Execution: mcp.started + mcp.completed (handler **1**)
- Request: `lookup_customer_tier` / `customer:read`
- Trust: untrusted_data · **OBSERVE**
- Memory: `{MALICIOUS_MEM}`
- WRITE `{ATTACK_WRITE}`
- RECALL `{ATTACK_RECALL}`
- Fingerprint (full):

{fingerprint_block(MALICIOUS_HASH)}

- Provenance: `{PROVENANCE}` (identity, not trust)

Memory did not grant the tool.
""",
        title="ATTACK",
    )
    add_md(
        "viz_cmp_card_rt",
        f"""
# RETEST

**LIVE · defended · SAME malicious memory as ATTACK**

- Authz: CTRL-MCP-001 **DENY** `tool_not_granted`
- Execution: no mcp.started (handler **0**)
- Request: `lookup_customer_tier` / `customer:read`
- Trust: untrusted_data · **OBSERVE**
- Memory: `{MALICIOUS_MEM}`
- WRITE `{RETEST_WRITE}`
- RECALL `{RETEST_RECALL}`
- Fingerprint (full):

{fingerprint_block(MALICIOUS_HASH)}

- Provenance: `{PROVENANCE}` (identity, not trust)

SAME hash as ATTACK. Runtime handler count is authoritative.
""",
        title="RETEST",
    )
    add_table(
        "viz_cmp_base",
        "ds_q_mem_b",
        "BASELINE Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem + " Expect no_followon.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_cmp_atk",
        "ds_q_mem_a",
        "ATTACK Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem + " Expect SAME MALICIOUS hash as RETEST plus ALLOW.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_cmp_rt",
        "ds_q_mem_r",
        "RETEST Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem + " Expect SAME MALICIOUS hash as ATTACK plus DENY.",
        no_data=EMPTY_MEM,
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
5. **SEARCH.** Q-MEMORY-CONTEXT-AUTHORITY. Zero rows follow no-data semantics.
6. **DETECTION.** DET-MCP-001: 0/0/0. Silent is correct. Not SAFE. **NO NEW MEMORY DETECTOR.**

LIVE A/B/C write+recall are OBSERVED/MEASURED. DETECT SIMULATED table is **SIMULATED**.

Knowledge check (answers in knowledge-check.md):

1. Which run wrote the memory?
2. Which later run recalled it?
3. What memory.id links the evidence?
4. What SHA-256 fingerprints the content?
5. Does provenance imply trust?
6. What trust classification was applied?
7. Was the memory classified with ALLOW?
8. Did recall influence a privileged request?
9. What tool was requested?
10. What scope was requested?
11. Which control decided authority?
12. Did memory itself authorize the tool?
13. What happened in ATTACK?
14. What happened in RETEST?
15. Why is ATTACK not proof that malicious memory always executes?
16. Why is RETEST missing mcp.started only corroboration?
17. Why does DET-MCP-001 return zero for ATTACK?
18. Why does DET-MCP-001 return zero for RETEST?
19. Why should AGENT MEMORY NOTE not become a detector?
20. Why is the vulnerable overlay reason not a production IOC?
21. What is INV-003?
22. How is memory different from RAG?
23. Which evidence plane determines authorization?
24. Which evidence plane determines execution?
25. What telemetry is missing for cross-agent memory?
26. What telemetry is missing for tenant isolation?
27. Why is anomaly != incident?
28. Can ML grant or deny authority?
29. Can Splunk authorize a tool?
30. What evidence would be required before creating a production memory-security detection?

Validated WRITE/RECALL: BASELINE `{BASELINE_WRITE}` / `{BASELINE_RECALL}` · ATTACK `{ATTACK_WRITE}` / `{ATTACK_RECALL}` · RETEST `{RETEST_WRITE}` / `{RETEST_RECALL}`.

NORMAL fingerprint `{NORMAL_HASH}`

MALICIOUS fingerprint `{MALICIOUS_HASH}` (ATTACK and RETEST share this hash)

No DET-MEMORY. Schema 1.7.0. Phase 12 not started. No A2A. No rug-pull. No vector memory.
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_mem",
        "ds_q_mem",
        "What Happened? Q-MEMORY-CONTEXT-AUTHORITY (Hunt write + Hunt recall)",
        cap_mem,
        no_data=EMPTY_MEM,
    )

    definition = {
        "title": "Persistent Memory",
        "description": (
            "WS-MEMORY-SECURITY Dashboard Studio workshop. Reuses validated "
            "Q-MEMORY-CONTEXT-AUTHORITY and Q-MCP investigation SPL. Saved search "
            "DET-MCP-001 is packaged disabled; this dashboard does not enable it. "
            "No DET-MEMORY. Splunk does not ALLOW or DENY a tool."
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
            "input_write_run_id": {
                "type": "input.dropdown",
                "title": "Investigate write specimen",
                "options": {
                    "token": "write_run_id",
                    "defaultValue": BASELINE_WRITE,
                    "items": [
                        {"label": "Baseline write — defended / normal", "value": BASELINE_WRITE},
                        {"label": "Attack write — vulnerable / malicious", "value": ATTACK_WRITE},
                        {"label": "Retest write — defended / malicious", "value": RETEST_WRITE},
                    ],
                },
            },
            "input_run_id": {
                "type": "input.dropdown",
                "title": "Investigate recall specimen",
                "options": {
                    "token": "run_id",
                    "defaultValue": BASELINE_RECALL,
                    "items": [
                        {"label": "Baseline recall — defended / normal", "value": BASELINE_RECALL},
                        {"label": "Attack recall — vulnerable / malicious", "value": ATTACK_RECALL},
                        {"label": "Retest recall — defended / malicious", "value": RETEST_RECALL},
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
                "input_write_run_id",
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
                        block("viz_learn_flow", 0, 0, FULL, 380),
                        block("viz_learn", 0, 380, FULL, 520),
                        block("viz_learn_planes", 0, 900, HALF, 400),
                        block("viz_learn_vs", HALF, 900, HALF, 400),
                    ],
                    1320,
                ),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 460),
                        block("viz_baseline_mem", 0, 460, FULL, 280),
                        block("viz_baseline_authz", 0, 740, HALF, 260),
                        block("viz_baseline_exec", HALF, 740, HALF, 260),
                    ],
                    1020,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 560),
                        block("viz_attack_mem", 0, 560, FULL, 280),
                        block("viz_attack_authz", 0, 840, HALF, 260),
                        block("viz_attack_tool", HALF, 840, HALF, 260),
                        block("viz_attack_exec", 0, 1100, FULL, 260),
                    ],
                    1380,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, HALF, 280),
                        block("viz_observe_planes", HALF, 0, HALF, 280),
                        block("viz_observe_write", 0, 280, FULL, 280),
                        block("viz_observe_recall", 0, 560, FULL, 280),
                        block("viz_observe_mem", 0, 840, FULL, 280),
                        block("viz_observe_authz", 0, 1120, HALF, 260),
                        block("viz_observe_exec", HALF, 1120, HALF, 260),
                    ],
                    1400,
                ),
                "layout_hunt": layout(
                    [
                        block("viz_hunt_md", 0, 0, FULL, 420),
                        block("viz_hunt_mem", 0, 420, FULL, 280),
                        block("viz_hunt_authz", 0, 700, HALF, 240),
                        block("viz_hunt_tool", HALF, 700, HALF, 240),
                        block("viz_hunt_exec", 0, 940, HALF, 240),
                        block("viz_hunt_who", HALF, 940, HALF, 240),
                    ],
                    1200,
                ),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, HALF, 420),
                        block("viz_detect_class", HALF, 0, HALF, 420),
                        block("viz_detect_b", 0, 420, THIRD, 280),
                        block("viz_detect_a", THIRD, 420, THIRD, 280),
                        block("viz_detect_r", THIRD * 2, 420, THIRD, 280),
                        block("viz_detect_sim", 0, 700, HALF, 280),
                        block("viz_detect_future", HALF, 700, HALF, 280),
                        block("viz_detect_gaps", 0, 980, FULL, 320),
                    ],
                    1320,
                ),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 620),
                        block("viz_defend_evidence", 0, 620, FULL, 240),
                    ],
                    880,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 560),
                        block("viz_retest_mem", 0, 560, FULL, 280),
                        block("viz_retest_authz", 0, 840, HALF, 260),
                        block("viz_retest_tool", HALF, 840, HALF, 260),
                        block("viz_retest_exec", 0, 1100, FULL, 260),
                    ],
                    1380,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 300),
                        block("viz_cmp_card_base", 0, 300, THIRD, 780),
                        block("viz_cmp_card_atk", THIRD, 300, THIRD, 780),
                        block("viz_cmp_card_rt", THIRD * 2, 300, THIRD, 780),
                        block("viz_cmp_base", 0, 1080, THIRD, 280),
                        block("viz_cmp_atk", THIRD, 1080, THIRD, 280),
                        block("viz_cmp_rt", THIRD * 2, 1080, THIRD, 280),
                    ],
                    1380,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 1100),
                        block("viz_prove_mem", 0, 1100, FULL, 280),
                    ],
                    1400,
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
        "  <label>Persistent Memory</label>\n"
        "  <description>LIVE Persistent Memory workshop. LAB-MEMORY-001. Splunk does not ALLOW or DENY.</description>\n"
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
