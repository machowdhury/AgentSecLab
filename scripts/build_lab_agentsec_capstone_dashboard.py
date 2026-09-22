#!/usr/bin/env python3
"""Build the LAB-AGENTSEC-CAPSTONE-001 Dashboard Studio workshop.

Reuses validated Q-RAG / Q-MEMORY / Q-MCP / Q-RUN-EVENTS / Q-GOAL /
Q-AGENT-DELEGATION hunts. Bind tokens only. No Q-CAPSTONE. No DET-CAPSTONE.
Splunk is evidence, not the tool PDP.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RAG_DIR = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "searches"
MEMORY_DIR = ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "searches"
PI_DIR = ROOT / "learning" / "level_1" / "LAB-PI-001" / "searches"
GOAL_DIR = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001" / "searches"
IDENT_DIR = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001" / "searches"
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-AGENTSEC-CAPSTONE-001"
OUT_JSON = LAB_DIR / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_agentsec_capstone.xml"
)
INV_PATH = LAB_DIR / "investigations.json"
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
ATTACK_URL = "http://127.0.0.1:5001/labs/LAB-AGENTSEC-CAPSTONE-001"

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

# Official LIVE ids (Phase 16B, 2026-09-20). Not placeholders.
BASELINE_RETRIEVE = "5a15fe04-4bb1-4f70-8ec0-ab83f423dcde"
BASELINE_WRITE = "5dd71f94-5b12-4c52-b5ed-93a0b6832d45"
BASELINE_RECALL = "3d2b66a1-9ef1-4b1d-b993-444db50fd3ee"
ATTACK_RETRIEVE = "2a248113-7436-46a7-9b1d-0243489ac000"
ATTACK_WRITE = "348c8f18-fdfb-4501-ad8a-3f1bcda64c34"
ATTACK_RECALL = "2437f64a-fff4-424f-8a83-0f04285662e4"
RETEST_RETRIEVE = "f9015037-651d-4207-ac57-4f3ea1abc673"
RETEST_WRITE = "3f8d6305-2d3b-4988-9e65-dc99b7ac10de"
RETEST_RECALL = "8d2c016f-cadc-4463-939a-23a183221b3d"

MALICIOUS_HASH = "sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef"
NORMAL_HASH = "sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e"

NORMAL_DOC = "doc.lending-policy.normal"
MALICIOUS_DOC = "doc.lending-policy.malicious"
NORMAL_MEM = "mem.capstone.retrieved.normal"
MALICIOUS_MEM = "mem.capstone.retrieved.malicious"
PROVENANCE_RAG = "rag.local.fixture"
PROVENANCE_MEM = "agentsec.memory.fixture"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_EVENT = (
    "No indexed event matched this evidence question. Zero rows is not SAFE, "
    "not TRUSTED, not blocked, not prevented, and not proof there was no attack."
)
EMPTY_RAG = (
    "Q-RAG-CONTEXT-AUTHORITY returned zero rows. Zero rows means no indexed "
    "CTRL-RAG-CONTEXT-001 for this retrieve run.id. That is not SAFE, not DENY, "
    "not prevention, and not a TRUSTED verdict."
)
EMPTY_MEM = (
    "Q-MEMORY-CONTEXT-AUTHORITY returned zero rows. Zero rows means no indexed "
    "write+recall pair for these two run.id values. That is not SAFE, not DENY, "
    "and not prevention."
)
EMPTY_CONTROL = (
    "No indexed event matched this evidence question. Missing control.decision "
    "is not DENY, not SAFE, and not prevention. It can be a wrong run.id or an "
    "incomplete copy."
)
EMPTY_TOOL = (
    "No indexed event matched this evidence question. Missing mcp.started is "
    "not automatically DENY, blocked, or prevented. Runtime handler count "
    "remains authoritative. Zero rows is not SAFE."
)
EMPTY_AFTER = (
    "DET-MCP-001 / Q-MCP-AFTER-DENY look for DENY then later mcp.started. "
    "Zero rows is not SAFE and is not prevention."
)
EMPTY_SEQ = (
    "No indexed event matched this evidence question. Sequence cannot be shown. "
    "That is not a security outcome, not SAFE, and not prevention."
)
EMPTY_HUNT = (
    "Investigate retrieve / write / recall specimen defaults to the official "
    "LIVE BASELINE triple. Choose Attack or Retest from the dropdowns. Fresh "
    "LIVE run.ids come from Attack Service Search, not a token write. Empty "
    "tables are missing indexed rows, not security outcomes. Zero rows is not "
    "SAFE and not prevention."
)
EMPTY_ABSENT = (
    "Zero rows means this event family is not indexed for these run.ids. "
    "That is instrumented absence in this packet. It is not SAFE, not "
    "prevention, and not proof the domain never fails."
)
ALLOW_NOT_EXEC = (
    "ALLOW is the control decision. Tool execution begins at mcp.started. "
    "Do not read ALLOW as execution. mcp.completed is success of a begun call. "
    "mcp.failed is execution then error, not prevention."
)
RUNTIME_AUTH = (
    "Runtime handler count is authoritative proof of execution or non-execution. "
    "Missing indexed mcp.started is corroboration only, and only on a complete "
    "copy. Splunk does not prove prevention."
)
INFLUENCE_NOT_AUTHORITY = (
    "RETRIEVED CONTENT != AUTHORITY. STORED MEMORY != TRUSTED INSTRUCTION. "
    "REQUEST != GRANT. OBSERVE != ALLOW. ALLOW != EXECUTION. SPLUNK != ENFORCEMENT."
)

SPL_TEACHING = {
    "Q-RUN-EVENTS": (
        "- Lists indexed events for the quoted run.id values.\n"
        "- Schema, profile, testbed.mode, hop, and sequence are correlation fields.\n"
        "- Finding events does not prove completeness or prevention."
    ),
    "Q-RAG-CONTEXT-AUTHORITY": (
        "- Reconstructs retrieve classification on the RETRIEVE run.id.\n"
        "- Document fingerprint is CONTEXT-001 content.hash, not a grant.\n"
        "- OBSERVE is not ALLOW. Capstone retrieve skips privileged follow-on."
    ),
    "Q-MEMORY-CONTEXT-AUTHORITY": (
        "- Reconstructs WRITE → later RECALL → classification → follow-on request.\n"
        "- Bind BOTH write and recall run.id. source_run_id is the write UUID.\n"
        "- Hash equality joins retrieve to write. Preview is not the fingerprint."
    ),
    "Q-MCP-WHO": (
        "- Principal / agent / tool identity on control.decision for the RECALL run.\n"
        "- Identity is not a grant. Requested is not authorized."
    ),
    "Q-MCP-AUTHZ": (
        "- Control.decision rows on the RECALL run. Hop 0 may be a classifier.\n"
        "- Hop 1 CTRL-MCP-001 is the tool PDP. Splunk did not make the decision."
    ),
    "Q-MCP-TOOL": (
        "- mcp.started rows only on the RECALL run. Presence means the handler began."
    ),
    "Q-MCP-EXECUTED": (
        "- Joins control + mcp.* into execution_state on the RECALL run.\n"
        "- Runtime handler count remains authoritative for non-execution."
    ),
    "Q-GOAL-INTEGRITY-AUTHORITY": (
        "- Looks for CTRL-GOAL-INTEGRITY-001 on the given run.ids.\n"
        "- Zero rows here means CTRL-GOAL-INTEGRITY-001 is NOT PRESENT in this packet. That is instrumented absence, not a ruling that Goal Integrity is irrelevant forever."
    ),
    "Q-AGENT-DELEGATION-AUTHORITY": (
        "- Looks for CTRL-IDENTITY-001 / delegation fields on the given run.ids.\n"
        "- Zero rows here means CTRL-IDENTITY-001 is NOT PRESENT in this packet. That is instrumented absence, not a ruling that Identity never fails."
    ),
}

HUNT_DIRS = (RAG_DIR, MEMORY_DIR, PI_DIR, GOAL_DIR, IDENT_DIR, MCP_DIR)

INVESTIGATE_IDS = {
    "CAP-I1-FIND-THE-RUNS",
    "CAP-I2-RECONSTRUCT-SEQUENCE",
    "CAP-I12-GOAL-INTEGRITY-REQUIRED",
    "CAP-I13-IDENTITY-DELEGATION-REQUIRED",
}
TRACE_IDS = {
    "CAP-I3-IDENTIFY-RETRIEVED-SOURCE",
    "CAP-I4-PROVENANCE-AND-TRUST",
    "CAP-I5-DID-CONTENT-PERSIST",
    "CAP-I6-WRITE-TO-RECALL",
    "CAP-I7-WHAT-RECALL-INFLUENCED",
}
AUTHORITY_IDS = {
    "CAP-I8-REQUESTED-PRIVILEGED-OPERATION",
    "CAP-I9-ACTUAL-CODED-AUTHORITY",
    "CAP-I10-WHO-AUTHORIZED",
    "CAP-I11-DID-EXECUTION-OCCUR",
}

TABLE_BIND = {
    "CAP-I1-FIND-THE-RUNS": [
        (
            "ds_q_run",
            "Q-RUN-EVENTS (retrieve OR write OR recall)",
            "Three distinct run.ids per experiment. Finding them is not completeness.",
        )
    ],
    "CAP-I2-RECONSTRUCT-SEQUENCE": [
        (
            "ds_seq",
            "Studio sequence (retrieve OR write OR recall)",
            "Sort launch order then agentsec.sequence. Missing a hop is not prevention.",
        )
    ],
    "CAP-I3-IDENTIFY-RETRIEVED-SOURCE": [
        (
            "ds_q_rag",
            "Q-RAG-CONTEXT-AUTHORITY (retrieve specimen)",
            "One RAG OBSERVE row. Untrusted is not malicious. Retrieve is not a grant.",
        )
    ],
    "CAP-I4-PROVENANCE-AND-TRUST": [
        (
            "ds_q_rag",
            "Q-RAG-CONTEXT-AUTHORITY provenance (retrieve specimen)",
            "rag.local.fixture is source identity, not trust. OBSERVE is not SAFE.",
        )
    ],
    "CAP-I5-DID-CONTENT-PERSIST": [
        (
            "ds_q_mem",
            "Q-MEMORY-CONTEXT-AUTHORITY (write + recall)",
            "Compare write_hash to retrieve context_hash. Matching preview is not the fingerprint.",
        )
    ],
    "CAP-I6-WRITE-TO-RECALL": [
        (
            "ds_q_mem",
            "Q-MEMORY-CONTEXT-AUTHORITY write-to-recall",
            "write_recall_linked and source_run_id. Linked persistence is not a grant.",
        )
    ],
    "CAP-I7-WHAT-RECALL-INFLUENCED": [
        (
            "ds_q_mem",
            "Q-MEMORY-CONTEXT-AUTHORITY follow-on",
            "OBSERVE plus follow-on request is influence, not authority.",
        )
    ],
    "CAP-I8-REQUESTED-PRIVILEGED-OPERATION": [
        (
            "ds_q_who",
            "Q-MCP-WHO (recall specimen)",
            "Requested tool / scope / resource. REQUEST != GRANT.",
        )
    ],
    "CAP-I9-ACTUAL-CODED-AUTHORITY": [
        (
            "ds_q_authz",
            "Q-MCP-AUTHZ (recall specimen)",
            "Coded allowed_scope vs requested_scope. Overlay is not a coded_policy mutation.",
        )
    ],
    "CAP-I10-WHO-AUTHORIZED": [
        (
            "ds_q_authz",
            "Q-MCP-AUTHZ control.id (recall specimen)",
            "Only CTRL-MCP-001 is the tool PDP. Classifiers stay OBSERVE. Splunk did not decide.",
        )
    ],
    "CAP-I11-DID-EXECUTION-OCCUR": [
        (
            "ds_q_executed",
            "Q-MCP-EXECUTED (recall specimen)",
            "has_started is copy evidence. Runtime handler count remains authoritative.",
        ),
        (
            "ds_q_tool",
            "Q-MCP-TOOL (recall specimen)",
            "mcp.started rows only. Missing start is not independently prevented.",
        ),
    ],
    "CAP-I12-GOAL-INTEGRITY-REQUIRED": [
        (
            "ds_q_goal",
            "Q-GOAL-INTEGRITY-AUTHORITY (three run.ids)",
            "Expect zero rows. Absence here is not proof Goal Integrity never fails.",
        )
    ],
    "CAP-I13-IDENTITY-DELEGATION-REQUIRED": [
        (
            "ds_q_ident",
            "Q-AGENT-DELEGATION-AUTHORITY (three run.ids)",
            "Expect zero rows. WHO AUTHENTICATED remains NOT PROVEN.",
        )
    ],
}


def fingerprint_block(h: str) -> str:
    """Split sha256:<64 hex> so Studio markdown can show the full digest."""
    algo, digest = h.split(":", 1)
    return f"{algo}:\n{digest[:32]}\n{digest[32:]}"


def inv_number(inv: dict) -> int:
    return int(inv["investigation_id"].split("-")[1][1:])


def load_hunt_spl(name: str) -> str:
    for directory in HUNT_DIRS:
        path = directory / name
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    raise FileNotFoundError(name)


def bound_run(ref: str) -> str:
    """Token name stays $token$; UUID becomes a quoted literal."""
    if len(ref) == 36 and ref.count("-") == 4:
        return f'"{ref}"'
    return f'"${ref}$"'


def bind_run_id(spl: str, token: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError(f"expected __RUN_ID__ in query for token {token}")
    return spl.replace("__RUN_ID__", f'"${token}$"')


def bind_literal(spl: str, run_id: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError("expected __RUN_ID__ in query")
    return spl.replace("__RUN_ID__", f'"{run_id}"')


def bind_or_runs(spl: str, refs: list[str]) -> str:
    needle = '"agentsec.run.id"=__RUN_ID__'
    if needle not in spl:
        raise ValueError("expected \"agentsec.run.id\"=__RUN_ID__")
    or_expr = "(" + " OR ".join(f'"agentsec.run.id"={bound_run(ref)}' for ref in refs) + ")"
    return spl.replace(needle, or_expr)


def bind_memory(spl: str, write_token: str, recall_token: str) -> str:
    if "__WRITE_RUN_ID__" not in spl or "__RECALL_RUN_ID__" not in spl:
        raise ValueError("expected __WRITE_RUN_ID__ and __RECALL_RUN_ID__")
    return spl.replace("__WRITE_RUN_ID__", f'"${write_token}$"').replace(
        "__RECALL_RUN_ID__", f'"${recall_token}$"'
    )


def bind_memory_literal(spl: str, write_id: str, recall_id: str) -> str:
    if "__WRITE_RUN_ID__" not in spl or "__RECALL_RUN_ID__" not in spl:
        raise ValueError("expected __WRITE_RUN_ID__ and __RECALL_RUN_ID__")
    return spl.replace("__WRITE_RUN_ID__", f'"{write_id}"').replace(
        "__RECALL_RUN_ID__", f'"{recall_id}"'
    )


def bind_solution_spl(hunt: str, spl: str) -> str:
    if hunt == "Q-MEMORY-CONTEXT-AUTHORITY":
        return bind_memory(spl, "write_run_id", "run_id")
    if hunt == "Q-RAG-CONTEXT-AUTHORITY":
        return bind_run_id(spl, "retrieve_run_id")
    if hunt in {
        "Q-RUN-EVENTS",
        "Q-GOAL-INTEGRITY-AUTHORITY",
        "Q-AGENT-DELEGATION-AUTHORITY",
    }:
        return bind_or_runs(spl, ["retrieve_run_id", "write_run_id", "run_id"])
    return bind_run_id(spl, "run_id")


def capstone_sequence_spl() -> str:
    """Studio-only sequence. Not a new hunt file."""
    or_expr = (
        '("agentsec.run.id"="$retrieve_run_id$" OR '
        '"agentsec.run.id"="$write_run_id$" OR '
        '"agentsec.run.id"="$run_id$")'
    )
    return f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 {or_expr} ("event.name"=agentsec.memory.written OR "event.name"=agentsec.memory.recalled OR "event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval hop=mvindex(mvdedup('agentsec.hop.index'),0)
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval document_id=mvindex(mvdedup('agentsec.rag.context.document.id'),0)
| eval memory_id=mvindex(mvdedup('agentsec.memory.id'),0)
| eval source_run_id=mvindex(mvdedup('agentsec.memory.source_run_id'),0)
| eval content_hash=mvindex(mvdedup('agentsec.content.hash'),0)
| eval preview=mvindex(mvdedup('agentsec.content.preview'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval profile=mvindex(mvdedup('agentsec.security.profile'),0)
| eval mode=mvindex(mvdedup('agentsec.testbed.mode'),0)
| eval run_order=case(run_id="$retrieve_run_id$",0,run_id="$write_run_id$",1,run_id="$run_id$",2,1=1,9)
| table run_order, sequence, run_id, event_name, hop, control_id, decision, reason, document_id, memory_id, source_run_id, content_hash, preview, tool, requested_scope, allowed_scope, profile, mode
| sort run_order, sequence"""


def question_md(inv: dict, number: int) -> str:
    return f"""
# Investigation {number} — {inv["title"]}

**QUESTION**

{inv["security_question"]}

**WHAT AM I TRYING TO PROVE?**

{inv["learning_objective"]}

**YOUR TASK (Path A — try it yourself)**

{inv["starter_guidance"]}

1. Copy the fresh LIVE retrieve, write, and recall run.ids from Attack Service, or use Investigate specimen for the official LIVE triple.
2. [Open Splunk Search]({SEARCH_URL})
3. Constrain `index=agentsec_telemetry sourcetype=otel:agentic:json`.
4. Filter quoted `agentsec.run.id` for the relevant UUID. Do not collapse three related runs into one id.

Studio cannot receive a fresh LIVE run.id. That handoff is Search, not a token write.

Starter (paste your LIVE UUIDs; do not search `index=*`):

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 ("agentsec.run.id"="PASTE-RETRIEVE-RUN-ID" OR "agentsec.run.id"="PASTE-WRITE-RUN-ID" OR "agentsec.run.id"="PASTE-RECALL-RUN-ID")
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
    spl = load_hunt_spl(f"{hunt}.spl")
    bound = bind_solution_spl(hunt, spl)
    teach = SPL_TEACHING[hunt]
    nxt = inv["next_investigation"] or "PROVE — classify what you can actually conclude."
    return f"""
# Solution — Investigation {number} {inv["title"]}

This is a **review key**, not the default path. Reconstruct the chain in Search first. Path B does not authorize, detect, or prove completeness. Path A remains Search with your LIVE retrieve / write / recall run.ids.

**SOLUTION SPL** (`{hunt}`)

Copy this into Search. Replace tokens with LIVE UUIDs, or leave tokens for Investigate specimen REPLAY.

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


def block(item: str, x: int, y: int, w: int, h: int) -> dict:
    return {"item": item, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}


def markdown(viz_id: str, body: str, title: str | None = None) -> tuple[str, dict]:
    text = textwrap.dedent(body).strip() + "\n"
    for line in text.splitlines():
        stripped = line.strip()
        cells = [part.strip() for part in stripped.split("|")]
        looks_like_row = stripped.startswith("|") and stripped.endswith("|") and len(cells) >= 4
        looks_like_sep = looks_like_row and all(
            set(part) <= {"-", ":", " "} for part in cells if part
        )
        if looks_like_row or looks_like_sep:
            raise ValueError(f"{viz_id} contains a GFM pipe table; use lists or headings")
    viz = {
        "type": "splunk.markdown",
        "options": {
            "markdown": text,
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


def empty_for(ident: str) -> str:
    if ident.startswith("CAP-I1") or ident.startswith("CAP-I2"):
        return EMPTY_HUNT
    if ident.startswith("CAP-I3") or ident.startswith("CAP-I4"):
        return EMPTY_RAG
    if ident.startswith("CAP-I5") or ident.startswith("CAP-I6") or ident.startswith("CAP-I7"):
        return EMPTY_MEM
    if ident.startswith("CAP-I12") or ident.startswith("CAP-I13"):
        return EMPTY_ABSENT
    if ident == "CAP-I11-DID-EXECUTION-OCCUR":
        return EMPTY_TOOL
    return EMPTY_CONTROL


def build() -> dict:
    q_rag = bind_run_id(load_hunt_spl("Q-RAG-CONTEXT-AUTHORITY.spl"), "retrieve_run_id")
    q_mem = bind_memory(load_hunt_spl("Q-MEMORY-CONTEXT-AUTHORITY.spl"), "write_run_id", "run_id")
    q_who = bind_run_id(load_hunt_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_hunt_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_hunt_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_hunt_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_after = bind_run_id(load_hunt_spl("Q-MCP-AFTER-DENY.spl"), "run_id")
    q_params = bind_run_id(load_hunt_spl("Q-MCP-PARAMS.spl"), "run_id")
    q_scope = bind_run_id(load_hunt_spl("Q-MCP-SCOPE.spl"), "run_id")
    q_result = bind_run_id(load_hunt_spl("Q-MCP-RESULT.spl"), "run_id")
    q_result_trust = bind_run_id(load_hunt_spl("Q-MCP-RESULT-TRUST.spl"), "run_id")
    q_run = bind_or_runs(
        load_hunt_spl("Q-RUN-EVENTS.spl"),
        ["retrieve_run_id", "write_run_id", "run_id"],
    )
    q_goal = bind_or_runs(
        load_hunt_spl("Q-GOAL-INTEGRITY-AUTHORITY.spl"),
        ["retrieve_run_id", "write_run_id", "run_id"],
    )
    q_ident = bind_or_runs(
        load_hunt_spl("Q-AGENT-DELEGATION-AUTHORITY.spl"),
        ["retrieve_run_id", "write_run_id", "run_id"],
    )
    q_rag_b = bind_literal(load_hunt_spl("Q-RAG-CONTEXT-AUTHORITY.spl"), BASELINE_RETRIEVE)
    q_rag_a = bind_literal(load_hunt_spl("Q-RAG-CONTEXT-AUTHORITY.spl"), ATTACK_RETRIEVE)
    q_rag_r = bind_literal(load_hunt_spl("Q-RAG-CONTEXT-AUTHORITY.spl"), RETEST_RETRIEVE)
    q_mem_b = bind_memory_literal(
        load_hunt_spl("Q-MEMORY-CONTEXT-AUTHORITY.spl"), BASELINE_WRITE, BASELINE_RECALL
    )
    q_mem_a = bind_memory_literal(
        load_hunt_spl("Q-MEMORY-CONTEXT-AUTHORITY.spl"), ATTACK_WRITE, ATTACK_RECALL
    )
    q_mem_r = bind_memory_literal(
        load_hunt_spl("Q-MEMORY-CONTEXT-AUTHORITY.spl"), RETEST_WRITE, RETEST_RECALL
    )
    q_authz_a = bind_literal(load_hunt_spl("Q-MCP-AUTHZ.spl"), ATTACK_RECALL)
    q_authz_r = bind_literal(load_hunt_spl("Q-MCP-AUTHZ.spl"), RETEST_RECALL)
    q_authz_b = bind_literal(load_hunt_spl("Q-MCP-AUTHZ.spl"), BASELINE_RECALL)
    q_exec_a = bind_literal(load_hunt_spl("Q-MCP-EXECUTED.spl"), ATTACK_RECALL)
    q_exec_r = bind_literal(load_hunt_spl("Q-MCP-EXECUTED.spl"), RETEST_RECALL)
    q_exec_b = bind_literal(load_hunt_spl("Q-MCP-EXECUTED.spl"), BASELINE_RECALL)
    q_tool_a = bind_literal(load_hunt_spl("Q-MCP-TOOL.spl"), ATTACK_RECALL)
    q_tool_r = bind_literal(load_hunt_spl("Q-MCP-TOOL.spl"), RETEST_RECALL)
    q_after_a = bind_literal(load_hunt_spl("Q-MCP-AFTER-DENY.spl"), ATTACK_RECALL)
    q_after_r = bind_literal(load_hunt_spl("Q-MCP-AFTER-DENY.spl"), RETEST_RECALL)

    data_sources = dict(
        (
            search_ds("ds_q_rag", "Q-RAG-CONTEXT-AUTHORITY", q_rag),
            search_ds("ds_q_mem", "Q-MEMORY-CONTEXT-AUTHORITY", q_mem),
            search_ds("ds_q_who", "Q-MCP-WHO", q_who),
            search_ds("ds_q_authz", "Q-MCP-AUTHZ", q_authz),
            search_ds("ds_q_tool", "Q-MCP-TOOL", q_tool),
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_after", "Q-MCP-AFTER-DENY", q_after),
            search_ds("ds_q_params", "Q-MCP-PARAMS", q_params),
            search_ds("ds_q_scope", "Q-MCP-SCOPE", q_scope),
            search_ds("ds_q_result", "Q-MCP-RESULT", q_result),
            search_ds("ds_q_result_trust", "Q-MCP-RESULT-TRUST", q_result_trust),
            search_ds("ds_q_run", "Q-RUN-EVENTS", q_run),
            search_ds("ds_q_goal", "Q-GOAL-INTEGRITY-AUTHORITY", q_goal),
            search_ds("ds_q_ident", "Q-AGENT-DELEGATION-AUTHORITY", q_ident),
            search_ds("ds_seq", "Capstone sequence", capstone_sequence_spl()),
            search_ds("ds_q_rag_b", "Q-RAG-CONTEXT-AUTHORITY BASELINE retrieve", q_rag_b),
            search_ds("ds_q_rag_a", "Q-RAG-CONTEXT-AUTHORITY ATTACK retrieve", q_rag_a),
            search_ds("ds_q_rag_r", "Q-RAG-CONTEXT-AUTHORITY RETEST retrieve", q_rag_r),
            search_ds("ds_q_mem_b", "Q-MEMORY-CONTEXT-AUTHORITY BASELINE", q_mem_b),
            search_ds("ds_q_mem_a", "Q-MEMORY-CONTEXT-AUTHORITY ATTACK", q_mem_a),
            search_ds("ds_q_mem_r", "Q-MEMORY-CONTEXT-AUTHORITY RETEST", q_mem_r),
            search_ds("ds_q_authz_b", "Q-MCP-AUTHZ BASELINE recall", q_authz_b),
            search_ds("ds_q_authz_a", "Q-MCP-AUTHZ ATTACK recall", q_authz_a),
            search_ds("ds_q_authz_r", "Q-MCP-AUTHZ RETEST recall", q_authz_r),
            search_ds("ds_q_exec_b", "Q-MCP-EXECUTED BASELINE recall", q_exec_b),
            search_ds("ds_q_exec_a", "Q-MCP-EXECUTED ATTACK recall", q_exec_a),
            search_ds("ds_q_exec_r", "Q-MCP-EXECUTED RETEST recall", q_exec_r),
            search_ds("ds_q_tool_a", "Q-MCP-TOOL ATTACK recall", q_tool_a),
            search_ds("ds_q_tool_r", "Q-MCP-TOOL RETEST recall", q_tool_r),
            search_ds("ds_q_after_a", "Q-MCP-AFTER-DENY ATTACK recall", q_after_a),
            search_ds("ds_q_after_r", "Q-MCP-AFTER-DENY RETEST recall", q_after_r),
            search_ds(
                "ds_det_mcp_001_sim",
                "DET-MCP-001-POSITIVE-CONTROL",
                load_hunt_spl("DET-MCP-001-POSITIVE-CONTROL.spl"),
            ),
        )
    )

    visualizations: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str | None = None) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    def add_table(viz_id: str, ds: str, title: str, description: str, *, no_data: str) -> str:
        if ds not in data_sources:
            raise KeyError(f"{viz_id} references missing dataSource {ds}")
        key, viz = table(viz_id, ds, title, description, no_data=no_data)
        visualizations[key] = viz
        return key

    cap_rag = (
        "Q-RAG-CONTEXT-AUTHORITY on the RETRIEVE run. Reconstructs document.id, "
        "content.hash, provenance, trust, and CTRL-RAG-CONTEXT-001. OBSERVE is "
        "classification, not a grant. Capstone retrieve skips privileged follow-on."
    )
    cap_mem = (
        "Q-MEMORY-CONTEXT-AUTHORITY on WRITE + RECALL. Reconstructs persist, "
        "later recall, SHA-256, trust, follow-on request, and indexed execution "
        "observation. Bind both run.ids. Hash equality is the retrieve-to-write join."
    )
    cap_authz = (
        "Q-MCP-AUTHZ on the RECALL run. Classifier OBSERVE is not a grant. "
        "CTRL-MCP-001 is the tool PDP. Splunk did not decide."
    )
    cap_exec = (
        "Q-MCP-EXECUTED on the RECALL run. Read has_started and execution_state. "
        + ALLOW_NOT_EXEC
    )
    cap_who = (
        "Q-MCP-WHO on the RECALL run. Principal / agent / tool identity. "
        "Caller id is not a grant."
    )
    cap_tool = (
        "Q-MCP-TOOL on the RECALL run. mcp.started means the handler began. "
        "Zero rows is not independently DENY."
    )
    cap_seq = (
        "Studio-only sequence across retrieve, write, and recall tokens. "
        "Launch order then agentsec.sequence. Not a new hunt file. No `_raw`."
    )
    cap_run = (
        "Q-RUN-EVENTS adapted to OR retrieve, write, and recall tokens. "
        "Three distinct run.ids. Correlation is not authorization."
    )
    cap_goal = (
        "Q-GOAL-INTEGRITY-AUTHORITY across retrieve, write, and recall. "
        "Expect zero rows in this packet. Zero rows is not SAFE."
    )
    cap_ident = (
        "Q-AGENT-DELEGATION-AUTHORITY across retrieve, write, and recall. "
        "Expect zero rows in this packet. WHO AUTHENTICATED remains NOT PROVEN."
    )
    cap_after = (
        "Q-MCP-AFTER-DENY on the RECALL run. Hunt form of DET-MCP-001. "
        "Capstone ATTACK and RETEST are expected 0 rows. Zero rows is not SAFE. "
        "No DET-CAPSTONE."
    )

    add_md(
        "viz_mission",
        f"""
# Lending Assistant Investigation

A lending assistant accessed **customer-tier** information while the expected work was to **summarize lending policy**.

This is an investigation assignment. Determine what the evidence can prove.

**Before you start**

You should already be able to name a trust boundary, treat retrieved content and memory as data, distinguish a tool request from a grant, reconstruct execution, correlate more than one run.id, compare ATTACK versus RETEST, and classify proof. If that is new, open Home START, then Direct Prompt Injection. This is graduation, not another random lab.

Path B is a review key here. Reconstruct in Search first.

**Determine**

- Origin — which bytes entered, and on which retrieve run
- Trust — how those bytes were classified
- Persistence — whether they were written into memory
- Later request — whether a later recall shaped a privileged tool request
- Authority — what coded policy actually granted
- Decision — which control recorded ALLOW, DENY, or OBSERVE
- Execution — whether the privileged handler ran
- RETEST change — what stayed the same and what changed
- Splunk limits — what reconstructed telemetry cannot prove

**How to work**

1. Read ARCHITECTURE. Write a prediction in the cards below before you treat ATTACK as solved.
2. Launch LIVE from [Attack Service]({ATTACK_URL}) when you want fresh retrieve / write / recall run.ids.
3. Hunt in [Splunk Search]({SEARCH_URL}). Studio dropdowns default to the official LIVE pair. Fresh launches mint new ids you copy into Search.
4. Fresh LIVE ids come from Attack Service Search. They are not written into these dropdowns.

`LAB-AGENTSEC-CAPSTONE-001` · Schema **1.9.0** · three run.ids per experiment

Do not collapse retrieve, write, and recall into one UUID.

Do not label BASELINE SAFE.

Do not assume every previous lab vulnerability occurred here.
""",
        title="MISSION",
    )
    add_md(
        "viz_mission_limits",
        f"""
# Evidence rules

- REQUEST != GRANT
- OBSERVE != ALLOW
- ALLOW != EXECUTION
- MISSING EVENT != PREVENTION
- ZERO ROWS != SAFE
- SPLUNK != ENFORCEMENT

Investigate specimen dropdowns default to the official LIVE BASELINE triple.

BASELINE retrieve `{BASELINE_RETRIEVE}`

BASELINE write `{BASELINE_WRITE}`

BASELINE recall `{BASELINE_RECALL}`

Studio does not launch the experiment. Attack Service does not sit in the authorization path. Splunk reconstructs copies of telemetry.

{INFLUENCE_NOT_AUTHORITY}
""",
        title="LIMITS",
    )

    add_md(
        "viz_arch",
        """
# Architecture

Readable path. This is the experiment, not a product diagram.

1. User / Task
2. Retriever
3. RAG Context
4. Memory Store
5. Later Recall
6. Agent Request
7. CTRL-MCP-001
8. Tool
9. Business Data

Telemetry leaves each stage toward Splunk. Splunk is not a step between CTRL-MCP-001 and the tool.

**Telemetry from each stage → Splunk**

- Retriever / RAG Context → document.id, content.hash, preview, CTRL-RAG-CONTEXT-001
- Memory Store / Later Recall → memory.id, source_run_id, write/recall hash, CTRL-MEMORY-CONTEXT-001
- Agent Request → gen_ai.tool.name, requested_scope, resource
- CTRL-MCP-001 → control.decision, reason, allowed_scope
- Tool → mcp.started / completed / failed, runtime handler count
- Splunk → reconstructed, searchable copy of those fields

**Splunk is evidence, not inline enforcement.**

Splunk does not ALLOW or DENY. Splunk does not sit between CTRL-MCP-001 and the handler. HEC acceptance is not searchable evidence.
""",
        title="PATH",
    )
    add_md(
        "viz_arch_planes",
        """
# What each stage can and cannot do

**RAG Context** classifies retrieved bytes as data. It does not mint `customer:read`.

**Memory Store** persists bytes for a later run. Stored is not trusted. Recalled is not authorized.

**Agent Request** can be shaped by recalled text. A request is not a grant.

**CTRL-MCP-001** is the tool authorization decision. That is where coded policy is evaluated.

**Tool / handler** is execution. Runtime handler count is authoritative.

**Splunk** reconstructs the copy. It does not change the decision.

Do not treat this page as naming the failing control. Reconstruct the chain from evidence.
""",
        title="PLANES",
    )

    add_md(
        "viz_predict_attack",
        f"""
# Predict ATTACK

Write this down before you treat the ATTACK tables as the answer.

- Where will untrusted bytes enter?
- Will they persist into memory?
- Will a later recall request `lookup_customer_tier`?
- Will that request become a grant?
- Will the privileged handler start?

Influence can remain present without becoming authority.

A retrieved document can be classified as data and still shape a later request.

A stored record can survive into a later run without granting a tool.

Do not assume Goal Integrity or Identity must explain the symptom.

Do not assume BASELINE is SAFE.

[Open Attack Service]({ATTACK_URL}) after you write the prediction.
""",
        title="ATTACK PREDICTION",
    )
    add_md(
        "viz_predict_retest",
        """
# Predict RETEST

Same adversarial bytes. Different experiment context.

- Will the content.hash stay the same?
- Will RAG still classify the retrieve as data?
- Will memory still classify the recall as data?
- Will the same privileged tool still be requested?
- Will authorization change?
- Will execution change?

Influence can remain without becoming authority.

One RETEST is not universal resistance.

Missing telemetry is not prevention.

Splunk will show a reconstructed difference only if the runtime emitted it. Splunk will not cause the difference.
""",
        title="RETEST PREDICTION",
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK

Predict **before** you launch. Launching is not the investigation.

**WHY ARE WE DOING THIS?**

We want to test whether untrusted retrieved content, then persisted memory, can cause a later run to acquire authority it did not already possess.

**WHAT DOES THE ATTACKER CONTROL?**

Only the closed specimen bytes (malicious document and memory fixture). Not profile, grants, or policy.

**WHAT DOES THE SERVER OWN?**

Coded grants, profile, overlay eligibility, and whether CTRL-MCP-001 ALLOW or DENY.

**WHAT DO YOU PREDICT?**

Retrieve OBSERVE. Write then later recall OBSERVE. Follow-on lookup_customer_tier requested. Vulnerable CTRL-MCP-001 ALLOW. Privileged handler 1. OBSERVE did not authorize. Recalled memory did not grant the tool.

**THEN:** Open Attack Service, launch LIVE ATTACK, copy retrieve / write / recall run.ids, wait until **EVIDENCE READY**, then hunt in Search.

[Open Attack Service (LIVE launch)]({ATTACK_URL})

**INTENTIONALLY VULNERABLE LAB PROFILE**

Tables below default to the official LIVE ATTACK triple. Fresh launches mint new ids you copy into Search.

**What this specimen does**

- RAG **OBSERVE** `retrieved_context_is_data` on retrieve `{ATTACK_RETRIEVE}`
- Memory **OBSERVE** `memory_context_is_data` on write `{ATTACK_WRITE}` / recall `{ATTACK_RECALL}`
- Follow-on **REQUEST** `lookup_customer_tier` / `customer:read`
- CTRL-MCP-001 **ALLOW** labeled fail-open on this recall run only
- Privileged handler **1**

document `{MALICIOUS_DOC}` · memory `{MALICIOUS_MEM}`

{fingerprint_block(MALICIOUS_HASH)}

The retrieved document did not grant `customer:read`. The memory record did not grant `lookup_customer_tier`. The labeled fail-open is a lab overlay, not a mutation of coded policy, and not a production IOC.

```text
retrieve OBSERVE → write → later recall OBSERVE → REQUEST → ALLOW → handler 1
```
""",
        title="INTENTIONALLY VULNERABLE",
    )
    add_table(
        "viz_attack_rag",
        "ds_q_rag_a",
        "ATTACK retrieve — Q-RAG-CONTEXT-AUTHORITY",
        cap_rag + " Literal ATTACK retrieve. Expect OBSERVE, malicious hash, no retrieve follow-on.",
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_attack_mem",
        "ds_q_mem_a",
        "ATTACK write + recall — Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem + " Literal ATTACK write/recall. Expect OBSERVE plus privileged follow-on.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_a",
        "ATTACK recall — Q-MCP-AUTHZ",
        cap_authz + " Literal ATTACK recall. Expect hop-1 ALLOW labeled fail-open.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_exec_a",
        "ATTACK recall — Q-MCP-EXECUTED",
        cap_exec + " Literal ATTACK recall. Expect started/completed on a complete copy. Handler 1 is runtime.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_attack_tool",
        "ds_q_tool_a",
        "ATTACK recall — Q-MCP-TOOL",
        cap_tool + " Literal ATTACK recall. Expect hop-1 mcp.started for lookup_customer_tier.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_inv_md",
        f"""
# INVESTIGATE

Two paths. Path A is the default. Path B is an answer key, not policy.

**Path A — Try it yourself:** question, starter guidance, [Open Splunk Search]({SEARCH_URL}). Construct the hunt.

**Path B is a review key, not the default.** Copyable SPL from an existing hunt, expected shape, meaning, limitations. Reconstruct in Search first. Path B does not authorize or detect.

This tab covers CAP-I1, CAP-I2, CAP-I12, and CAP-I13.

Investigate specimen dropdowns default to the official LIVE triple. Fresh LIVE retrieve / write / recall run.ids come from Attack Service Search. Studio tokens are not auto-bound.

Do not search `index=*`. Do not invent a retrieve-to-write field. Schema remains 1.9.0.

No Q-CAPSTONE. No DET-CAPSTONE.

{INFLUENCE_NOT_AUTHORITY}

{EMPTY_HUNT}
""",
        title="PATH A THEN PATH B",
    )

    add_md(
        "viz_trace_md",
        f"""
# TRACE

SOURCE → PROVENANCE → TRUST → PERSISTENCE → LATER RECALL → INFLUENCE → REQUEST

CAP-I3 through CAP-I7. Path A first. Path B is the answer key.

Hash equality joins retrieve to write. `source_run_id` joins write to recall. Do not invent a schema field.

Tables below bind Investigate retrieve specimen and Investigate write / recall specimen.

{INFLUENCE_NOT_AUTHORITY}
""",
        title="INFLUENCE CHAIN",
    )
    add_table(
        "viz_trace_rag",
        "ds_q_rag",
        "Q-RAG-CONTEXT-AUTHORITY (retrieve specimen)",
        cap_rag,
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_trace_mem",
        "ds_q_mem",
        "Q-MEMORY-CONTEXT-AUTHORITY (write + recall specimen)",
        cap_mem,
        no_data=EMPTY_MEM,
    )

    add_md(
        "viz_auth_md",
        f"""
# AUTHORITY

Coded grants. CTRL-MCP-001 decision. Handler count.

CAP-I8 through CAP-I11. Path A first. Path B is the answer key.

OBSERVE != ALLOW. ALLOW != EXECUTION. REQUEST != GRANT.

Tables bind Investigate recall specimen.

{ALLOW_NOT_EXEC}

{RUNTIME_AUTH}
""",
        title="GRANT VS EXECUTION",
    )
    add_table("viz_auth_who", "ds_q_who", "Q-MCP-WHO (recall specimen)", cap_who, no_data=EMPTY_CONTROL)
    add_table("viz_auth_authz", "ds_q_authz", "Q-MCP-AUTHZ (recall specimen)", cap_authz, no_data=EMPTY_CONTROL)
    add_table(
        "viz_auth_exec",
        "ds_q_executed",
        "Q-MCP-EXECUTED (recall specimen)",
        cap_exec,
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_auth_params",
        "ds_q_params",
        "Q-MCP-PARAMS (recall specimen)",
        "Q-MCP-PARAMS on the RECALL run. Parameters are request data, not a grant.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_auth_scope",
        "ds_q_scope",
        "Q-MCP-SCOPE (recall specimen)",
        "Q-MCP-SCOPE on the RECALL run. Requested scope is not allowed_scope.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_auth_result",
        "ds_q_result",
        "Q-MCP-RESULT (recall specimen)",
        "Q-MCP-RESULT on the RECALL run. A result row is execution aftermath, not authorization.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_auth_result_trust",
        "ds_q_result_trust",
        "Q-MCP-RESULT-TRUST (recall specimen)",
        "Q-MCP-RESULT-TRUST on the RECALL run. Result trust is not a grant.",
        no_data=EMPTY_TOOL,
    )

    inv_doc = json.loads(INV_PATH.read_text(encoding="utf-8"))
    by_id = {row["investigation_id"]: row for row in inv_doc["investigations"]}

    def stack_notebook(
        ids: list[str],
        prefix: str,
        *,
        q_h: int,
        hint_h: int,
        sol_h: int,
        tbl_h: int,
        y0: int,
    ) -> tuple[list[dict], int]:
        structure: list[dict] = []
        y_cursor = y0
        for ident in ids:
            inv = by_id[ident]
            number = inv_number(inv)
            q_id = f"viz_{prefix}_{number}_q"
            h1_id = f"viz_{prefix}_{number}_h1"
            h2_id = f"viz_{prefix}_{number}_h2"
            sol_id = f"viz_{prefix}_{number}_sol"
            add_md(q_id, question_md(inv, number), title=f"I{number} question")
            add_md(h1_id, hint_md(inv, number, "hint_1"), title=f"I{number} hint 1")
            add_md(h2_id, hint_md(inv, number, "hint_2"), title=f"I{number} hint 2")
            add_md(sol_id, solution_md(inv, number), title=f"I{number} solution")
            q_y = y_cursor
            h1_y = q_y + q_h
            h2_y = h1_y + hint_h
            sol_y = h2_y + hint_h
            tbl_y = sol_y + sol_h
            structure.extend(
                [
                    block(q_id, 0, q_y, FULL, q_h),
                    block(h1_id, 0, h1_y, FULL, hint_h),
                    block(h2_id, 0, h2_y, FULL, hint_h),
                    block(sol_id, 0, sol_y, FULL, sol_h),
                ]
            )
            binds = TABLE_BIND[ident]
            no_data = empty_for(ident)
            if len(binds) == 1:
                ds, title, desc = binds[0]
                tbl_id = f"viz_{prefix}_{number}_tbl"
                add_table(tbl_id, ds, title, desc, no_data=no_data)
                structure.append(block(tbl_id, 0, tbl_y, FULL, tbl_h))
            else:
                width = FULL // len(binds)
                for col, (ds, title, desc) in enumerate(binds):
                    tbl_id = f"viz_{prefix}_{number}_tbl_{col}"
                    add_table(tbl_id, ds, title, desc, no_data=no_data)
                    structure.append(block(tbl_id, col * width, tbl_y, width, tbl_h))
            y_cursor = tbl_y + tbl_h
        return structure, y_cursor

    inv_intro_h = 420
    investigate_ids = [
        "CAP-I1-FIND-THE-RUNS",
        "CAP-I2-RECONSTRUCT-SEQUENCE",
        "CAP-I12-GOAL-INTEGRITY-REQUIRED",
        "CAP-I13-IDENTITY-DELEGATION-REQUIRED",
    ]
    investigate_structure = [block("viz_inv_md", 0, 0, FULL, inv_intro_h)]
    stacked, inv_y = stack_notebook(
        investigate_ids,
        "inv",
        q_h=320,
        hint_h=180,
        sol_h=520,
        tbl_h=260,
        y0=inv_intro_h,
    )
    investigate_structure.extend(stacked)

    trace_intro_h = 280
    trace_tbl_h = 240
    trace_ids = [
        "CAP-I3-IDENTIFY-RETRIEVED-SOURCE",
        "CAP-I4-PROVENANCE-AND-TRUST",
        "CAP-I5-DID-CONTENT-PERSIST",
        "CAP-I6-WRITE-TO-RECALL",
        "CAP-I7-WHAT-RECALL-INFLUENCED",
    ]
    trace_structure = [
        block("viz_trace_md", 0, 0, FULL, trace_intro_h),
        block("viz_trace_rag", 0, trace_intro_h, HALF, trace_tbl_h),
        block("viz_trace_mem", HALF, trace_intro_h, HALF, trace_tbl_h),
    ]
    stacked, trace_y = stack_notebook(
        trace_ids,
        "tr",
        q_h=280,
        hint_h=160,
        sol_h=480,
        tbl_h=240,
        y0=trace_intro_h + trace_tbl_h,
    )
    trace_structure.extend(stacked)

    auth_intro_h = 280
    auth_tbl_h = 240
    authority_ids = [
        "CAP-I8-REQUESTED-PRIVILEGED-OPERATION",
        "CAP-I9-ACTUAL-CODED-AUTHORITY",
        "CAP-I10-WHO-AUTHORIZED",
        "CAP-I11-DID-EXECUTION-OCCUR",
    ]
    authority_structure = [
        block("viz_auth_md", 0, 0, FULL, auth_intro_h),
        block("viz_auth_who", 0, auth_intro_h, THIRD, auth_tbl_h),
        block("viz_auth_authz", THIRD, auth_intro_h, THIRD, auth_tbl_h),
        block("viz_auth_exec", THIRD * 2, auth_intro_h, THIRD, auth_tbl_h),
        block("viz_auth_params", 0, auth_intro_h + auth_tbl_h, 360, auth_tbl_h),
        block("viz_auth_scope", 360, auth_intro_h + auth_tbl_h, 360, auth_tbl_h),
        block("viz_auth_result", 720, auth_intro_h + auth_tbl_h, 360, auth_tbl_h),
        block("viz_auth_result_trust", 1080, auth_intro_h + auth_tbl_h, 360, auth_tbl_h),
    ]
    stacked, auth_y = stack_notebook(
        authority_ids,
        "au",
        q_h=300,
        hint_h=160,
        sol_h=500,
        tbl_h=240,
        y0=auth_intro_h + auth_tbl_h * 2,
    )
    authority_structure.extend(stacked)

    add_md(
        "viz_defend",
        """
# DEFEND

Defense is not a content wipe. Keep the same adversarial bytes. Change authorization.

**Do not teach these as the defense that changes RETEST**

- sanitize everything
- delete memory
- block all RAG
- trust known provenance
- ask Splunk to block prompts
- invent DET-CAPSTONE
- treat a classifier OBSERVE as a grant or a deny

**What actually changes**

Remove the lab overlay. Keep the same retrieved bytes and the same stored bytes.

- RAG stays **OBSERVE**
- Memory stays **OBSERVE**
- CTRL-MCP-001 **DENY** `tool_not_granted`
- Privileged handler **0**

```text
SAME malicious retrieve
        ↓
SAME memory write / later recall
        ↓
SAME REQUEST lookup_customer_tier
        ↓
CTRL-MCP-001
        ↓
DENY tool_not_granted
        ↓
HANDLER DOES NOT START
```

Influence can remain. Authority does not have to follow.

Splunk does not DENY the tool. The runtime control does.
""",
        title="DEFEND",
    )
    add_md(
        "viz_defend_evidence",
        f"""
# What is not the variable

SAME document family `{MALICIOUS_DOC}`

SAME memory family `{MALICIOUS_MEM}`

SAME fingerprint

{fingerprint_block(MALICIOUS_HASH)}

SAME requested tool `lookup_customer_tier`

SAME requested scope `customer:read`

DIFFERENT ExperimentContext (defended). DIFFERENT CTRL-MCP-001 decision. DIFFERENT execution.

{INFLUENCE_NOT_AUTHORITY}
""",
        title="SAME BYTES",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

**DEFENDED PROFILE** · same adversarial hash · handler **0**

Launch LIVE RETEST from [Attack Service]({ATTACK_URL}). Tables below default to the official LIVE RETEST triple. Fresh launches mint new ids.

- RAG **OBSERVE** on retrieve `{RETEST_RETRIEVE}`
- Memory **OBSERVE** on write `{RETEST_WRITE}` / recall `{RETEST_RECALL}`
- SAME request `lookup_customer_tier` / `customer:read`
- CTRL-MCP-001 **DENY** `tool_not_granted`
- Privileged handler **0**

SAME fingerprint as ATTACK

{fingerprint_block(MALICIOUS_HASH)}

Runtime handler count is authoritative for non-execution. Missing indexed `mcp.started` is corroboration on a complete copy. Do not treat Splunk as independent prevention proof.

```text
retrieve OBSERVE → write → later recall OBSERVE → REQUEST → DENY → handler 0
```

Do not label RETEST SAFE. Do not claim universal RAG/memory resistance.
""",
        title="SAME HASH · DIFFERENT DECISION",
    )
    add_table(
        "viz_retest_rag",
        "ds_q_rag_r",
        "RETEST retrieve — Q-RAG-CONTEXT-AUTHORITY",
        cap_rag + " Literal RETEST retrieve. Expect OBSERVE and the SAME malicious hash.",
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_retest_mem",
        "ds_q_mem_r",
        "RETEST write + recall — Q-MEMORY-CONTEXT-AUTHORITY",
        cap_mem + " Literal RETEST write/recall. Expect OBSERVE plus follow-on DENY.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_r",
        "RETEST recall — Q-MCP-AUTHZ",
        cap_authz + " Literal RETEST recall. Expect hop-1 DENY tool_not_granted.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_exec_r",
        "RETEST recall — Q-MCP-EXECUTED",
        cap_exec + " Literal RETEST recall. Expect no_indexed_followon_execution_event. Handler 0 is runtime.",
        no_data=EMPTY_TOOL,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_r",
        "RETEST recall — Q-MCP-TOOL",
        cap_tool + " Literal RETEST recall. Empty start is corroboration, not independent prevention.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

**SAME ADVERSARIAL INFLUENCE. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

Lists below are the proof. Color is not the proof.

```text
BASELINE:  normal bytes → OBSERVE → no privileged follow-on → handler 0
ATTACK:    malicious bytes → OBSERVE → REQUEST → ALLOW → handler 1
RETEST:    SAME malicious bytes → OBSERVE → REQUEST → DENY → handler 0
```

Cards default to the official LIVE pair. Fresh LIVE triples come from Attack Service Search.
""",
        title="PRIMARY STATEMENT",
    )
    add_md(
        "viz_cmp_card_base",
        f"""
# BASELINE

**defended · normal fixture · handler 0**

**SAME as the other modes**

- Three run.ids: retrieve, write, later recall
- RAG classifier OBSERVE
- Memory classifier OBSERVE
- Schema 1.9.0
- Splunk is evidence, not enforcement

**DIFFERENT from ATTACK / RETEST**

- document `{NORMAL_DOC}`
- memory `{NORMAL_MEM}`
- no privileged `lookup_customer_tier` follow-on
- no labeled fail-open
- handler **0**

Fingerprint

{fingerprint_block(NORMAL_HASH)}

Official LIVE retrieve `{BASELINE_RETRIEVE}`

Official LIVE write `{BASELINE_WRITE}`

Official LIVE recall `{BASELINE_RECALL}`

Do not label SAFE.
""",
        title="BASELINE",
    )
    add_md(
        "viz_cmp_card_atk",
        f"""
# ATTACK

**INTENTIONALLY VULNERABLE LAB PROFILE · handler 1**

**SAME as RETEST**

- document `{MALICIOUS_DOC}`
- memory `{MALICIOUS_MEM}`
- content.hash (full):

{fingerprint_block(MALICIOUS_HASH)}

- provenance `{PROVENANCE_RAG}` / `{PROVENANCE_MEM}` (identity, not trust)
- requested tool `lookup_customer_tier`
- requested scope `customer:read`
- RAG OBSERVE · Memory OBSERVE

**DIFFERENT from RETEST**

- ExperimentContext: vulnerable
- CTRL-MCP-001 **ALLOW** labeled fail-open
- mcp.started / completed on a complete copy
- privileged handler **1**
- run.ids are a different triple

Official LIVE retrieve `{ATTACK_RETRIEVE}`

Official LIVE write `{ATTACK_WRITE}`

Official LIVE recall `{ATTACK_RECALL}`

The bytes did not grant the tool.
""",
        title="ATTACK",
    )
    add_md(
        "viz_cmp_card_rt",
        f"""
# RETEST

**defended · SAME malicious bytes · handler 0**

**SAME as ATTACK**

- document `{MALICIOUS_DOC}`
- memory `{MALICIOUS_MEM}`
- content.hash (full):

{fingerprint_block(MALICIOUS_HASH)}

- requested tool `lookup_customer_tier`
- requested scope `customer:read`
- RAG OBSERVE · Memory OBSERVE

**DIFFERENT from ATTACK**

- ExperimentContext: defended
- CTRL-MCP-001 **DENY** `tool_not_granted`
- no privileged handler start
- privileged handler **0**
- run.ids are a different triple

Official LIVE retrieve `{RETEST_RETRIEVE}`

Official LIVE write `{RETEST_WRITE}`

Official LIVE recall `{RETEST_RECALL}`

SAME influence. DIFFERENT authorization. DIFFERENT execution.
""",
        title="RETEST",
    )
    add_table(
        "viz_cmp_rag_b",
        "ds_q_rag_b",
        "BASELINE RAG",
        cap_rag + " Expect NORMAL hash. Not SAFE.",
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_cmp_rag_a",
        "ds_q_rag_a",
        "ATTACK RAG",
        cap_rag + " Expect SAME malicious hash as RETEST.",
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_cmp_rag_r",
        "ds_q_rag_r",
        "RETEST RAG",
        cap_rag + " Expect SAME malicious hash as ATTACK.",
        no_data=EMPTY_RAG,
    )
    add_table(
        "viz_cmp_mem_b",
        "ds_q_mem_b",
        "BASELINE MEMORY",
        cap_mem + " Expect no privileged follow-on.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_cmp_mem_a",
        "ds_q_mem_a",
        "ATTACK MEMORY",
        cap_mem + " Expect SAME malicious hash as RETEST plus ALLOW.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_cmp_mem_r",
        "ds_q_mem_r",
        "RETEST MEMORY",
        cap_mem + " Expect SAME malicious hash as ATTACK plus DENY.",
        no_data=EMPTY_MEM,
    )
    add_table(
        "viz_cmp_authz_b",
        "ds_q_authz_b",
        "BASELINE AUTHZ",
        cap_authz + " Expect no privileged hop-1 grant.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_cmp_authz_a",
        "ds_q_authz_a",
        "ATTACK AUTHZ",
        cap_authz + " Expect hop-1 ALLOW labeled fail-open.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_cmp_authz_r",
        "ds_q_authz_r",
        "RETEST AUTHZ",
        cap_authz + " Expect hop-1 DENY tool_not_granted.",
        no_data=EMPTY_CONTROL,
    )
    add_table(
        "viz_cmp_exec_b",
        "ds_q_exec_b",
        "BASELINE EXECUTED",
        cap_exec + " Expect no privileged handler start.",
        no_data=EMPTY_TOOL,
    )

    add_md(
        "viz_prove",
        f"""
# PROVE

Classify each claim. Do not upgrade expected results into measured LIVE results. Path B is an answer key.

**SUPPORTED** — runtime or control evidence in this experiment can carry the claim.

**CORROBORATED** — Splunk copy agrees, on a complete export, but is not the authority.

**NOT PROVEN** — the packet does not establish it.

**INCORRECT** — the claim contradicts the security model or the evidence.

## Claims

**The retrieved document granted customer:read.** — INCORRECT

**The memory record granted lookup_customer_tier.** — INCORRECT

**CTRL-MCP-001 authorized the tool.** — ATTACK SUPPORTED when the recall control row is ALLOW. RETEST would be DENY `tool_not_granted`.

**Splunk prevented the attack.** — INCORRECT

**The privileged handler executed during ATTACK.** — SUPPORTED when runtime handler count is 1. Indexed `mcp.started` is CORROBORATED on a complete copy.

**The privileged handler did not execute during RETEST.** — SUPPORTED when runtime handler count is 0. Missing `mcp.started` is corroboration only.

**RETEST proves the application is secure against all RAG/memory attacks.** — INCORRECT

**Missing telemetry proves prevention.** — INCORRECT

## Also not proven

- WHO AUTHENTICATED (no auth stack)
- Goal Integrity failure caused this incident
- Identity/Delegation failure caused this incident
- Completeness of the Splunk copy without a local vs indexed count
- Universal resistance after one RETEST

## DET-MCP-001

DET-MCP-001 looks for DENY then later `mcp.started` for the same tool. It may return **0 rows** on ATTACK (ALLOW path) and RETEST (DENY respected).

0 rows != SAFE. 0 rows != prevention. **No DET-CAPSTONE.**

Right table is **SIMULATED** `| makeresults`. Not indexed. Not this LIVE packet.

## Debrief

Answer from evidence, not from the lab title.

- What was the attack chain?
- Where did untrusted influence enter?
- Which components only observed?
- Which component authorized?
- What executed, and what proves that versus what only corroborates it?
- What stayed identical in RETEST, what changed, and why?
- What can you not conclude?

Multiple influence planes can exist. Authority still requires an enforcement decision. Splunk reconstructed a copy. Splunk did not enforce.

## Learning connection

- **PI** — untrusted input can influence
- **MCP** — request is not grant
- **RAG** — retrieved context is data
- **MEMORY** — stored context is not authority
- **GOAL** — authorized tool does not imply authorized purpose
- **IDENTITY** — claims do not mint grants
- **CAPSTONE** — multiple influence planes may exist; authority still requires an enforcement decision

This packet does **not** replay every previous vulnerability. Goal and Identity event families are expected absent here.

**NEXT** — [Mastery Check](http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_mastery) is reasoning validation after Capstone. It is not a certificate, not a score, and not another lab.

## Limits

Schema **1.9.0**. No retrieve-to-write field. Fresh LIVE ids come from Attack Service Search, not token writes.

{RUNTIME_AUTH}

{INFLUENCE_NOT_AUTHORITY}
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_seq",
        "ds_seq",
        "Investigate specimen sequence",
        cap_seq,
        no_data=EMPTY_SEQ,
    )
    add_table(
        "viz_prove_after_a",
        "ds_q_after_a",
        "DET-MCP-001 / Q-MCP-AFTER-DENY ATTACK recall",
        cap_after + " ATTACK 0: ALLOW path.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_prove_after_r",
        "ds_q_after_r",
        "DET-MCP-001 / Q-MCP-AFTER-DENY RETEST recall",
        cap_after + " RETEST 0: DENY respected.",
        no_data=EMPTY_AFTER,
    )
    add_table(
        "viz_prove_sim",
        "ds_det_mcp_001_sim",
        "DET-MCP-001-POSITIVE-CONTROL (SIMULATED)",
        "Always one fixture row labeled SIMULATED. DENY then mcp.started. Not this capstone LIVE packet. No DET-CAPSTONE.",
        no_data="SIMULATED search returned no fixture row. Re-check DET-MCP-001-POSITIVE-CONTROL.spl (makeresults).",
    )
    add_table(
        "viz_prove_run",
        "ds_q_run",
        "Q-RUN-EVENTS (three tokens)",
        cap_run,
        no_data=EMPTY_HUNT,
    )
    add_table(
        "viz_prove_goal",
        "ds_q_goal",
        "Q-GOAL-INTEGRITY-AUTHORITY (three tokens)",
        cap_goal,
        no_data=EMPTY_ABSENT,
    )
    add_table(
        "viz_prove_ident",
        "ds_q_ident",
        "Q-AGENT-DELEGATION-AUTHORITY (three tokens)",
        cap_ident,
        no_data=EMPTY_ABSENT,
    )
    add_table(
        "viz_prove_after",
        "ds_q_after",
        "Q-MCP-AFTER-DENY (recall specimen)",
        cap_after + " Token-bound recall. Zero rows is not SAFE.",
        no_data=EMPTY_AFTER,
    )

    definition = {
        "title": "Lending Assistant Investigation",
            "description": (
                "Lending Assistant Investigation. Splunk does not ALLOW or DENY."
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
            "input_retrieve_run_id": {
                "type": "input.dropdown",
                "title": "Investigate retrieve specimen",
                "options": {
                    "token": "retrieve_run_id",
                    "defaultValue": BASELINE_RETRIEVE,
                    "items": [
                        {
                            "label": "Baseline retrieve — defended / normal",
                            "value": BASELINE_RETRIEVE,
                        },
                        {
                            "label": "Attack retrieve — vulnerable / malicious",
                            "value": ATTACK_RETRIEVE,
                        },
                        {
                            "label": "Retest retrieve — defended / malicious",
                            "value": RETEST_RETRIEVE,
                        },
                    ],
                },
            },
            "input_write_run_id": {
                "type": "input.dropdown",
                "title": "Investigate write specimen",
                "options": {
                    "token": "write_run_id",
                    "defaultValue": BASELINE_WRITE,
                    "items": [
                        {
                            "label": "Baseline write — defended / normal",
                            "value": BASELINE_WRITE,
                        },
                        {
                            "label": "Attack write — vulnerable / malicious",
                            "value": ATTACK_WRITE,
                        },
                        {
                            "label": "Retest write — defended / malicious",
                            "value": RETEST_WRITE,
                        },
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
                        {
                            "label": "Baseline recall — defended / normal",
                            "value": BASELINE_RECALL,
                        },
                        {
                            "label": "Attack recall — vulnerable / malicious",
                            "value": ATTACK_RECALL,
                        },
                        {
                            "label": "Retest recall — defended / malicious",
                            "value": RETEST_RECALL,
                        },
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
                "input_retrieve_run_id",
                "input_write_run_id",
                "input_run_id",
            ],
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_mission", "label": "MISSION"},
                    {"layoutId": "layout_architecture", "label": "ARCHITECTURE"},
                    {"layoutId": "layout_attack", "label": "ATTACK"},
                    {"layoutId": "layout_investigate", "label": "INVESTIGATE"},
                    {"layoutId": "layout_trace", "label": "TRACE"},
                    {"layoutId": "layout_authority", "label": "AUTHORITY"},
                    {"layoutId": "layout_defend", "label": "DEFEND"},
                    {"layoutId": "layout_retest", "label": "RETEST"},
                    {"layoutId": "layout_compare", "label": "COMPARE"},
                    {"layoutId": "layout_prove", "label": "PROVE"},
                ],
            },
            "layoutDefinitions": {
                "layout_mission": layout(
                    [
                        block("viz_mission", 0, 0, FULL, 560),
                        block("viz_mission_limits", 0, 560, FULL, 420),
                        block("viz_predict_attack", 0, 980, HALF, 560),
                        block("viz_predict_retest", HALF, 980, HALF, 560),
                    ],
                    1560,
                ),
                "layout_architecture": layout(
                    [
                        block("viz_arch", 0, 0, FULL, 720),
                        block("viz_arch_planes", 0, 720, FULL, 420),
                    ],
                    1160,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 560),
                        block("viz_attack_rag", 0, 560, FULL, 260),
                        block("viz_attack_mem", 0, 820, FULL, 260),
                        block("viz_attack_authz", 0, 1080, THIRD, 260),
                        block("viz_attack_exec", THIRD, 1080, THIRD, 260),
                        block("viz_attack_tool", THIRD * 2, 1080, THIRD, 260),
                    ],
                    1360,
                ),
                "layout_investigate": layout(investigate_structure, inv_y + 40),
                "layout_trace": layout(trace_structure, trace_y + 40),
                "layout_authority": layout(authority_structure, auth_y + 40),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 720),
                        block("viz_defend_evidence", 0, 720, FULL, 420),
                    ],
                    1160,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 560),
                        block("viz_retest_rag", 0, 560, FULL, 260),
                        block("viz_retest_mem", 0, 820, FULL, 260),
                        block("viz_retest_authz", 0, 1080, HALF, 260),
                        block("viz_retest_exec", HALF, 1080, HALF, 260),
                        block("viz_retest_tool", 0, 1340, FULL, 260),
                    ],
                    1620,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 280),
                        block("viz_cmp_card_base", 0, 280, THIRD, 820),
                        block("viz_cmp_card_atk", THIRD, 280, THIRD, 820),
                        block("viz_cmp_card_rt", THIRD * 2, 280, THIRD, 820),
                        block("viz_cmp_rag_b", 0, 1100, THIRD, 240),
                        block("viz_cmp_rag_a", THIRD, 1100, THIRD, 240),
                        block("viz_cmp_rag_r", THIRD * 2, 1100, THIRD, 240),
                        block("viz_cmp_mem_b", 0, 1340, THIRD, 240),
                        block("viz_cmp_mem_a", THIRD, 1340, THIRD, 240),
                        block("viz_cmp_mem_r", THIRD * 2, 1340, THIRD, 240),
                        block("viz_cmp_authz_b", 0, 1580, THIRD, 240),
                        block("viz_cmp_authz_a", THIRD, 1580, THIRD, 240),
                        block("viz_cmp_authz_r", THIRD * 2, 1580, THIRD, 240),
                        block("viz_cmp_exec_b", 0, 1820, FULL, 240),
                    ],
                    2080,
                ),
                "layout_prove": layout(
                    [
                        block("viz_prove", 0, 0, FULL, 1400),
                        block("viz_prove_seq", 0, 1400, FULL, 260),
                        block("viz_prove_after_a", 0, 1660, HALF, 240),
                        block("viz_prove_after_r", HALF, 1660, HALF, 240),
                        block("viz_prove_sim", 0, 1900, FULL, 240),
                        block("viz_prove_run", 0, 2140, FULL, 240),
                        block("viz_prove_goal", 0, 2380, HALF, 240),
                        block("viz_prove_ident", HALF, 2380, HALF, 240),
                        block("viz_prove_after", 0, 2620, FULL, 240),
                    ],
                    2880,
                ),
            },
        },
        "applicationProperties": {
            "collapseNavigation": False,
            "downsampleVisualizations": False,
        },
    }
    _ = (TEAL, SECONDARY, BORDER, EMPTY_EVENT, INVESTIGATE_IDS, TRACE_IDS, AUTHORITY_IDS)
    validate_definition(definition)
    return definition


def validate_definition(definition: dict) -> None:
    data_sources = definition["dataSources"]
    visualizations = definition["visualizations"]
    used = set()
    for viz_id, viz in visualizations.items():
        ds = viz.get("dataSources", {}).get("primary")
        if ds:
            used.add(ds)
            if ds not in data_sources:
                raise ValueError(f"{viz_id} uses missing dataSource {ds}")
    unused = set(data_sources) - used
    if unused:
        raise ValueError(f"unused dataSources: {sorted(unused)}")
    created = set(data_sources) | {viz.get("title", "") for viz in visualizations.values()}
    if any("Q-CAPSTONE" in name or "DET-CAPSTONE" in name for name in created):
        raise ValueError("definition must not create Q-CAPSTONE or DET-CAPSTONE objects")
    title = definition["title"]
    if title != "Lending Assistant Investigation":
        raise ValueError(f"unexpected title {title}")
    if "RAG Memory MCP" in title:
        raise ValueError("forbidden title")
    labels = [item["label"] for item in definition["layout"]["tabs"]["items"]]
    expected = [
        "MISSION",
        "ARCHITECTURE",
        "ATTACK",
        "INVESTIGATE",
        "TRACE",
        "AUTHORITY",
        "DEFEND",
        "RETEST",
        "COMPARE",
        "PROVE",
    ]
    if labels != expected:
        raise ValueError(f"tab labels {labels} != {expected}")
    for token_name in ("retrieve_run_id", "write_run_id", "run_id"):
        found = [
            inp
            for inp in definition["inputs"].values()
            if inp["options"]["token"] == token_name
        ]
        if len(found) != 1:
            raise ValueError(f"token {token_name} missing")
        if "Investigate" not in found[0]["title"]:
            raise ValueError(f"token title must contain Investigate: {found[0]['title']}")
    layout_opts = definition["layout"]["options"]
    if layout_opts["submitButton"] is not False:
        raise ValueError("submitButton must be false")
    if layout_opts["submitOnDashboardLoad"] is not True:
        raise ValueError("submitOnDashboardLoad must be true")
    ds_names = {ds["name"] for ds in definition["dataSources"].values()}
    if any(name.startswith("Q-CAPSTONE") or name.startswith("DET-CAPSTONE") for name in ds_names):
        raise ValueError("definition must not create Q-CAPSTONE or DET-CAPSTONE searches")


def write_xml(definition: dict) -> None:
    payload = json.dumps(definition, indent=2, ensure_ascii=False)
    if "]]>" in payload:
        raise ValueError("definition contains CDATA terminator")
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<dashboard version="2" theme="light">\n'
        "  <label>Lending Assistant Investigation</label>\n"
        "  <description>Lending Assistant Investigation. Splunk does not ALLOW or DENY.</description>\n"
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
    tabs = ", ".join(item["label"] for item in definition["layout"]["tabs"]["items"])
    tokens = ", ".join(inp["options"]["token"] for inp in definition["inputs"].values())
    sources = ", ".join(sorted(definition["dataSources"]))
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")
    print(f"tabs: {tabs}")
    print(f"tokens: {tokens}")
    print(f"dataSources: {sources}")


if __name__ == "__main__":
    main()