#!/usr/bin/env python3
"""Build the LAB-MCP-CATALOG Dashboard Studio definition.

Q-MCP files from LAB-MCP-001 are unchanged except replacing __RUN_ID__ with a
quoted Studio token. Q-MCP-CATALOG-AUTHORITY is the catalog primary hunt.
DET-MCP-001.spl is not modified. The DETECT fixture is DET-MCP-001-POSITIVE-CONTROL
(SIMULATED). No DET-MCP-CATALOG.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
CATALOG_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-CATALOG" / "searches"
OUT_JSON = ROOT / "learning" / "level_1" / "LAB-MCP-CATALOG" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_mcp_catalog.xml"
)

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

BASELINE_ID = "d95717ed-ffd2-46c0-a130-9a5d7d539a5d"
ATTACK_ID = "a0937bff-31a5-453a-99bf-47d7b5148ce4"
RETEST_ID = "23c222ea-6a87-40b7-a3e9-f12a5b572fa1"
NORMAL_HASH = "sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3"
MALICIOUS_HASH = "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_HUNT = (
    "Investigate specimen defaults to the BASELINE specimen so this page is not an error "
    "state. Custom run.id is available from Search. Zero rows means "
    "no indexed CTRL-MCP-METADATA-001 for that id. Zero rows is not DENY and is not "
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
META_NOT_AUTHZ = (
    "REQUEST ≠ GRANT. OBSERVE ≠ ALLOW. METADATA PROVENANCE ≠ CONTENT TRUST. "
    "AUTHORIZED TOOL ≠ TRUSTED DESCRIPTION. The description is not authorized."
)
EXECUTED_NOTE = (
    "Control-event executed=false is not handler non-execution. METADATA-001 "
    "OBSERVE may inherit lookup_policy execution_state because Q-MCP-EXECUTED "
    "groups by run.id + tool. Do not read that as metadata executed or OBSERVE "
    "caused execution."
)


def load_spl(name: str, *, catalog: bool = False) -> str:
    directory = CATALOG_DIR if catalog else SEARCH_DIR
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
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval control_type=mvindex(mvdedup('agentsec.control.type'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval metadata_trust=mvindex(mvdedup('agentsec.mcp.metadata.trust'),0)
| eval metadata_provenance=mvindex(mvdedup('agentsec.mcp.metadata.provenance'),0)
| eval content_hash=mvindex(mvdedup('agentsec.content.hash'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| eval profile=mvindex(mvdedup('agentsec.security.profile'),0)
| eval mode=mvindex(mvdedup('agentsec.testbed.mode'),0)
| table sequence, run_id, profile, mode, event_name, hop, control_id, control_type, decision, reason, tool, metadata_trust, metadata_provenance, content_hash, outcome
| sort sequence"""


def what_happened_spl(token: str) -> str:
    return bind_run_id(load_spl("Q-MCP-CATALOG-AUTHORITY.spl", catalog=True), token)


def build() -> dict:
    q_who = bind_run_id(load_spl("Q-MCP-WHO.spl"), "run_id")
    q_authz = bind_run_id(load_spl("Q-MCP-AUTHZ.spl"), "run_id")
    q_tool = bind_run_id(load_spl("Q-MCP-TOOL.spl"), "run_id")
    q_executed = bind_run_id(load_spl("Q-MCP-EXECUTED.spl"), "run_id")
    q_after = bind_run_id(load_spl("Q-MCP-AFTER-DENY.spl"), "run_id")
    q_catalog = bind_run_id(load_spl("Q-MCP-CATALOG-AUTHORITY.spl", catalog=True), "run_id")
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
            search_ds("ds_q_executed", "Q-MCP-EXECUTED", q_executed),
            search_ds("ds_q_after_deny", "Q-MCP-AFTER-DENY", q_after),
            search_ds("ds_q_catalog", "Q-MCP-CATALOG-AUTHORITY", q_catalog),
            search_ds(
                "ds_det_mcp_001_sim",
                "DET-MCP-001-POSITIVE-CONTROL",
                load_spl("DET-MCP-001-POSITIVE-CONTROL.spl"),
            ),
            search_ds("ds_observe_seq", "MCP-CATALOG observe sequence", observe_sequence_spl("run_id")),
            search_ds("ds_what_baseline", "What Happened BASELINE", what_happened_spl(BASELINE_ID)),
            search_ds("ds_what_attack", "What Happened ATTACK", what_happened_spl(ATTACK_ID)),
            search_ds("ds_what_retest", "What Happened RETEST", what_happened_spl(RETEST_ID)),
            search_ds("ds_q_authz_baseline", "Q-MCP-AUTHZ BASELINE", q_authz_b),
            search_ds("ds_q_authz_attack", "Q-MCP-AUTHZ ATTACK", q_authz_a),
            search_ds("ds_q_authz_retest", "Q-MCP-AUTHZ RETEST", q_authz_r),
            search_ds("ds_q_tool_baseline", "Q-MCP-TOOL BASELINE", q_tool_b),
            search_ds("ds_q_tool_attack", "Q-MCP-TOOL ATTACK", q_tool_a),
            search_ds("ds_q_tool_retest", "Q-MCP-TOOL RETEST", q_tool_r),
            search_ds("ds_q_executed_baseline", "Q-MCP-EXECUTED BASELINE", q_exec_b),
            search_ds("ds_q_executed_attack", "Q-MCP-EXECUTED ATTACK", q_exec_a),
            search_ds("ds_q_executed_retest", "Q-MCP-EXECUTED RETEST", q_exec_r),
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
        "It can be a wrong run.id or an incomplete copy."
    )
    empty_tool = (
        "No indexed follow-on MCP execution event was found for this run. That does not "
        "automatically mean DENY. ERROR, schema failure, and export loss also look like zero rows."
    )
    empty_after = (
        "No indexed DENY followed later by mcp.started was found. "
        "That does not independently prove the handler never executed. Runtime handler count remains authoritative."
    )
    empty_what = (
        "No indexed CTRL-MCP-METADATA-001 was found for this run. The dashboard will not "
        "invent trusted metadata, a grant, or prevention from an empty table."
    )
    empty_seq = (
        "No indexed control or mcp.* events were found for this run. Ordering cannot "
        "be shown. That is not a security outcome."
    )
    empty_catalog = (
        "Q-MCP-CATALOG-AUTHORITY returned zero rows. This hunt requires CTRL-MCP-METADATA-001. "
        "Zero rows is not safe, not DENY, and not proof metadata-derived authority was refused."
    )
    cap_what = (
        "Q-MCP-CATALOG-AUTHORITY (data-driven What Happened). One row per run.id with "
        "metadata trust, provenance, description hash, METADATA-001 OBSERVE, first "
        "lookup_policy grant, follow-on decision, and execution observation. Hash is "
        "the fingerprint. Do not treat OBSERVE as authorization."
    )
    cap_authz = (
        "Q-MCP-AUTHZ control.decision rows. Extra METADATA-001 OBSERVE row is classification, "
        "not a grant. executed here is the control-event field (false on ALLOW). "
        "It is not handler execution. Do not collapse METADATA-001 into CTRL-MCP-001."
    )
    cap_catalog = (
        "Q-MCP-CATALOG-AUTHORITY (primary catalog hunt). metadata_trust=untrusted_data. "
        "derived_authority is a display helper from the follow-on reason, not a detector. "
        "Do not read hop-1 ALLOW as authorization of the description."
    )
    cap_tool = "Q-MCP-TOOL mcp.started rows. Zero rows is not automatically DENY."
    cap_executed = (
        "Q-MCP-EXECUTED. " + EXECUTED_NOTE + " Read has_started and execution_state for "
        "whether the handler began."
    )
    cap_who = (
        "Q-MCP-WHO. Extra METADATA-001 row has empty mcp.method.name. That is not a second tool."
    )
    cap_seq = (
        "Ordered control then mcp.* events. METADATA-001 is hop 0 OBSERVE. CTRL-MCP-001 is "
        "the grant. Hash is the description fingerprint. Preview and _raw are not shown."
    )

    add_md(
        "viz_learn",
        f"""
# Tool Catalog

Investigate why legitimate tool metadata must not determine the grant.

**LIVE EVIDENCE** · `LAB-MCP-CATALOG` · Schema 1.5.0 · CTRL-MCP-METADATA-001

**A legitimate tool can still carry untrusted catalog metadata. Metadata may influence a REQUEST. Metadata must not determine the GRANT.**

{META_NOT_AUTHZ}

**Phase 8D LIVE evidence identity**

BASELINE `{BASELINE_ID}`

ATTACK `{ATTACK_ID}`

RETEST `{RETEST_ID}`

Ladder: MCP-001 tool → MCP-003 scope → MCP-004 resource → MCP-005 result data → MCP-006 deputy authority → **MCP-CATALOG tool metadata**. These are not the only MCP problems. Splunk does **not** ALLOW or DENY.
""",
        title="LEARN",
    )
    add_md(
        "viz_learn_meta",
        """
# METADATA vs TOOL

**Catalog metadata:** tool `description` bytes (hash + bounded preview).

**Tool:** `lookup_policy` is a legitimate, granted tool.

**Trust:** `untrusted_data` — always data, never a grant.

**Provenance:** `mcp.catalog.snapshot` — where the bytes came from, not whether they are trusted.

Malicious metadata ≠ malicious tool.
""",
        title="METADATA / TOOL",
    )
    add_md(
        "viz_learn_req",
        """
# REQUEST vs GRANT

Metadata may change what an agent **asks for next**.

CTRL-MCP-001 still decides what the server **grants**.

```text
MCP catalog
  → Tool metadata
  → Agent observes metadata
  → Agent may form a request
  → CTRL-MCP-001
  → Handler only after ALLOW
```

REQUEST ≠ GRANT. OBSERVE ≠ ALLOW.
""",
        title="REQUEST / GRANT",
    )
    add_md(
        "viz_learn_trust",
        """
# Trust boundary

Catalog snapshot → METADATA-001 OBSERVE `metadata_is_data` → CTRL-MCP-001 (tool grant) → **Handler only after ALLOW**

The defended boundary is still CTRL-MCP-001. METADATA-001 classifies. It does not authorize.

Rejected / not published: Q-MCP-CATALOG-METADATA · TRUST · FINGERPRINT · FOLLOWON · AUTHZ
""",
        title="TRUST BOUNDARY",
    )

    add_md(
        "viz_baseline_md",
        f"""
# BASELINE

profile = **defended** · mode = **BASELINE** · catalog = **NORMAL**

The catalog metadata was treated as data. The granted lookup_policy call was authorized separately and executed. No follow-on tool request was produced.

- METADATA-001: **OBSERVE** `metadata_is_data` (not ALLOW, not DENY)
- Hash: `{NORMAL_HASH}`
- First tool: `lookup_policy` CTRL-MCP-001 **ALLOW** `tool_granted`
- Then: `mcp.started` · `mcp.completed`
- Follow-on: **NONE**

Do not label this **SAFE**. OBSERVE is classification. The first grant is a separate fact.

Validated: `{BASELINE_ID}`. Tables use the **BASELINE** token.

{ALLOW_NOT_EXEC}
""",
        title="STEP 1 BASELINE",
    )
    add_table(
        "viz_baseline_what",
        "ds_what_baseline",
        "What Happened? Q-MCP-CATALOG-AUTHORITY",
        cap_what + " Expect OBSERVE, derived_authority=absent, no_followon.",
        no_data=empty_what,
    )
    add_table(
        "viz_baseline_authz",
        "ds_q_authz_baseline",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect METADATA-001 OBSERVE then CTRL-MCP-001 ALLOW.",
        no_data=empty_control,
    )
    add_table(
        "viz_baseline_tool",
        "ds_q_tool_baseline",
        "Q-MCP-TOOL",
        cap_tool + " Expect mcp.started for lookup_policy only.",
        no_data=empty_tool,
    )
    add_table(
        "viz_baseline_exec",
        "ds_q_executed_baseline",
        "Q-MCP-EXECUTED",
        cap_executed + " Extra OBSERVE row may show mcp.completed for lookup_policy. That is not metadata execution.",
        no_data=empty_tool,
    )

    add_md(
        "viz_attack_md",
        f"""
# ATTACK

profile = **vulnerable** · mode = **ATTACK** · catalog = **MALICIOUS**

**INTENTIONALLY VULNERABLE LAB BEHAVIOR** — not a production exploit.

The DESCRIPTION was not authorized. The FOLLOW-ON REQUEST was improperly granted by the vulnerable authorization path.

```text
METADATA-001 OBSERVE metadata_is_data
  → lookup_policy ALLOW tool_granted + execute + complete
  → follow-on REQUEST lookup_customer_tier
  → CTRL-MCP-001 ALLOW
     reason = vulnerable_profile_fail_open:metadata_derived_authority
  → mcp.started + mcp.completed
```

Fingerprint (hash, not preview): `{MALICIOUS_HASH}`

Q-MCP-AUTHZ may show hop-1 `lookup_customer_tier` first. That ALLOW is the vulnerable follow-on grant, **not** description authorization. METADATA-001 stays OBSERVE. First tool `lookup_policy` remains ALLOW `tool_granted`.

Runtime follow-on handler **1**. Validated: `{ATTACK_ID}`. Tables use the **ATTACK** token.
""",
        title="STEP 2 ATTACK",
    )
    add_table(
        "viz_attack_what",
        "ds_what_attack",
        "What Happened? Q-MCP-CATALOG-AUTHORITY",
        cap_what + " Expect OBSERVE, derived_authority=present, follow-on ALLOW, mcp.completed_observed.",
        no_data=empty_what,
    )
    add_table(
        "viz_attack_authz",
        "ds_q_authz_attack",
        "Q-MCP-AUTHZ",
        cap_authz + " METADATA-001 stays OBSERVE. Hop-1 CTRL-MCP-001 ALLOW is the vulnerable grant, not description authz.",
        no_data=empty_control,
    )
    add_table(
        "viz_attack_tool",
        "ds_q_tool_attack",
        "Q-MCP-TOOL",
        cap_tool + " Expect lookup_policy then lookup_customer_tier mcp.started.",
        no_data=empty_tool,
    )
    add_table(
        "viz_attack_exec",
        "ds_q_executed_attack",
        "Q-MCP-EXECUTED",
        cap_executed + " Follow-on lookup_customer_tier has_started=1. Extra OBSERVE row is not metadata execution.",
        no_data=empty_tool,
    )

    add_md(
        "viz_observe_md",
        f"""
# OBSERVE

Use **Hunt run.id** (defaults to BASELINE). Tables are telemetry, not a story. Hash is the fingerprint. Full descriptions and `_raw` are not shown.

{META_NOT_AUTHZ}

{EMPTY_HUNT}
""",
        title="STEP 3 OBSERVE",
    )
    add_table("viz_observe_seq", "ds_observe_seq", "Control then MCP events (ordered)", cap_seq, no_data=empty_seq)
    add_table("viz_observe_catalog", "ds_q_catalog", "AUTHORITY — Q-MCP-CATALOG-AUTHORITY", cap_catalog, no_data=empty_catalog)
    add_table("viz_observe_authz", "ds_q_authz", "CONTROL — Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_observe_tool", "ds_q_tool", "EXECUTION START — Q-MCP-TOOL", cap_tool, no_data=empty_tool)
    add_table("viz_observe_exec", "ds_q_executed", "EXECUTION — Q-MCP-EXECUTED", cap_executed, no_data=empty_tool)

    add_md(
        "viz_hunt_md",
        f"""
# HUNT

**Question:** What catalog metadata did this run observe, how was it classified, and how was any follow-on authorized?

**Primary hunt:** Q-MCP-CATALOG-AUTHORITY. **Reuse:** Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED. **Rejected / not published:** Q-MCP-CATALOG-METADATA, Q-MCP-CATALOG-TRUST, Q-MCP-CATALOG-FINGERPRINT, Q-MCP-CATALOG-FOLLOWON, Q-MCP-CATALOG-AUTHZ.

Q-MCP-RESULT-AUTHORITY returns zero rows here (looks for RESULT-001). Do not invent `gen_ai.tool.call.id`. Compare ATTACK/RETEST by **hash**, not preview.

{ALLOW_NOT_EXEC} {EXECUTED_NOTE}

{EMPTY_HUNT}
""",
        title="STEP 4 HUNT",
    )
    add_table("viz_hunt_catalog", "ds_q_catalog", "Q-MCP-CATALOG-AUTHORITY (primary catalog hunt)", cap_catalog, no_data=empty_catalog)
    add_table("viz_hunt_authz", "ds_q_authz", "Q-MCP-AUTHZ", cap_authz, no_data=empty_control)
    add_table("viz_hunt_tool", "ds_q_tool", "Q-MCP-TOOL", cap_tool, no_data=empty_tool)
    add_table("viz_hunt_exec", "ds_q_executed", "Q-MCP-EXECUTED", cap_executed, no_data=empty_tool)
    add_table("viz_hunt_who", "ds_q_who", "Q-MCP-WHO", cap_who, no_data=empty_control)

    add_md(
        "viz_detect_md",
        """
# DETECT — DETECTION GAP, not detector failure

No notable event. **No DET-MCP-CATALOG.** This dashboard does **not** enable DET-MCP-001.

DET-MCP-001 detects **DENY → later mcp.started**. Catalog ATTACK is **ALLOW-path** fail-open, so DET-MCP-001 is expected **silent** (LIVE BASELINE 0 · ATTACK 0 · RETEST 0). Zero rows is not "safe" and not "the attack did not occur."

**DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN** for a *lab* teaching signal on the fail-open reason. That string is a poor general production poisoning detector. Not implemented.

Right table: **SIMULATED** `| makeresults`. **NOT INDEXED.** Not OBSERVED runtime. Not a LIVE catalog attack.
""",
        title="STEP 5 DETECT",
    )
    add_table(
        "viz_detect_live",
        "ds_q_after_deny",
        "Q-MCP-AFTER-DENY (indexed hunt)",
        "Investigation query. LIVE catalog specimens: 0 rows. DET-MCP-001 silent on ATTACK vulnerable ALLOW. Zero rows is not 'the attack did not occur.'",
        no_data=empty_after,
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

The defense is **not**: sanitize the description, block the first legitimate tool, trust scanner output, or ask Splunk for permission.

**Security property:** catalog metadata may influence a REQUEST, but server-owned authorization determines the GRANT.

```text
metadata: untrusted_data
first tool lookup_policy: ALLOW (legitimate)
follow-on REQUEST: lookup_customer_tier
coded allowed tools (runtime): lookup_policy
CTRL-MCP-001: DENY tool_not_granted
handler: does not begin
```

{RUNTIME_AUTH}

Splunk did **not** prevent the action. The control did. Scanner PASS ≠ trusted. Scanner FAIL ≠ runtime DENY. Scanners are not wired in this lab.
""",
        title="STEP 6 DEFEND",
    )
    add_md(
        "viz_defend_evidence",
        f"""
# INV-002 on catalog metadata

CTRL-MCP-METADATA-001 asks: how is this description classified? Answer on A/B/C: **OBSERVE** `metadata_is_data`.

CTRL-MCP-001 asks: may this agent call **this tool**? The first `lookup_policy` is granted. The follow-on is not, unless the vulnerable overlay fail-opens.

{META_NOT_AUTHZ}
""",
        title="INV-002",
    )

    add_md(
        "viz_retest_md",
        f"""
# RETEST

profile = **defended** · mode = **RETEST** · catalog = **same MALICIOUS as ATTACK**

ATTACK hash == RETEST hash (indexed METADATA-001):

`{MALICIOUS_HASH}`

Same metadata. Different authorization profile. Metadata did not become authority.

- METADATA-001: **OBSERVE** `metadata_is_data`
- `lookup_policy` ALLOW + execute
- same follow-on REQUEST `lookup_customer_tier`
- CTRL-MCP-001 **DENY** `tool_not_granted`
- runtime follow-on handler count = **0** (authoritative)
- no indexed follow-on mcp.started on a COMPLETE transport copy (corroboration)

Runtime handler count 0 is the authoritative non-execution proof. The complete Splunk copy provides corroborating evidence. Do not say Splunk proves it was blocked.

Q-MCP-AUTHZ should show METADATA-001 OBSERVE, hop-0 `lookup_policy` ALLOW, then hop-1 DENY `tool_not_granted`.

Validated: `{RETEST_ID}`. Tables use the **RETEST** token.
""",
        title="STEP 7 RETEST",
    )
    add_table(
        "viz_retest_what",
        "ds_what_retest",
        "What Happened? Q-MCP-CATALOG-AUTHORITY",
        cap_what + " Expect same hash as ATTACK, OBSERVE, follow-on DENY, no_indexed_followon_execution_event.",
        no_data=empty_what,
    )
    add_table(
        "viz_retest_authz",
        "ds_q_authz_retest",
        "Q-MCP-AUTHZ",
        cap_authz + " Expect METADATA-001 OBSERVE, hop-0 ALLOW, hop-1 DENY tool_not_granted.",
        no_data=empty_control,
    )
    add_table(
        "viz_retest_tool",
        "ds_q_tool_retest",
        "Q-MCP-TOOL",
        "Q-MCP-TOOL. lookup_policy start is expected. No indexed follow-on mcp.started. That is Splunk corroboration. Runtime follow-on handler count = 0 is authoritative.",
        no_data=empty_tool,
    )
    add_table(
        "viz_retest_exec",
        "ds_q_executed_retest",
        "Q-MCP-EXECUTED",
        cap_executed + " Follow-on lookup_customer_tier should show no_mcp_execution_event.",
        no_data=empty_tool,
    )

    add_md(
        "viz_compare_md",
        f"""
# COMPARE

ATTACK and RETEST used the **SAME** malicious metadata. The difference was the authorization profile. Metadata did not become authority in the defended profile.

Fingerprint (hash, not preview): `{MALICIOUS_HASH}`

ATTACK follow-on reason: `vulnerable_profile_fail_open:metadata_derived_authority`. RETEST follow-on reason: `tool_not_granted`.

Three cards, not three giant hunt tables. Indexed reconstruction stays on BASELINE / ATTACK / RETEST What Happened.

{META_NOT_AUTHZ} {RUNTIME_AUTH}
""",
        title="BEFORE / AFTER",
    )
    add_md(
        "viz_cmp_card_base",
        f"""
# BASELINE

**Profile:** defended · **Mode:** BASELINE · **Catalog:** NORMAL

- Hash: `{NORMAL_HASH}`
- METADATA-001: OBSERVE `metadata_is_data`
- First tool: `lookup_policy` ALLOW `tool_granted`
- Follow-on requested: **NO**
- Follow-on decision: none
- Follow-on handler: **0**
- Terminal evidence: lookup_policy mcp.completed
- Outcome: completed_allowed

Not labeled SAFE.

`{BASELINE_ID}`
""",
        title="BASELINE",
    )
    add_md(
        "viz_cmp_card_atk",
        f"""
# ATTACK

**Profile:** vulnerable · **Mode:** ATTACK · **Catalog:** MALICIOUS

- Hash: `{MALICIOUS_HASH}`
- METADATA-001: OBSERVE (description **not** authorized)
- First tool: `lookup_policy` ALLOW + execute
- Follow-on requested: **YES** `lookup_customer_tier`
- Follow-on: ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`
- Follow-on handler: **1**
- Terminal evidence: hop-1 mcp.completed
- Outcome: completed_allowed

**INTENTIONALLY VULNERABLE LAB BEHAVIOR**

`{ATTACK_ID}`
""",
        title="ATTACK",
    )
    add_md(
        "viz_cmp_card_rt",
        f"""
# RETEST

**Profile:** defended · **Mode:** RETEST · **Catalog:** same MALICIOUS

- Hash: `{MALICIOUS_HASH}` (**equals ATTACK**)
- METADATA-001: OBSERVE
- First tool: `lookup_policy` ALLOW + execute
- Follow-on requested: **YES** (same request)
- Follow-on: DENY `tool_not_granted`
- Follow-on handler: **0** (authoritative)
- Terminal evidence: no indexed follow-on mcp.started
- Outcome: completed_denied

Splunk corroborates. Splunk did not block.

`{RETEST_ID}`
""",
        title="RETEST",
    )

    add_md(
        "viz_prove",
        f"""
# PROVE

```text
RUNTIME  →  LOCAL EVIDENCE  →  OTLP  →  SPLUNK  →  HUNT  →  SECURITY EVIDENCE
```

{RUNTIME_AUTH}

1. Was the first tool legitimate? **Yes** — `lookup_policy` ALLOW `tool_granted` on A/B/C.
2. Was its catalog metadata treated as authority? **No** — METADATA-001 OBSERVE `metadata_is_data` on A/B/C.
3. Did the metadata influence a follow-on request? **ATTACK/RETEST yes** (`lookup_customer_tier`). BASELINE no.
4. Who authorized the follow-on? **CTRL-MCP-001** — ATTACK vulnerable ALLOW; RETEST DENY `tool_not_granted`. Not the description. Not Splunk. Not a scanner.
5. Did the follow-on handler begin? ATTACK **yes** (runtime 1). RETEST **no** (runtime **0**).
6. What changed between ATTACK and RETEST? **Profile**, not the metadata. Same hash `{MALICIOUS_HASH}`.
7. Runtime-authoritative evidence: handler counts.
8. Splunk corroboration: COMPLETE `dc(_raw)` copy; no hop-1 mcp.started on RETEST.
9. Why is DET-MCP-001 silent? ALLOW-path ATTACK; RETEST DENY with no later start. **DETECTION GAP**, not detector failure.
10. Why would scanner output still not be authorization? Scanner PASS ≠ trusted. Scanner FAIL ≠ runtime DENY. Scanners are not wired.

**INV-002:** Retrieved/tool-provided content cannot independently widen authority.

LIVE A/B/C are OBSERVED/MEASURED. DETECT right table is **SIMULATED**.

## Limitations

- no indexed allowed_tools
- no full advertised catalog list
- Q-MCP-EXECUTED extra OBSERVE row
- bounded preview (hash is the fingerprint)
- no `gen_ai.tool.call.id`
- no DET-MCP-CATALOG
- scanners not ingested

Validated: BASELINE `{BASELINE_ID}` · ATTACK `{ATTACK_ID}` · RETEST `{RETEST_ID}`.
""",
        title="PROVE",
    )
    add_table(
        "viz_prove_what",
        "ds_q_catalog",
        "What Happened? Q-MCP-CATALOG-AUTHORITY (Hunt run.id)",
        cap_what,
        no_data=empty_what,
    )

    definition = {
        "title": "Tool Catalog",
        "description": (
            "WS-MCP-CATALOG Dashboard Studio workshop. Reuses validated Q-MCP investigation SPL "
            "plus Q-MCP-CATALOG-AUTHORITY. Saved search DET-MCP-001 is packaged disabled; this "
            "dashboard does not enable it. No DET-MCP-CATALOG. Splunk does not ALLOW or DENY."
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
                        block("viz_learn", 0, 0, FULL, 520),
                        block("viz_learn_meta", 0, 520, THIRD, 420),
                        block("viz_learn_req", THIRD, 520, THIRD, 420),
                        block("viz_learn_trust", THIRD * 2, 520, THIRD, 420),
                    ],
                    960,
                ),
                "layout_baseline": layout(
                    [
                        block("viz_baseline_md", 0, 0, FULL, 340),
                        block("viz_baseline_what", 0, 340, FULL, 280),
                        block("viz_baseline_authz", 0, 620, FULL, 300),
                        block("viz_baseline_tool", 0, 920, HALF, 280),
                        block("viz_baseline_exec", HALF, 920, HALF, 280),
                    ],
                    1220,
                ),
                "layout_attack": layout(
                    [
                        block("viz_attack_md", 0, 0, FULL, 400),
                        block("viz_attack_what", 0, 400, FULL, 200),
                        block("viz_attack_authz", 0, 600, FULL, 380),
                        block("viz_attack_tool", 0, 980, HALF, 280),
                        block("viz_attack_exec", HALF, 980, HALF, 280),
                    ],
                    1280,
                ),
                "layout_observe": layout(
                    [
                        block("viz_observe_md", 0, 0, FULL, 220),
                        block("viz_observe_seq", 0, 220, FULL, 360),
                        block("viz_observe_catalog", 0, 580, FULL, 260),
                        block("viz_observe_authz", 0, 840, HALF, 260),
                        block("viz_observe_tool", HALF, 840, HALF, 260),
                        block("viz_observe_exec", 0, 1100, FULL, 260),
                    ],
                    1380,
                ),
                "layout_hunt": layout(
                    [
                        block("viz_hunt_md", 0, 0, FULL, 340),
                        block("viz_hunt_catalog", 0, 340, FULL, 280),
                        block("viz_hunt_authz", 0, 620, HALF, 260),
                        block("viz_hunt_tool", HALF, 620, HALF, 260),
                        block("viz_hunt_exec", 0, 880, HALF, 260),
                        block("viz_hunt_who", HALF, 880, HALF, 260),
                    ],
                    1160,
                ),
                "layout_detect": layout(
                    [
                        block("viz_detect_md", 0, 0, FULL, 360),
                        block("viz_detect_live", 0, 360, HALF, 400),
                        block("viz_detect_sim", HALF, 360, HALF, 400),
                    ],
                    780,
                ),
                "layout_defend": layout(
                    [
                        block("viz_defend", 0, 0, FULL, 520),
                        block("viz_defend_evidence", 0, 520, FULL, 300),
                    ],
                    840,
                ),
                "layout_retest": layout(
                    [
                        block("viz_retest_md", 0, 0, FULL, 360),
                        block("viz_retest_what", 0, 360, FULL, 220),
                        block("viz_retest_authz", 0, 580, FULL, 400),
                        block("viz_retest_tool", 0, 980, HALF, 280),
                        block("viz_retest_exec", HALF, 980, HALF, 280),
                    ],
                    1280,
                ),
                "layout_compare": layout(
                    [
                        block("viz_compare_md", 0, 0, FULL, 320),
                        block("viz_cmp_card_base", 0, 320, THIRD, 600),
                        block("viz_cmp_card_atk", THIRD, 320, THIRD, 600),
                        block("viz_cmp_card_rt", THIRD * 2, 320, THIRD, 600),
                    ],
                    940,
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
        "  <label>Tool Catalog</label>\n"
        "  <description>LIVE Tool Catalog workshop. LAB-MCP-CATALOG. Splunk does not ALLOW or DENY.</description>\n"
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
