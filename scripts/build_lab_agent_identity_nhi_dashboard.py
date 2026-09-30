#!/usr/bin/env python3
"""Build the Agent Identity and Non-Human IAM REPLAY workshop.

The workshop teaches claim, authentication, authorization, and execution
as separate evidence. It does not add runtime authentication, a LIVE attack,
or a detector.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from agentsec_studio import (  # noqa: E402
    FULL,
    block,
    layout,
    layout_options,
    markdown,
    search_ds,
    studio_defaults,
    table,
    write_definition,
    write_studio_xml,
)

LAB = ROOT / "learning" / "level_1" / "LAB-AGENT-IDENTITY-NHI"
SEARCHES = LAB / "searches"
OUT_JSON = LAB / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_agent_identity_nhi.xml"
)
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

NO_ROWS = (
    "NO EVIDENCE FOUND for this predicate and time range. "
    "Empty is not SAFE, not AUTHENTICATED, and not proof the behavior did not occur."
)


def load_spl(name: str) -> str:
    text = (SEARCHES / name).read_text(encoding="utf-8").strip()
    if UUID.search(text):
        raise ValueError(f"{name} must not embed a run.id")
    if "earliest=0" not in text:
        raise ValueError(f"{name} needs an explicit earliest=0")
    if "index=*" in text:
        raise ValueError(f"{name} is unbounded")
    if "LAB-AGENT-DELEGATION-001" in text:
        raise ValueError(f"{name} must not require the unindexed lab id")
    if '"agentsec.workflow.entry"="/identity/delegate"' not in text:
        raise ValueError(f"{name} must discover the identity workflow")
    return text


def build() -> dict:
    visualizations: dict[str, dict] = {}
    data_sources: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str | None = None) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    def add_table(viz_id: str, ds: str, title: str, description: str) -> str:
        key, viz = table(viz_id, ds, title, description, no_data=NO_ROWS)
        visualizations[key] = viz
        return key

    def add_search(ds_id: str, name: str, filename: str) -> str:
        key, ds = search_ds(ds_id, name, load_spl(filename))
        data_sources[key] = ds
        return key

    add_search("ds_modes", "Q-ID-MODES", "Q-ID-MODES.spl")
    add_search("ds_controls", "Q-ID-CONTROLS", "Q-ID-CONTROLS.spl")
    add_search("ds_starts", "Q-ID-STARTS", "Q-ID-STARTS.spl")

    add_md(
        "viz_mission",
        f"""
# Agent Identity and Non-Human IAM

**Security question.** Who or what requested the delegated operation, what identity evidence exists, what authorized the tool, and what actually executed?

Write that as a hypothesis before you search. You are not handed a run identifier. A name in a log does not prove who authenticated.

**REPLAY workshop.** This page sits after L7 and before L8. It is not a new attack level and not a LIVE lab. It does not launch an attack and it does not mint a credential. CTRL-MCP-001 remains the tool policy decision point. Splunk remains downstream. A row here does not authenticate anyone.

**Same evidence for every learner.**

- **Beginner.** Seeing a name in a log does not prove who authenticated. Use the hints and the partial search.
- **Practitioner.** Change the SPL, order events by sequence, and classify each ledger row.
- **Expert.** Say which attribution claims stay unsupported, and name the production telemetry this index does not contain. Do not invent that telemetry.

Work in [Search]({SEARCH_URL}). Path B is an answer key, not policy. Opening this mission does not tell you how ATTACK, RETEST, and BASELINE differ.

If Search is unavailable or returns nothing: **NO EVIDENCE FOUND**. Do not fill the gap with SAFE, AUTHENTICATED, TRUSTED, or AUTHORIZED HUMAN.
""",
        title="MISSION",
    )

    add_md(
        "viz_discover",
        """
# Discover the workflow

Do not start from a run identifier. Do not search only for `LAB-AGENT-DELEGATION-001`. That lab id is a repository contract. It is not the indexed key for this corpus.

Indexed activity uses `agentsec.lab.id=agentsec-local` together with the workflow entry below.

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0
"agentsec.workflow.entry"="/identity/delegate"
```

Add a `stats` that groups by `agentsec.run.id` and `agentsec.testbed.mode`. Keep the principal, caller, callee, and control fields you will need later.

The table on this tab is a **run count** by mode. A run count is not a CTRL-MCP-001 decision. ATTACK, RETEST, and BASELINE are not the same authorization outcome just because each mode has runs.

If this table is empty: **NO EVIDENCE FOUND**. Stop. Do not invent a candidate run.
""",
        title="DISCOVER",
    )
    add_table(
        "viz_modes",
        "ds_modes",
        "Run counts by mode",
        "Corpus size only. These counts are not authorization decisions.",
    )

    add_md(
        "viz_identity",
        """
# Identity claims

Pick one run you discovered. Inspect these fields. They are not the same fact.

- `agentsec.principal.id` — a label on the event. On this workflow the observed label is `applicant-web`.
- `agentsec.principal.type` — the emitter writes `user` on this workflow, including the callee's events.
- `agentsec.identity.caller_agent_id` — caller claim. Observed value `acme-agent-advisor-005`.
- `agentsec.identity.callee_agent_id` — callee claim. Observed value `acme-agent-fulfillment-006`.
- `agentsec.delegator.agent.id` — present on a later hop when a delegator is recorded. Absence is **NO EVIDENCE FOUND** for a delegator, not proof there was none in the real world.
- `gen_ai.agent.id` — an agent identifier on the event. It does not by itself prove execution, and it does not name an authenticated principal.

**Telemetry limitation.** `agentsec.principal.type=user` does not mean an authenticated human. The emitter writes `user` for this workflow. This workshop does not change the emitter and does not change schema 1.9.0.

`applicant-web` also appears on other labs. A shared label is not causation and not a human identity.

Authentication is **NOT MODELED**. There is no indexed `who_authenticated` attribute. An empty search for that word is **AUTHENTICATION NOT OBSERVED**.
""",
        title="IDENTITY",
    )

    add_md(
        "viz_authority",
        """
# Authority

Keep two controls apart.

**CTRL-IDENTITY-001** observes an identity claim. Its decision on this workflow is an observation or an error. OBSERVE is not ALLOW. This control does not authenticate a principal and does not authorize a tool.

**CTRL-MCP-001** is the tool policy decision point. Authorization evidence is that control's own decision event: `agentsec.control.id`, `agentsec.control.decision`, and `agentsec.control.reason`.

If the reason contains `caller_identity_derived_authority`, read it as a **LABELED AUTHORIZATION FAULT**. That string is not authenticated delegation, not legitimate delegation, not verified identity, not valid agent authority, and not production IAM.

Splunk displaying the row does not make the identity authenticated. External evidence, if you open it, stays adjacent. It does not authenticate the principal.
""",
        title="AUTHORITY",
    )

    add_md(
        "viz_execution",
        """
# Execution

Execution evidence is `event.name=agentsec.mcp.started`. That event is bounded to observed runtime execution. A later `agentsec.mcp.completed` can corroborate completion when it is present. It does not upgrade the start into an authenticated principal.

`gen_ai.agent.id` on a start event does not prove execution by itself, and it does not identify the executing security principal. A start row can carry `gen_ai.agent.id` and omit `agentsec.control.id`. That omission means the start row is not the control decision.

Caller agent, callee agent, principal label, authorizing control, and executing tool are five different ideas. Do not collapse them into one name.

If a mode has no start event: **NO EVIDENCE FOUND** for execution in that mode. Do not call the absence SAFE.
""",
        title="EXECUTION",
    )

    add_md(
        "viz_compare",
        """
# Compare modes

You already have run counts. Those counts do not tell you the CTRL-MCP-001 decision.

Write one small query. Start from the discover search, keep `event.name=agentsec.control.decision`, and `stats` by mode, `agentsec.control.id`, decision, and reason. Write a second query for `event.name=agentsec.mcp.started`.

Then order one candidate run by `agentsec.sequence`. Separate the identity observation, the tool decision, and the start. An incomplete sequence is **INSUFFICIENT EVIDENCE**. An agent id that you cannot tie to one of those events is **ATTRIBUTION NOT PROVEN**. Sharing only a name across runs is **CORRELATION NOT ESTABLISHED**.

**Question.** What changed at authorization, and what did not become authenticated merely because authorization changed?

Read the decision evidence. Do not copy a conclusion from the run counts. If a mode is missing from your comparison: **INSUFFICIENT EVIDENCE**.
""",
        title="COMPARE",
    )

    add_md(
        "viz_ledger",
        """
# Evidence ledger

For each row, write the observed value, the event you used, and what that event does not prove. Use these evidence states when the index does not support a stronger sentence: **NOT PROVEN**, **NOT MODELED**, **FALSE**, **SUPPORTED**, **AUTHENTICATION NOT OBSERVED**, **ATTRIBUTION NOT PROVEN**.

Required rows:

- Claim: `applicant-web` is a human. Boundary: **NOT PROVEN**.
- Claim: `applicant-web` authenticated. Boundary: **NOT PROVEN / NOT MODELED**.
- Claim: `applicant-web` caused the tool call. Boundary: **NOT PROVEN**.
- Claim: `acme-agent-advisor-005` authenticated. Boundary: **NOT PROVEN / NOT MODELED**.
- Claim: `acme-agent-advisor-005` possessed legitimate delegated authority. Boundary: **NOT PROVEN**.
- Claim: `acme-agent-fulfillment-006` authenticated. Boundary: **NOT PROVEN / NOT MODELED**.
- Claim: `acme-agent-fulfillment-006` received authenticated delegation. Boundary: **NOT PROVEN**.
- Claim: CTRL-IDENTITY-001 authenticated a principal. Boundary: **FALSE**. It observes a claim.
- Claim: CTRL-IDENTITY-001 authorized a tool. Boundary: **FALSE**.
- Claim: `gen_ai.agent.id` proves execution. Boundary: **FALSE**.
- Claim: CTRL-MCP-001 authorized the tool. Boundary: **SUPPORTED** only by that control's decision event. Name the decision and the reason you observed. Do not copy them from a run count.
- Claim: `agentsec.mcp.started` is execution evidence. Boundary: **YES**, bounded to observed runtime execution.

Unsupported claims stay unsupported. Do not upgrade a label into a human, an authentication, or a delegation proof.
""",
        title="EVIDENCE LEDGER",
    )

    add_md(
        "viz_gaps",
        """
# Production identity gaps

This lab does not contain production identity forensics. The list below is **GAP ANALYSIS ONLY**. It is **NOT MODELED**. Do not add these fields, and do not treat a missing field as SAFE.

A production reconstruction would still need an authenticated principal, a credential issuer, an authentication method, a workload identity, a session identity, a tenant, an owner, a credential lifetime, issuance, expiry, rotation, revocation, a delegation proof, an audience, and a scope. None of those are in this workshop's evidence.

**FUTURE / NOT MODELED.** Later learning can use this foundation. Those mechanisms are not in the runtime today:

- authenticated agent-to-agent
- delegated authority
- short-lived credentials
- human approval before a privileged action
- retrieval authorization
- memory ownership and isolation
- an AI bill of materials
- supply-chain trust

**Failure language.** Splunk unavailable, no workflow rows, no candidate run, no CTRL-IDENTITY-001, no CTRL-MCP-001, no start event, a broken sequence, an ambiguous agent id, an empty mode comparison, or no authentication evidence: say **NO EVIDENCE FOUND**, **INSUFFICIENT EVIDENCE**, **AUTHENTICATION NOT OBSERVED**, **ATTRIBUTION NOT PROVEN**, or **CORRELATION NOT ESTABLISHED**. Do not say SAFE, AUTHENTICATED, TRUSTED, or AUTHORIZED HUMAN.
""",
        title="GAPS",
    )

    add_md(
        "viz_path_b",
        f"""
# Path B — finished searches

Answer key, not policy. These searches discover `/identity/delegate` without a run identifier. They do not filter on `LAB-AGENT-DELEGATION-001`.

Read the control table before you write the ledger. CTRL-IDENTITY-001 and CTRL-MCP-001 are different rows. A run count from Discover is not the decision.

The start table is execution evidence only where `event.name=agentsec.mcp.started` exists. `gen_ai.agent.id` on that row is not an authenticated principal. An empty `agentsec.control.id` on a start row means that row is not the PDP.

`caller_identity_derived_authority`, when it appears in `agentsec.control.reason`, remains a **LABELED AUTHORIZATION FAULT**.

`earliest=0` is the workshop window. It is not a saved-search schedule. Do not enable a detector from this page.

Open [Search]({SEARCH_URL}) if you want to edit a copy. Editing the copy does not change CTRL-MCP-001.
""",
        title="PATH B · REVIEW",
    )
    add_table(
        "viz_controls",
        "ds_controls",
        "Path B control decisions",
        "One row per mode, control, decision, and reason. Run counts are not this table.",
    )
    add_table(
        "viz_starts",
        "ds_starts",
        "Path B execution evidence",
        "agentsec.mcp.started only. An empty agentsec.control.id is not a decision.",
    )

    definition = {
        "visualizations": visualizations,
        "dataSources": data_sources,
        "defaults": studio_defaults(),
        "inputs": {},
        "layout": {
            "type": "grid",
            "options": layout_options(),
            "tabs": {
                "items": [
                    {"layoutId": "layout_mission", "label": "MISSION"},
                    {"layoutId": "layout_discover", "label": "DISCOVER"},
                    {"layoutId": "layout_identity", "label": "IDENTITY"},
                    {"layoutId": "layout_authority", "label": "AUTHORITY"},
                    {"layoutId": "layout_execution", "label": "EXECUTION"},
                    {"layoutId": "layout_compare", "label": "COMPARE"},
                    {"layoutId": "layout_ledger", "label": "EVIDENCE LEDGER"},
                    {"layoutId": "layout_gaps", "label": "GAPS"},
                    {"layoutId": "layout_path_b", "label": "PATH B · REVIEW"},
                ]
            },
            "layoutDefinitions": {
                "layout_mission": layout([block("viz_mission", 0, 0, FULL, 640)], 680),
                "layout_discover": layout(
                    [
                        block("viz_discover", 0, 0, FULL, 520),
                        block("viz_modes", 0, 520, FULL, 280),
                    ],
                    840,
                ),
                "layout_identity": layout([block("viz_identity", 0, 0, FULL, 720)], 760),
                "layout_authority": layout([block("viz_authority", 0, 0, FULL, 560)], 600),
                "layout_execution": layout([block("viz_execution", 0, 0, FULL, 520)], 560),
                "layout_compare": layout([block("viz_compare", 0, 0, FULL, 560)], 600),
                "layout_ledger": layout([block("viz_ledger", 0, 0, FULL, 860)], 900),
                "layout_gaps": layout([block("viz_gaps", 0, 0, FULL, 720)], 760),
                "layout_path_b": layout(
                    [
                        block("viz_path_b", 0, 0, FULL, 560),
                        block("viz_controls", 0, 560, FULL, 320),
                        block("viz_starts", 0, 880, FULL, 280),
                    ],
                    1200,
                ),
            },
        },
    }
    validate(definition)
    return definition


def _tab_markdown(definition: dict, layout_id: str) -> str:
    parts = []
    for row in definition["layout"]["layoutDefinitions"][layout_id]["structure"]:
        viz = definition["visualizations"][row["item"]]
        if viz.get("type") == "splunk.markdown":
            parts.append(viz["options"]["markdown"])
    return "\n".join(parts)


def validate(definition: dict) -> None:
    labels = [row["label"] for row in definition["layout"]["tabs"]["items"]]
    expected = [
        "MISSION",
        "DISCOVER",
        "IDENTITY",
        "AUTHORITY",
        "EXECUTION",
        "COMPARE",
        "EVIDENCE LEDGER",
        "GAPS",
        "PATH B · REVIEW",
    ]
    if labels != expected:
        raise ValueError(f"unexpected tabs: {labels}")
    if definition["inputs"] != {}:
        raise ValueError("workshop must not start from a run dropdown")
    path_a_ids = (
        "layout_mission",
        "layout_discover",
        "layout_identity",
        "layout_authority",
        "layout_execution",
        "layout_compare",
        "layout_ledger",
        "layout_gaps",
    )
    path_a = "\n".join(_tab_markdown(definition, layout_id) for layout_id in path_a_ids)
    if UUID.search(path_a):
        raise ValueError("Path A supplies a run identifier")
    mission = _tab_markdown(definition, "layout_mission")
    for forbidden in (
        "tool_not_granted",
        "tool_granted",
        "vulnerable_profile_fail_open",
        "110dd7a6",
    ):
        if forbidden in mission:
            raise ValueError(f"mission states a comparison result: {forbidden}")
    for required in (
        "Who or what requested the delegated operation",
        "NOT PROVEN",
        "agentsec.principal.type",
        "LABELED AUTHORIZATION FAULT",
        "agentsec.mcp.started",
        "CTRL-IDENTITY-001",
        "CTRL-MCP-001",
        "FUTURE / NOT MODELED",
        "NOT MODELED",
        "applicant-web",
        "acme-agent-advisor-005",
        "acme-agent-fulfillment-006",
    ):
        if required not in path_a:
            raise ValueError(f"Path A missing {required}")
    if "does not authenticate a principal" not in path_a:
        raise ValueError("identity control is described as authentication")
    if "tool policy decision point" not in path_a:
        raise ValueError("CTRL-MCP-001 is not described as the PDP")
    path_b = _tab_markdown(definition, "layout_path_b")
    for required in ("not policy", "earliest=0", "CTRL-MCP-001", "LAB-AGENT-DELEGATION-001"):
        if required not in path_b:
            raise ValueError(f"path B missing {required}")
    queries = "\n".join(ds["options"]["query"] for ds in definition["dataSources"].values())
    if "LAB-AGENT-DELEGATION-001" in queries:
        raise ValueError("a search requires the unindexed lab id")
    if "index=*" in queries:
        raise ValueError("unbounded index")


def main() -> None:
    definition = build()
    write_definition(OUT_JSON, definition)
    write_studio_xml(
        OUT_XML,
        definition,
        label="Agent Identity and Non-Human IAM",
        description=(
            "LAB-AGENT-IDENTITY-NHI. REPLAY workshop after L7. "
            "Identity claim is not authentication. Splunk is not the PDP."
        ),
    )


if __name__ == "__main__":
    main()
