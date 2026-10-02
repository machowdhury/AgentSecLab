#!/usr/bin/env python3
"""Build the bounded A2A Authentication and Delegation REPLAY workshop.

The simulated packet is educational evidence. This builder does not add
runtime authentication, delegation enforcement, a PDP, or a LIVE attack.
"""

from __future__ import annotations

import json
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

LAB = ROOT / "learning" / "level_1" / "LAB-A2A-AUTH-DELEGATION"
PACKET = LAB / "evidence.packet.json"
SEARCH = LAB / "searches" / "Q-AUTH-DELEGATION-HISTORICAL.spl"
OUT_JSON = LAB / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_a2a_auth_delegation.xml"
)
SEARCH_URL = "/en-US/app/search/search"
NO_ROWS = (
    "NO EVIDENCE FOUND for the historical claim-only corpus. "
    "Empty is not authenticated, delegated, authorized, executed, or safe."
)


def _load_packet() -> dict:
    packet = json.loads(PACKET.read_text(encoding="utf-8"))
    if packet["evidence_classification"] != "SIMULATED / REPLAYED":
        raise ValueError("packet must remain SIMULATED / REPLAYED")
    return packet


def _load_spl() -> str:
    query = SEARCH.read_text(encoding="utf-8").strip()
    for required in (
        "earliest=0",
        '"agentsec.workflow.entry"="/identity/delegate"',
        'evidence_plane="HISTORICAL CLAIM-ONLY CORPUS"',
    ):
        if required not in query:
            raise ValueError(f"historical query missing {required}")
    if "LAB-AGENT-DELEGATION-001" in query or "index=*" in query:
        raise ValueError("historical query uses an invalid key or unbounded index")
    return query


def build() -> dict:
    packet = _load_packet()
    auth = packet["authentication"]
    modes = {row["mode"]: row for row in packet["modes"]}
    attack = modes["ATTACK"]
    retest = modes["RETEST"]
    baseline = modes["BASELINE"]

    visualizations: dict[str, dict] = {}
    data_sources: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str) -> None:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz

    def add_table(viz_id: str, ds: str, title: str, description: str) -> None:
        key, viz = table(viz_id, ds, title, description, no_data=NO_ROWS)
        visualizations[key] = viz

    key, ds = search_ds(
        "ds_historical",
        "Q-AUTH-DELEGATION-HISTORICAL",
        _load_spl(),
    )
    data_sources[key] = ds

    add_md(
        "viz_mission",
        f"""
# A2A Authentication and Delegation

**Security question.** Two agents are named. What evidence would support authentication, what authority was delegated, what was requested, what did the tool PDP decide, and what outcome remains unknown?

Write a hypothesis before opening later tabs. Reject this shortcut: **authenticated agent = authorized request**.

**REPLAY / STATIC workshop.** The A2A packet is clearly labeled **SIMULATED / REPLAYED**. It is not historical authentication, production IAM, credential issuance, or runtime delegation enforcement. The historical `/identity/delegate` corpus remains claim-only.

CTRL-IDENTITY-001 observes a claim. CTRL-MCP-001 remains the tool PDP. Splunk is downstream evidence, not authority.

Work in [Search]({SEARCH_URL}) when the task asks you to inspect historical evidence. Searching a simulated packet does not transform it into measured authentication.

Path A asks you to reason through the chain. Path B is the review key, not policy.
""",
        "MISSION",
    )

    add_md(
        "viz_claims",
        """
# Claims and historical evidence

Start with the existing **HISTORICAL CLAIM-ONLY CORPUS**:

- indexed lab id: `agentsec-local`
- workflow entry: `/identity/delegate`
- caller claim: `acme-agent-advisor-005`
- callee claim: `acme-agent-fulfillment-006`
- principal label: `applicant-web`

These are labels and claims. They are not authentication, credential proof, or delegated authority. `applicant-web` is not proven human, authenticated, or causal.

**Task.** Build a small `stats` query by mode. Record the caller and callee claims. Then write what each row does **not** prove.

Previously measured run counts are ATTACK 6, RETEST 6, BASELINE 1. `who_authenticated` and `LAB-AGENT-DELEGATION-001` were previously measured at count 0. Those facts remain historical; this workshop does not relabel them.
""",
        "CLAIMS",
    )
    add_table(
        "viz_historical",
        "ds_historical",
        "Historical claim-only contrast",
        "Investigation only. These rows do not authenticate or delegate.",
    )

    add_md(
        "viz_authenticate",
        f"""
# Authenticate — simulated evidence only

The packet contains rows labeled **{auth[0]["record_label"]}**.

Advisor record:

- principal id `{auth[0]["principal_id"]}`
- principal type `{auth[0]["principal_type"]}`
- method `{auth[0]["method"]}`
- issuer `{auth[0]["issuer"]}`
- audience `{auth[0]["audience"]}`
- result `{auth[0]["result"]}`
- credential reference `{auth[0]["credential_reference"]}`
- issued `{auth[0]["issued_at"]}`; not before `{auth[0]["not_before"]}`; expires `{auth[0]["expires_at"]}`

Fulfillment record:

- principal id `{auth[1]["principal_id"]}`
- audience `{auth[1]["audience"]}`
- result `{auth[1]["result"]}`
- credential reference `{auth[1]["credential_reference"]}`

Credential references are synthetic metadata. They are not credential values and do not prove possession. No token, key, certificate, password, API key, or reusable credential exists in this packet.

**Task.** Identify which statements are supported only inside the simulated packet. Explain why neither result authorizes a tool and why it does not authenticate `applicant-web`.
""",
        "AUTHENTICATE",
    )

    add_md(
        "viz_delegate",
        f"""
# Delegate — one bounded simulated grant

The **SIMULATED DELEGATION DECISION** record names:

- delegation id `{attack["delegation_id"]}`
- delegator `{attack["delegator"]}`
- delegate `{attack["delegate"]}`
- delegated tool `{attack["delegated_tool"]}`
- delegated scope `{attack["delegated_scope"]}`
- delegated resource `{attack["delegated_resource"]}`
- audience `{attack["delegation_audience"]}`
- issued `{attack["delegation_issued_at"]}`; not before `{attack["delegation_not_before"]}`; expires `{attack["delegation_expires_at"]}`

Tool and resource are different dimensions. Permission to invoke one tool does not prove permission to every resource reachable through it.

This grant does not overload `agentsec.delegator.agent.id` or `agentsec.delegation.claimed_scope`. Those historical fields keep their existing claim and prior-hop meanings.

**Task.** Name the delegator, delegate, tool, resource, audience, and window. Then reject: “two agent ids prove delegation.”

**Boundary.** A same-tool / different-resource authorization case is **NOT MODELED** in this workshop.
""",
        "DELEGATE",
    )

    add_md(
        "viz_request",
        f"""
# Request

The coded grant in this packet is `lookup_policy` on `lending-basics`. Three cards are shown in a fixed order. The order is not a timeline and not a verdict.

Card Cedar

- tool `{baseline["requested_tool"]}`
- resource `{baseline["requested_resource"]}`

Card Birch

- tool `{attack["requested_tool"]}`
- resource `{attack["requested_resource"]}`

Card Alder

- tool `{retest["requested_tool"]}`
- resource `{retest["requested_resource"]}`

**Task.** Which cards request something outside that grant? Which two cards are the same request? Same request does not mean the same control decision. Do not open Path B until you have written MATCH or MISMATCH for each card.
""",
        "REQUEST",
    )

    add_md(
        "viz_authorize",
        """
# Authorize

Now inspect the separate CTRL-MCP-001 decision in the packet.

CTRL-MCP-001 is the actual tool authorization PDP. The simulated authentication result is not a PDP. The simulated delegation evaluation is not a PDP. MATCH is not ALLOW. MISMATCH is not DENY.

**Task.** For each mode, record the delegation evaluation, CTRL-MCP-001 decision, and CTRL-MCP-001 reason in separate ledger columns.

In the vulnerable case, disagreement is intentional teaching evidence: a MISMATCH can appear beside an ALLOW. The ALLOW comes from deliberately vulnerable tool-policy behavior, not from authentication and not from the delegation.
""",
        "AUTHORIZE",
    )

    add_md(
        "viz_execute",
        """
# Execute

`agentsec.mcp.started` is separate execution-start evidence. CTRL-MCP-001 ALLOW does not prove that row exists.

A start does not prove successful completion. Completion does not prove downstream resource change. Resource impact requires its own evidence.

**Task.** For each mode:

1. Record whether a separate start is present.
2. Leave downstream resource impact `NOT PROVEN`.
3. Explain why an ALLOW without a start is authorization evidence only.

A missing start is **NO EVIDENCE FOUND** for execution in this packet, not proof of prevention everywhere.
""",
        "EXECUTE",
    )

    add_md(
        "viz_compare",
        """
# Compare

Build the comparison before opening Path B.

Required columns:

- mode, caller, callee
- authentication result and audience
- delegation id
- delegated tool and requested tool
- delegated resource and requested resource
- delegation evaluation
- CTRL-MCP-001 decision and reason
- execution observed
- resource impact
- evidence classification
- claim strength

**Challenge.** Reject “authenticated agent = authorized request.” Authentication supports an identity statement in the simulated packet. Only CTRL-MCP-001 decides the tool request.

Acquisition classification and claim strength are separate. `SIMULATED / REPLAYED` describes the source. `SUPPORTED WITHIN THE PACKET` or `NOT PROVEN` describes the claim.
""",
        "COMPARE",
    )

    add_md(
        "viz_ledger",
        """
# Learner evidence ledger

Complete one row per mode. Keep every required column from Compare.

Then add claim-boundary rows:

- `applicant-web` is an authenticated human — **NOT PROVEN**
- `applicant-web` caused the call — **NOT PROVEN**
- historical `/identity/delegate` is authenticated A2A — **NOT PROVEN**
- historical rows contain real delegated authority — **NOT PROVEN**
- simulated authentication is production IAM — **NOT PROVEN**
- authentication authorizes a tool — **FALSE**
- delegation MATCH authorizes a tool — **FALSE**
- CTRL-MCP-001 ALLOW proves execution — **FALSE**
- `agentsec.mcp.started` proves completion — **FALSE**
- execution proves resource change — **FALSE**
- BASELINE proves universal safety — **FALSE**

Do not upgrade SIMULATED to MEASURED because Splunk or a dashboard displays it.
""",
        "LEDGER",
    )

    add_md(
        "viz_conclude",
        """
# Conclude

Your bounded conclusion must answer all thirteen questions:

1. Which values are identity claims?
2. Which authentication evidence is simulated?
3. Who is delegator? 4. Who is delegate?
5. What tool was delegated? 6. What resource was delegated?
7. What tool was requested? 8. What resource was requested?
9. MATCH or MISMATCH?
10. What did CTRL-MCP-001 decide?
11. Was execution observed?
12. Was downstream resource impact proven?
13. Which claims remain NOT PROVEN?

Use **SUPPORTED**, **NOT PROVEN**, **FALSE**, **NO EVIDENCE FOUND**, or **INSUFFICIENT EVIDENCE**. Do not say SAFE, production-authenticated, or universally enforced.
""",
        "CONCLUDE",
    )

    add_md(
        "viz_path_b",
        f"""
# Path B — review key

Answer key, not policy. The packet remains **SIMULATED / REPLAYED**.

**ATTACK**

- request `{attack["requested_tool"]}` / `{attack["requested_resource"]}`
- grant `{attack["delegated_tool"]}` / `{attack["delegated_resource"]}`
- delegation `{attack["delegation_evaluation"]}`
- CTRL-MCP-001 `{attack["ctrl_mcp_001_decision"]}` because `{attack["ctrl_mcp_001_reason"]}`
- execution `{attack["execution_observed"]}`; resource impact `{attack["resource_impact"]}`

Authentication did not authorize the customer-tier request. Delegation did not authorize it. The ALLOW is the labeled vulnerable tool-policy fault.

**RETEST**

- same request and grant as ATTACK
- delegation `{retest["delegation_evaluation"]}`
- CTRL-MCP-001 `{retest["ctrl_mcp_001_decision"]}` because `{retest["ctrl_mcp_001_reason"]}`
- execution `{retest["execution_observed"]}`; resource impact `{retest["resource_impact"]}`

**BASELINE**

- different request `{baseline["requested_tool"]}` / `{baseline["requested_resource"]}`
- grant `{baseline["delegated_tool"]}` / `{baseline["delegated_resource"]}`
- delegation `{baseline["delegation_evaluation"]}`
- CTRL-MCP-001 `{baseline["ctrl_mcp_001_decision"]}` because `{baseline["ctrl_mcp_001_reason"]}`
- execution `{baseline["execution_observed"]}`; resource impact `{baseline["resource_impact"]}`

ATTACK versus RETEST isolates the tool PDP response to the same out-of-scope request. BASELINE demonstrates a different, in-scope request.

Splunk displays evidence. It does not authenticate, delegate, authorize, execute, or prove resource impact.
""",
        "PATH B · REVIEW",
    )

    tabs = [
        ("layout_mission", "MISSION", "viz_mission", 700),
        ("layout_claims", "CLAIMS", "viz_claims", 760),
        ("layout_authenticate", "AUTHENTICATE", "viz_authenticate", 800),
        ("layout_delegate", "DELEGATE", "viz_delegate", 780),
        ("layout_request", "REQUEST", "viz_request", 650),
        ("layout_authorize", "AUTHORIZE", "viz_authorize", 620),
        ("layout_execute", "EXECUTE", "viz_execute", 600),
        ("layout_compare", "COMPARE", "viz_compare", 680),
        ("layout_ledger", "LEDGER", "viz_ledger", 760),
        ("layout_conclude", "CONCLUDE", "viz_conclude", 680),
        ("layout_path_b", "PATH B · REVIEW", "viz_path_b", 1120),
    ]
    layout_definitions = {
        layout_id: layout([block(viz_id, 0, 0, FULL, height - 40)], height)
        for layout_id, _, viz_id, height in tabs
    }
    layout_definitions["layout_claims"] = layout(
        [
            block("viz_claims", 0, 0, FULL, 580),
            block("viz_historical", 0, 580, FULL, 280),
        ],
        900,
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
                    {"layoutId": layout_id, "label": label}
                    for layout_id, label, _, _ in tabs
                ]
            },
            "layoutDefinitions": layout_definitions,
        },
    }
    validate(definition)
    return definition


def validate(definition: dict) -> None:
    markdown_text = "\n".join(
        viz["options"]["markdown"]
        for viz in definition["visualizations"].values()
        if viz.get("type") == "splunk.markdown"
    )
    required = (
        "SIMULATED / REPLAYED",
        "HISTORICAL CLAIM-ONLY",
        "CTRL-IDENTITY-001",
        "CTRL-MCP-001",
        "lookup_customer_tier",
        "lookup_policy",
        "cust-001",
        "lending-basics",
        "authenticated agent = authorized request",
        "same-tool / different-resource",
        "NOT PROVEN",
    )
    for value in required:
        if value not in markdown_text:
            raise ValueError(f"workshop missing {value}")
    if "| --- |" in markdown_text:
        raise ValueError("Studio markdown must not contain a GFM table")
    if definition["inputs"]:
        raise ValueError("static workshop must not request a run id")
    if definition["layout"]["options"]["submitButton"] is not False:
        raise ValueError("submit button must be disabled")


def main() -> None:
    definition = build()
    write_studio_xml(
        OUT_XML,
        definition,
        definition_path=OUT_JSON,
        label="A2A Authentication and Delegation",
        description=(
            "LAB-A2A-AUTH-DELEGATION. SIMULATED / REPLAYED workshop between "
            "the Identity/NHI checkpoint and L8. Splunk remains downstream."
        ),
    )


if __name__ == "__main__":
    main()
