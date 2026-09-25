#!/usr/bin/env python3
"""Build the bounded REPLAY threat-modeling workbench."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from agentsec_studio import (  # noqa: E402
    FULL,
    HALF,
    block,
    layout,
    layout_options,
    markdown,
    studio_defaults,
    write_definition,
    write_studio_xml,
)

LAB = ROOT / "learning" / "level_1" / "LAB-THREAT-MODELING-001"
OUT_JSON = LAB / "dashboard.definition.json"
OUT_XML = (
    ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    / "ws_lab_threat_modeling.xml"
)


def build() -> dict:
    visualizations: dict[str, dict] = {}

    def add(viz_id: str, body: str, title: str) -> None:
        key, value = markdown(viz_id, body, title)
        visualizations[key] = value

    add(
        "viz_mission",
        """
# AcmeBank Agentic Customer Operations Platform

You are the security architect. Determine what matters, how the bounded system works, where trust and authority change, what can go wrong, where controls belong, what evidence is needed, and what risk remains.

This is a **REPLAY workshop / ARCHITECTURE** exercise. It creates no attack, control, detector, identity system, risk score, or compliance result.

**Path A:** write your first system purpose and three critical assets before opening PATH B · REVIEW. Path B is a review key, not policy.

Runtime schema **1.9.0** · ExternalEvidence contract **1.0.0**.
""",
        "MISSION",
    )
    add(
        "viz_method",
        """
# Canonical method

UNDERSTAND SYSTEM → IDENTIFY ASSETS → IDENTIFY ACTORS → MAP COMPONENTS → MAP DATA FLOWS → DRAW TRUST BOUNDARIES → IDENTIFY AUTHORITY → IDENTIFY ATTACK SURFACE → ENUMERATE THREATS → MAP CONTROLS → IDENTIFY TELEMETRY → TEST ASSUMPTIONS → IDENTIFY GAPS → RESIDUAL RISK

Do not automate away the reasoning. A catalog suggests questions; it does not complete a threat model.
""",
        "METHOD",
    )
    add(
        "viz_invariants",
        """
# Reasoning invariants

- OBSERVATION != ENFORCEMENT
- AUTHENTICATION != AUTHORIZATION
- AUTHORIZATION != EXECUTION
- EXECUTION != OUTCOME
- DETECTION != PREVENTION
- CORRELATION != CAUSATION
- SCANNER FINDING != EXPLOITATION
- EVALUATION PASS != SAFE
- ABSENCE OF EVIDENCE != EVIDENCE OF ABSENCE
- INFLUENCE != AUTHORITY
- CONTROL IMPLEMENTED != RISK ELIMINATED

CTRL-MCP-001 remains the tool PDP. Splunk is downstream. External evidence is adjacent.
""",
        "DO NOT COLLAPSE THESE",
    )
    add(
        "viz_system",
        """
# Bounded architecture

```text
HUMAN USER
    │ request / claimed user id       [TB-01]
    ▼
ACMEBANK APP → AGENT / ORCHESTRATOR → MODEL SERVICE
                   │       │
          RAG ─────┤       ├──── MEMORY
          [TB-02]  │       │     [TB-03]
                   ▼
          MCP + CTRL-MCP-001          [TB-04 AUTHORITY]
                   │ allow ticket
                   ▼
              TOOL REGISTRY
                   │                  [TB-05]
                   ▼
        FIXTURE-BACKED BANK RECORDS

APP → OTEL → SPLUNK                   [TB-06 OBSERVATION]
SCANNER / GARAK → SPLUNK              [TB-07 ADJACENT EVIDENCE]
```

The model, RAG, and memory can influence a request. They do not mint authority. A boundary marks changed assumptions; crossing it is not proof of compromise.
""",
        "SYSTEM · FLOWS · BOUNDARIES",
    )
    add(
        "viz_assets",
        """
# Select assets that matter

Consider customer records; prompts, retrieved documents, and memory; tool/scope/resource grants; coded policy and allow-ticket integrity; lending workflow; service availability; telemetry, provenance, and investigation artifacts.

For each selected asset state its owner, security property, and business consequence. Assets include **data, authority, systems, business workflows, and security evidence**.

# Identify actors without anthropomorphism

Human user · administrator · untrusted-input supplier · agent/orchestration software · model dependency · MCP server · tool handler · security analyst.

An agent can be an architectural actor without being a human or cryptographically authenticated identity.
""",
        "ASSETS · ACTORS",
    )
    add(
        "viz_flows",
        """
# Trace each important flow

For each source → process/store → decision → action → destination ask:

- What data moves, who supplied it, and is it sensitive?
- Is it trusted or persisted?
- Can it influence a decision?
- Can it trigger authority?
- Where is it logged and correlated?
- Where could it leak?

Start with one flow: user request → context construction → tool request → CTRL-MCP-001 decision → allow ticket → handler → fixture-backed record. Then map telemetry separately.
""",
        "DATA-FLOW WORKSHEET",
    )
    add(
        "viz_authority",
        """
# Authority is first-class

For every agent/tool relationship: WHAT can be requested? WHO requests? WHO authorizes? WHAT policy, scope, credential, and downstream authority exist? Can authority be delegated or escalated?

In this lab:

- Requester: agent/orchestrator.
- Requested objects: tool, scope, resource.
- Authorizer: CTRL-MCP-001 at `McpServer.authorize`.
- Policy: coded exact membership.
- Execution gate: opaque allow ticket minted only after ALLOW.
- Downstream: fixture-backed lab action.
- Authentication: **NOT MODELED**.
- Human approval: **NOT MODELED**.
- Cryptographic delegation: **NOT MODELED**.

Missing architectural capabilities are findings, not invitations to draw fictional components.
""",
        "AUTHORITY MAP",
    )
    add(
        "viz_analyze",
        """
# Threat → control → evidence

For each threat bind:

**asset → actor/source → boundary/flow → precondition → influence or authority → consequence → existing control → control placement → telemetry → evidence gap → residual risk**

Classify controls where useful as preventive, detective, corrective, or recovery — and always as **OBSERVE** or **ENFORCE**.

Prompt filter: influence control. CTRL-MCP-001: authorization control. Splunk: observation/investigation. Scanner: assessment evidence.

A good control in the wrong place may not mitigate the threat.
""",
        "ANALYSIS WORKBENCH",
    )
    add(
        "viz_telemetry",
        """
# If it happened, how would we know?

Specify event, source, timestamp, identity claim, request, decision, invocation, completion, outcome, correlation identifier, and provenance where appropriate.

Then state what each event can and cannot prove. An ALLOW event does not prove invocation. `mcp.started` does not prove completion. A completion does not independently prove the expected business outcome.

Use exact gap labels: **NOT LOGGED · NOT MODELED · NOT OBSERVED · NOT CORRELATED · NOT CRYPTOGRAPHICALLY ESTABLISHED · NOT PROVEN**.
""",
        "OBSERVABILITY · EVIDENCE GAPS",
    )
    add(
        "viz_levels",
        """
# One architecture, three levels

**GUIDED** — architecture, prompts, examples, and four progressive hints. No completed threat list or final strategy.

**PRACTITIONER** — architecture, objectives, artifact template, minimal hints. You prioritize threats.

**ARCHITECT CHALLENGE** — business description, architecture, and constraints. Draft before opening the catalog or review.

Hints: (1) purpose and assets; (2) trace one flow and mark trust changes; (3) separate influence from authority and name enforcement; (4) bind threat to control placement, telemetry, gap, and residual risk.
""",
        "PROGRESSIVE SCAFFOLDING",
    )
    add(
        "viz_challenge",
        """
# Required architecture review

Produce: system purpose · critical assets · actors/components · data flows · trust boundaries · authority map · attack surface · defensible top threats · existing/missing controls · telemetry · evidence gaps · residual risks · prioritized recommendations.

No arbitrary Top 10. No numerical risk score. Test assumptions against repository evidence.

Communicate three times:

- **Engineering:** what technically changes and where.
- **SOC:** what must be observed, correlated, hunted, and investigated.
- **Leadership:** material risk, control strategy, and residual uncertainty.
""",
        "ARCHITECT CHALLENGE",
    )
    add(
        "viz_frameworks",
        """
# EDUCATIONAL MAPPING

Use different lenses, not interchangeable checklists:

- **OWASP Top 10 for Agentic Applications 2026:** application and agentic-risk lens.
- **MITRE ATLAS:** adversarial behavior and technique lens; official collection observed as 2026.05.
- **CSA MAESTRO v2:** agentic-system architectural threat-modeling lens.
- **NIST AI RMF 1.0 + NIST AI 600-1:** voluntary risk-management and governance lens.

**This is not certification. This is not compliance validation. This is not complete framework coverage.**

Specific AgentSec-to-framework identifiers remain **NEEDS_EXTERNAL_VALIDATION** unless individually verified against the current official source.
""",
        "FRAMEWORK LENSES",
    )
    add(
        "viz_review",
        """
# Path B — bounded reference analysis

Open only after drafting purpose, assets, one complete data flow, three boundaries, an authority map, and at least three threats.

A defensible model identifies customer records, authority grants, policy/ticket integrity, business workflow, and evidence as important assets. It distinguishes untrusted input/context/memory **influence** from tool **authority**. It places authorization at CTRL-MCP-001 before handler invocation, treats Splunk as downstream observation, and keeps scanner/evaluation evidence adjacent.

Likely threat prompts include context or memory manipulation, goal manipulation, excessive authority/tool abuse, identity/delegation claim abuse, data exposure, dependency/supply-chain risk, observability gaps, and security-evidence overclaim. This list is not a completed prioritization.

Material gaps include authentication, human approval, and cryptographic delegation being NOT MODELED. Universal control effectiveness is NOT PROVEN. Fixture-backed downstream behavior does not establish production banking impact.

Residual risk remains because correct authorization does not validate every model output, eliminate dependency failure, guarantee telemetry completeness, or establish a real principal.
""",
        "REFERENCE — NOT AN AUTOMATIC MODEL",
    )
    add(
        "viz_transfer",
        """
# Durable principle transfer

MCP authorization maps conceptually to API authorization middleware, cloud IAM, network policy, Kubernetes admission policy, and database privileges: the syntax differs, but authority should be explicitly evaluated near the action.

RAG and memory boundaries resemble document ingestion, message queues, caches, and data pipelines: provenance helps, but data cannot self-authorize.

Telemetry and response transfer to traditional SOC practice: preserve attribution, decision, execution, outcome, correlation, and evidence integrity.

Submit the reusable template as an architecture review, not a compliance assessment.
""",
        "TRANSFER · FINISH",
    )

    definition = {
        "title": "Threat Modeling & Security Architecture",
        "description": "LAB-THREAT-MODELING-001 REPLAY architecture workbench. Reasoning assistance, not compliance.",
        "defaults": studio_defaults(),
        "inputs": {},
        "visualizations": visualizations,
        "layout": {
            "options": layout_options(),
            "layoutDefinitions": {
                "layout_foundations": layout(
                    [
                        block("viz_mission", 0, 0, FULL, 430),
                        block("viz_method", 0, 430, HALF, 460),
                        block("viz_invariants", HALF, 430, HALF, 460),
                    ],
                    910,
                ),
                "layout_system": layout(
                    [
                        block("viz_system", 0, 0, FULL, 720),
                        block("viz_assets", 0, 720, HALF, 620),
                        block("viz_flows", HALF, 720, HALF, 620),
                        block("viz_authority", 0, 1340, FULL, 620),
                    ],
                    1980,
                ),
                "layout_model": layout(
                    [
                        block("viz_analyze", 0, 0, HALF, 600),
                        block("viz_telemetry", HALF, 0, HALF, 600),
                        block("viz_levels", 0, 600, FULL, 480),
                    ],
                    1100,
                ),
                "layout_challenge": layout(
                    [
                        block("viz_challenge", 0, 0, FULL, 620),
                        block("viz_frameworks", 0, 620, FULL, 620),
                    ],
                    1260,
                ),
                "layout_review": layout(
                    [
                        block("viz_review", 0, 0, FULL, 880),
                        block("viz_transfer", 0, 880, FULL, 520),
                    ],
                    1420,
                ),
            },
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_foundations", "label": "FOUNDATIONS"},
                    {"layoutId": "layout_system", "label": "SYSTEM · ARCHITECTURE"},
                    {"layoutId": "layout_model", "label": "MODEL · ANALYZE"},
                    {"layoutId": "layout_challenge", "label": "ARCHITECT CHALLENGE"},
                    {"layoutId": "layout_review", "label": "PATH B · REVIEW"},
                ],
            },
        },
        "applicationProperties": {
            "collapseNavigation": False,
            "downsampleVisualizations": False,
        },
    }
    validate(definition)
    return definition


def validate(definition: dict) -> None:
    early = ("layout_foundations", "layout_system", "layout_model", "layout_challenge")
    early_text = "\n".join(
        definition["visualizations"][row["item"]]["options"]["markdown"]
        for layout_id in early
        for row in definition["layout"]["layoutDefinitions"][layout_id]["structure"]
    )
    for leaked in (
        "Likely threat prompts include",
        "A defensible model identifies",
        "Residual risk remains because",
    ):
        if leaked in early_text:
            raise ValueError(f"review answer leaked before Path B: {leaked}")
    payload = json.dumps(definition)
    forbidden = ("risk_score", "compliance score", "index=*", "new detector")
    if any(term in payload for term in forbidden):
        raise ValueError("forbidden implementation implication in dashboard")


def main() -> None:
    definition = build()
    write_definition(OUT_JSON, definition)
    write_studio_xml(
        OUT_XML,
        definition,
        label="Threat Modeling and Security Architecture",
        description="REPLAY architecture workbench. Reasoning assistance, not compliance.",
    )
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
