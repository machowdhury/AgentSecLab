#!/usr/bin/env python3
"""Build the bounded L8 privacy investigation workbench."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from agentsec_studio import FULL, HALF, block, layout, layout_options, markdown, studio_defaults, write_definition, write_studio_xml  # noqa: E402

LAB = ROOT / "learning" / "level_1" / "LAB-PRIVACY-DATA-GOVERNANCE-001"
OUT_JSON = LAB / "dashboard.definition.json"
OUT_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_privacy_data_governance.xml"
FULL_RUN = "d27562be-3bb9-4643-ab88-5100173426a5"
MIN_RUN = "46f030ad-8b62-40d0-9c0e-fd4206b7bc47"


def build() -> dict:
    visualizations: dict[str, dict] = {}

    def add(viz_id: str, body: str, title: str) -> None:
        key, value = markdown(viz_id, body, title)
        visualizations[key] = value

    add("viz_foundations", """
# PRIV-2026-001 · synthetic privacy incident

Lab: **LAB-PRIVACY-DATA-GOVERNANCE-001**

An authorized customer-support task appears to have supplied more customer information than required.

**AUTHORIZED ACTION != AUTHORIZED DATA USE**

MODEL ACCESS != NEED TO KNOW · RETRIEVABLE != APPROPRIATE TO RETRIEVE · MEMORIZED != APPROPRIATE TO RETAIN · LOGGED != APPROPRIATE TO STORE · ENCRYPTED != PRIVACY-SAFE.

This is a **REPLAY workshop** and fixture-backed learning exercise. It is not policy. **This is not a breach claim.** It is not legal advice, a DLP product, compliance validation, or certification. Runtime schema **1.9.0** and ExternalEvidence **1.0.0** remain unchanged.
""", "FOUNDATIONS")
    add("viz_lifecycle", """
# Canonical lifecycle

COLLECT → INGEST → CLASSIFY → USE → RETRIEVE → INFER → ACT → STORE / REMEMBER → LOG → SHARE → RETAIN → DELETE

Not every stage exists. In this incident RAG, model context, memory, external providers, retention behavior, and deletion are **NOT MODELED**. Do not fabricate missing stages.

Inventory relevant personal, financial, authentication/security, business-confidential, AI-context, and security-evidence data according to this scenario.
""", "DATA LIFECYCLE · INVENTORY")
    add("viz_map", """
# Map the data before judging it

Task: confirm a synthetic customer's preferred support-contact channel.

For each flow ask: WHAT DATA? FROM WHERE? TO WHERE? WHY? WHO CAN SEE IT? IS IT REQUIRED? TRANSFORMED? PERSISTED? LOGGED? DOES IT CROSS A BOUNDARY?

```text
SYNTHETIC FIXTURE → TOOL ARGUMENT → CTRL-MCP-001 → FIXTURE TOOL
                                            │
                                            └→ TELEMETRY → SPLUNK COPY
```

CTRL-MCP-001 authorizes the tool. It does not establish that every argument field is appropriate.
""", "DATA MAP")
    add("viz_privacy_domains", """
# Apply the concepts without inventing incident facts

**RAG:** retrieval authorization is separate from tool authorization. Over-broad or cross-context retrieval can expose sensitive content. CTRL-MCP-001 does not control retrieval here.

**Memory:** distinguish WRITE, PERSIST, RECALL, REUSE. Privacy/retention failure is not identical to memory poisoning.

**Prompt:** ask what personal, confidential, secret, retrieved, or historical data actually needs to enter model context.

**Inference:** separately harmless inputs may support a sensitive inference; universal inference detection is not claimed.

For this incident these paths are architectural questions, not observed events.
""", "RAG · MEMORY · PROMPT · INFERENCE")
    add("viz_trace", f"""
# Path A · investigate before comparing

1. Discover candidates with `Q-PRIVACY-CANDIDATES`.
2. Bind `Q-PRIVACY-TRACE` to a candidate run.
3. Sort by `agentsec.sequence`; separate request, decision, invocation, completion, outcome, and telemetry.
4. Record each claim, evidence, data, boundary, confidence, and missing evidence.

Canonical full-record specimen: `{FULL_RUN}`
Canonical minimized specimen: `{MIN_RUN}`

These are **MEASURED historical copies**, not a launch you just minted. If Splunk returns no rows: **NO EVIDENCE FOUND — not SAFE**.
""", "TRACE · SPLUNK")
    add("viz_hints", """
# Progressive hints

**Hint 1:** Write the task purpose first; purpose determines necessity.

**Hint 2:** Find CTRL-MCP-001 decisions, then inspect execution and data evidence separately.

**Hint 3:** Compare `agentsec.content.preview` and content hashes. A preview is a bounded telemetry copy and itself illustrates logging exposure.

**Hint 4:** Use candidate → trace → compare only after recording your initial conclusion.
""", "GUIDED → INVESTIGATE → CHALLENGE")
    add("viz_minimize", """
# Minimization challenge

Select the minimum fields needed to confirm the preferred **channel type**:

`customer_id` · `preferred_channel` · `email` · `postal_address` · `account_balance_band` · `internal_case_note`

Explain each inclusion and exclusion. Cosmetic hiding is not minimization: the excluded fields must not enter the tool argument or its telemetry copy.

Redaction can reduce exposure, but it does not establish purpose, prevent inference, guarantee deletion, or repair over-broad retrieval.
""", "MINIMIZE")
    add("viz_observability", """
# How much should we log?

Balance investigative value against sensitivity, retention, access, minimization, redaction, provenance, and correlation. More telemetry may improve investigation: telemetry while increasing exposure is a privacy design failure.

Secrets, credentials, and tokens should not enter ordinary model context or telemetry. All examples here are synthetic; `example.invalid` cannot identify a real customer.

Specify event, source, timestamp, identity claim, request, decision, invocation, completion, outcome, correlation identifier, and provenance—without copying unnecessary content.
""", "TELEMETRY VS PRIVACY")
    add("viz_threat_model", """
# Privacy threat model

For each concern bind:

**ASSET → SOURCE → PROCESSOR → BOUNDARY → PURPOSE → EXPOSURE → PERSISTENCE → CONTROL → TELEMETRY → RESIDUAL RISK**

Consider input minimization, retrieval/memory scoping, argument filtering, secret exclusion, redaction, access control, retention, telemetry access, deletion, and monitoring. Place each control where it can affect the data flow.

Authentication, human approval, cryptographic delegation, provider retention, secure deletion, and production tenant isolation are **NOT MODELED**.
""", "THREAT MODEL · CONTROL DESIGN")
    add("viz_design", """
# Privacy by design

Before deployment ask: What data do we need and why? Where does it go? Who can see it? How long is it needed? What is logged? How can we investigate without over-collecting? What happens when it is no longer needed?

Produce three bounded explanations:

- **Engineering:** technical change and control placement.
- **SOC / Privacy Operations:** monitoring, access, retention, and investigation.
- **Leadership:** information exposed or potentially exposed, affected process, what is proven, uncertainty, and recommendation.

Avoid unsupported breach language and fake risk scores.
""", "DESIGN · COMMUNICATE")
    add("viz_frameworks", """
# EDUCATIONAL MAPPING

NIST Privacy Framework 1.0 is the current final framework used here; PF 1.1 remains an Initial Public Draft. NIST AI RMF 1.0 supplies AI risk context. Current OWASP agentic/application guidance supplies data-exposure questions.

**This is not compliance validation. This is not legal determination. This is not certification. This is not complete framework coverage.**

Unverified identifier-level mappings remain **NEEDS_EXTERNAL_VALIDATION**.
""", "FRAMEWORK CONTEXT")
    add("viz_review", """
# Path B · bounded reference analysis

Open after recording purpose, required fields, trace, and evidence ledger.

The bounded task requires `customer_id` and `preferred_channel`. The full specimen additionally supplied synthetic email, postal address, balance band, and internal case note. The minimized specimen excluded those fields.

Both runs received CTRL-MCP-001 **ALLOW / tool_granted**, invoked the same fixture-backed handler once, completed, and produced seven distinct correlated event payloads in live Splunk. Duplicate indexed rows were observed after local app restaging and are not additional runtime actions. Therefore authorization and expected execution stayed constant while data supplied to the tool and copied into telemetry changed.

This proves the bounded specimen comparison—not production exposure, provider handling, retention, deletion, RAG or memory behavior, universal control effectiveness, or a breach.
""", "REFERENCE ANALYSIS")
    add("viz_finish", """
# Residual risk and finish

`ALLOW + MINIMIZED DATA + EXPECTED EXECUTION` is preferable here to `ALLOW + EXCESSIVE DATA + EXPECTED EXECUTION`, but minimization does not eliminate risk.

Record remaining exposure, monitoring and response requirements, access to telemetry, retention/deletion uncertainty, and assumptions.

Complete the reusable evidence-ledger, privacy-threat-model, and incident-report templates. Screen-reader validation remains **PARTIAL** unless independently tested.
""", "PATH B · REVIEW")

    definition = {
        "title": "Privacy, Data Protection & Agentic Data Governance",
        "description": "L8 REPLAY privacy workbench. Synthetic evidence; not compliance or legal advice.",
        "defaults": studio_defaults(),
        "inputs": {},
        "visualizations": visualizations,
        "layout": {"options": layout_options(), "layoutDefinitions": {
            "layout_foundations": layout([block("viz_foundations", 0, 0, FULL, 520), block("viz_lifecycle", 0, 520, FULL, 480)], 1020),
            "layout_map": layout([block("viz_map", 0, 0, HALF, 620), block("viz_privacy_domains", HALF, 0, HALF, 620)], 640),
            "layout_trace": layout([block("viz_trace", 0, 0, HALF, 620), block("viz_hints", HALF, 0, HALF, 620)], 640),
            "layout_investigate": layout([block("viz_observability", 0, 0, FULL, 620)], 640),
            "layout_minimize": layout([block("viz_minimize", 0, 0, FULL, 620)], 640),
            "layout_model": layout([block("viz_threat_model", 0, 0, FULL, 680)], 700),
            "layout_design": layout([block("viz_design", 0, 0, HALF, 680), block("viz_frameworks", HALF, 0, HALF, 680)], 700),
            "layout_review": layout([block("viz_review", 0, 0, FULL, 760), block("viz_finish", 0, 760, FULL, 500)], 1280),
        }, "tabs": {"options": {"barPosition": "top"}, "items": [
            {"layoutId": "layout_foundations", "label": "FOUNDATIONS"},
            {"layoutId": "layout_map", "label": "DATA MAP"},
            {"layoutId": "layout_trace", "label": "TRACE"},
            {"layoutId": "layout_investigate", "label": "INVESTIGATE"},
            {"layoutId": "layout_minimize", "label": "MINIMIZE"},
            {"layoutId": "layout_model", "label": "THREAT MODEL"},
            {"layoutId": "layout_design", "label": "DESIGN"},
            {"layoutId": "layout_review", "label": "PATH B · REVIEW"},
        ]}},
        "applicationProperties": {"collapseNavigation": False, "downsampleVisualizations": False},
    }
    validate(definition)
    return definition


def validate(definition: dict) -> None:
    early_ids = tuple(f"layout_{name}" for name in ("foundations", "map", "trace", "investigate", "minimize", "model", "design"))
    early = "\n".join(definition["visualizations"][row["item"]]["options"]["markdown"] for lid in early_ids for row in definition["layout"]["layoutDefinitions"][lid]["structure"])
    for answer in ("The bounded task requires", "full specimen additionally supplied", "produced seven distinct correlated event payloads"):
        if answer in early:
            raise ValueError(f"Path B answer leaked: {answer}")
    payload = json.dumps(definition)
    for forbidden in ("index=*", "privacy score", "compliance score", "SAFE</"):
        if forbidden in payload:
            raise ValueError(f"forbidden implication: {forbidden}")


def main() -> None:
    definition = build()
    write_definition(OUT_JSON, definition)
    write_studio_xml(OUT_XML, definition, label="Privacy and Data Governance", description="L8 synthetic privacy investigation workbench.")
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
