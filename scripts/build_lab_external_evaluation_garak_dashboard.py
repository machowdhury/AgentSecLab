#!/usr/bin/env python3
"""Build the External Security Toolbox replay workshop.

Consumes only live-validated investigation searches. External findings and
evaluations remain non-causal evidence beside runtime telemetry.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from agentsec_studio import (  # noqa: E402
    FULL,
    HALF,
    THIRD,
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

LAB = ROOT / "learning" / "level_1" / "LAB-EXTERNAL-EVALUATION-GARAK"
CATALOG_SEARCHES = ROOT / "learning" / "level_1" / "LAB-MCP-CATALOG" / "searches"
OUT_JSON = LAB / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_external_evaluation_garak.xml"
)

MALICIOUS_SCAN = "7ae3ea64-4e7a-40fe-943f-3e582bce5ee8"
GARAK_EVIDENCE_ID = "aeb05718-1364-4143-8248-71dd6f27b07b|dan.Dan_11_0|dan.DAN"
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
HOME_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
SCANNER_URL = (
    "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_scanner_runtime_evidence"
)

NO_EVIDENCE = (
    "NO EVIDENCE FOUND. Check Splunk availability, HEC ingestion, time range, "
    "sourcetype, and evidence identifier. Zero rows is not SAFE, not DENY, "
    "not prevention, and not proof that no evaluation or finding exists."
)


def _spl(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _scan_query(name: str) -> str:
    query = _spl(CATALOG_SEARCHES / name)
    if "__SCAN_ID__" not in query:
        raise ValueError(f"{name} has no __SCAN_ID__ token")
    return query.replace("__SCAN_ID__", f'"{MALICIOUS_SCAN}"')


def build() -> dict:
    data_sources = dict(
        (
            search_ds("ds_cisco_who", "Q-SCANNER-WHO malicious specimen", _scan_query("Q-SCANNER-WHO.spl")),
            search_ds(
                "ds_cisco_finding",
                "Q-SCANNER-FINDINGS malicious specimen",
                _scan_query("Q-SCANNER-FINDINGS.spl"),
            ),
            search_ds(
                "ds_garak",
                "Q-GARAK-EVALUATION",
                _spl(LAB / "searches" / "Q-GARAK-EVALUATION.spl"),
            ),
            search_ds(
                "ds_planes",
                "Q-EXTERNAL-EVIDENCE-PLANES",
                _spl(LAB / "searches" / "Q-EXTERNAL-EVIDENCE-PLANES.spl"),
            ),
        )
    )
    visualizations: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    def add_table(viz_id: str, ds: str, title: str, description: str) -> str:
        key, viz = table(viz_id, ds, title, description, no_data=NO_EVIDENCE)
        visualizations[key] = viz
        return key

    add_md(
        "viz_toolbox",
        f"""
# External Security Toolbox

Two independent tools answer two different security questions. This is a bounded
learning toolbox—not a marketplace, endorsement, certification, or product catalog.

**BUILT BY AGENTSEC** — ExternalEvidence 1.0.0, adapters, HEC serialization,
investigation searches, and this learning experience.

**INTEGRATED BY AGENTSEC** — pinned local Cisco mcp-scanner and garak workflows.

**TAUGHT / REFERENCED BY AGENTSEC** — upstream tool behavior, native results,
project names, probes, detectors, and licenses. Upstream questions remain
`NEEDS_EXTERNAL_VALIDATION`.

[Review Cisco finding first]({SCANNER_URL}) · [Open Splunk Search]({SEARCH_URL})

```text
RUNTIME EVENT != SCANNER FINDING != ADVERSARIAL EVALUATION
FINDING != AUTHORIZATION
EVALUATION != AUTHORIZATION
SPLUNK != PDP
CORRELATION != CAUSATION
```
""",
        "TOOLBOX",
    )
    add_md(
        "viz_cisco",
        """
# Cisco mcp-scanner

**Classification:** STATIC / CATALOG SECURITY FINDING

It statically inspects the exported MCP tool catalog with the pinned YARA
analyzer. AgentSec preserves native output, emits class `finding`, and indexes
it as `agentsec:scanner:finding`.

**Upstream attribution:** repository pin metadata identifies
[cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner).
Current upstream details remain `NEEDS_EXTERNAL_VALIDATION`.

**It establishes:** this configured scan examined these catalog bytes and
reported its native result.

**It does not establish:** exploitation, authorization, execution, causality,
or safety. `HIGH != DENY`. `ZERO FINDINGS != SAFE`.

**Correlation:** SHA-256 over the UTF-8 tool-description bytes is compared with
runtime `content.hash`. A match proves only that defined byte relationship.
""",
        "STATIC FINDING",
    )
    add_md(
        "viz_garak_intro",
        """
# garak

**Classification:** ADVERSARIAL MODEL EVALUATION

garak probes a model and evaluates the response with a native detector.
AgentSec preserves JSONL, emits class `evaluation`, and indexes it as
`agentsec:external:evaluation`.

**Upstream attribution:** repository pin metadata identifies
[NVIDIA/garak](https://github.com/NVIDIA/garak). Current upstream details
remain `NEEDS_EXTERNAL_VALIDATION`.

**It establishes:** one response was evaluated under the recorded model,
probe, detector, seed, and configuration.

**It does not establish:** universal safety, compromise, tool execution, or
authorization. `PASS != SAFE`. `FAIL != EXPLOIT CONFIRMED`.

**Correlation:** native run + probe + detector + model identify the evaluation.
No `agentsec.run.id` or catalog hash is manufactured.
""",
        "ADVERSARIAL EVALUATION",
    )
    add_md(
        "viz_guided",
        f"""
# GUIDED — WHY → WHAT → WHERE IT FITS

**WHY:** use independent evidence to challenge assumptions and increase
assurance within tested conditions.

**WHAT:** compare a static catalog finding, an adversarial model evaluation,
and runtime telemetry without merging them.

**WHERE:** external tools normalize to ExternalEvidence, then HEC sends them to
Splunk. CTRL-MCP-001 remains the separate tool PDP.

**PREDICT:** before reading rows, decide which source can prove authorization,
which can prove execution began, and whether native HIGH or PASS can answer either.

**RUN / REPLAY:** this REPLAY workshop uses canonical historical evidence
generated by the real pack builders. It is not a fresh scanner or garak run.

**READ NATIVE RESULT → NORMALIZE → INGEST:** trace the native result into the
normalized contract, then verify the indexed fields and provenance before
correlating anything.

Cisco scan `{MALICIOUS_SCAN}`

garak evidence `{GARAK_EVIDENCE_ID}`
""",
        "GUIDED",
    )
    add_table(
        "viz_cisco_who",
        "ds_cisco_who",
        "READ NATIVE CONTEXT — Cisco",
        "Confirm tool/version, scan execution, and count. Scan execution is not authorization.",
    )
    add_table(
        "viz_cisco_finding",
        "ds_cisco_finding",
        "NORMALIZE — Cisco finding",
        "Read native severity/category and finding state. HIGH is not DENY or exploit proof.",
    )
    add_table(
        "viz_garak",
        "ds_garak",
        "READ + NORMALIZE — garak evaluation",
        "Trace result, model, probe, detector, evidence ID, raw reference/hash, and identity tuple.",
    )
    add_md(
        "viz_investigate",
        f"""
# INVESTIGATE — INGEST → SEARCH → CORRELATE

**Path A — try it yourself:** [Open Splunk Search]({SEARCH_URL}). Run
`Q-GARAK-EVALUATION.spl`, then `Q-EXTERNAL-EVIDENCE-PLANES.spl`. For Cisco,
start with `scan_id="{MALICIOUS_SCAN}"`.

Questions:

1. Which sourcetype carries each source?
2. What native result is preserved?
3. Can you trace the indexed row to raw evidence by path and SHA-256?
4. Which correlation method is used, and what exact relationship does it support?
5. Which runtime fields are intentionally absent from external evidence?

**Path B — show solution:** the tables below are the expected shape. Read them
only after Path A. They are an answer key, not policy; Splunk does not enforce.

No row means **NO EVIDENCE FOUND**, not SAFE. Diagnose Splunk, HEC, pack,
identifier, sourcetype, and time-range failures before making a claim.
Empty is not DENY, prevention, or proof that nothing occurred.
""",
        "INVESTIGATE",
    )
    add_table(
        "viz_planes",
        "ds_planes",
        "Q-EXTERNAL-EVIDENCE-PLANES",
        "Compare RUNTIME, STATIC FINDING, and ADVERSARIAL EVALUATION. Adjacency is not causality.",
    )
    add_md(
        "viz_challenge",
        """
# CHALLENGE THE EVIDENCE

For each row answer:

**What does it establish?** State only the observed tool/result/provenance fact.

**What does it suggest?** Identify a hypothesis worth further investigation.

**What does it NOT establish?** Separate authorization, execution, completion,
impact, safety, and causality.

**What additional evidence is required?** Ask for PDP decision/reason,
`mcp.started`, completion/failure, handler evidence, impact, broader negative
testing, and independent validation as appropriate.

Reason carefully:

- scanner severity HIGH does not prove exploitation;
- scanner finding_count 0 does not prove safety;
- evaluation FAIL does not prove compromise;
- evaluation PASS does not establish universal safety;
- control.decision ALLOW does not prove execution;
- execution.started does not prove successful completion.
""",
        "CHALLENGE",
    )
    add_md(
        "viz_fundamentals",
        """
# SECURITY FUNDAMENTALS

**Evidence quality and provenance:** preserve the native result, source,
version, timestamp, raw reference, and digest.

**Trust and authorization:** content and tool output are data. They do not mint
authority. Least privilege remains a coded policy concern.

**Execution and validation:** distinguish request, grant, start, completion,
failure, and impact.

**Negative testing and assurance:** tests increase confidence only within the
measured conditions. Defense in depth combines evaluation, preventive controls,
telemetry, investigation, and retesting.

**Correlation and causality:** shared identifiers or hashes support a named
relationship. They do not create a causal chain.
""",
        "TRANSFERABLE CONCEPTS",
    )
    add_md(
        "viz_threat",
        """
# THREAT-MODELING BRIDGE

**ASSET** — What model behavior, catalog integrity, authority, or data matters?

**ACTOR** — Who can influence the catalog, probe input, model response, or request?

**ENTRY POINT** — Where can untrusted text or metadata enter?

**TRUST BOUNDARY** — Where does data meet the model, adapter, PDP, or tool?

**CONTROL** — Which coded control should govern the dangerous action?

**OBSERVABILITY** — Which evidence would establish request, decision, start,
completion, failure, or impact?

**RESIDUAL RISK** — What remains after this specific scan, evaluation, and control?
""",
        "THREAT MODEL",
    )
    add_md(
        "viz_frameworks",
        """
# FRAMEWORK CONTEXT — EDUCATIONAL MAPPING

The specimen carries an upstream `owasp:llm01` tag. OWASP, MITRE ATLAS,
MAESTRO, and NIST AI RMF can provide educational vocabulary for adversarial
input, trust boundaries, testing, and assurance.

These references are **NEEDS_EXTERNAL_VALIDATION**. They are not compliance,
certification, complete coverage, or validated framework mappings.
""",
        "EDUCATIONAL MAPPING",
    )
    add_md(
        "viz_check",
        f"""
# EXPLAIN / KNOWLEDGE CHECK

1. Why are Cisco and garak different evidence classes?
2. What exact bytes support the Cisco hash relationship?
3. Why is garak identity correlation not an AgentSec runtime chain?
4. What does PASS establish here? What does it not establish?
5. Which component authorizes AgentSec MCP tools?
6. What evidence separates ALLOW from execution and completion?
7. What does NO EVIDENCE FOUND require you to check?
8. Fill in ASSET, ACTOR, ENTRY POINT, TRUST BOUNDARY, CONTROL,
   OBSERVABILITY, and RESIDUAL RISK.

Return to [Academy Home]({HOME_URL}) after answering in your own words.
Viewing this tab is not stored completion and is not certification.
""",
        "EXPLAIN",
    )

    definition = {
        "title": "External Security Toolbox",
        "description": (
            "Replay investigation of Cisco static findings, garak evaluations, "
            "and separate AgentSec runtime telemetry. Splunk is not the PDP."
        ),
        "defaults": studio_defaults(),
        "inputs": {},
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "options": layout_options(),
            "globalInputs": [],
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_toolbox", "label": "TOOLBOX"},
                    {"layoutId": "layout_guided", "label": "GUIDED"},
                    {"layoutId": "layout_investigate", "label": "INVESTIGATE"},
                    {"layoutId": "layout_challenge", "label": "CHALLENGE"},
                ],
            },
            "layoutDefinitions": {
                "layout_toolbox": layout(
                    [
                        block("viz_toolbox", 0, 0, FULL, 440),
                        block("viz_cisco", 0, 440, HALF, 460),
                        block("viz_garak_intro", HALF, 440, HALF, 460),
                    ],
                    920,
                ),
                "layout_guided": layout(
                    [
                        block("viz_guided", 0, 0, FULL, 420),
                        block("viz_cisco_who", 0, 420, HALF, 300),
                        block("viz_cisco_finding", HALF, 420, HALF, 300),
                        block("viz_garak", 0, 720, FULL, 360),
                    ],
                    1100,
                ),
                "layout_investigate": layout(
                    [
                        block("viz_investigate", 0, 0, FULL, 520),
                        block("viz_planes", 0, 520, FULL, 380),
                    ],
                    920,
                ),
                "layout_challenge": layout(
                    [
                        block("viz_challenge", 0, 0, FULL, 480),
                        block("viz_fundamentals", 0, 480, HALF, 460),
                        block("viz_threat", HALF, 480, HALF, 460),
                        block("viz_frameworks", 0, 940, THIRD, 360),
                        block("viz_check", THIRD, 940, THIRD * 2, 360),
                    ],
                    1320,
                ),
            },
        },
        "applicationProperties": {
            "collapseNavigation": False,
            "downsampleVisualizations": False,
        },
    }
    return definition


def main() -> None:
    definition = build()
    write_definition(OUT_JSON, definition)
    write_studio_xml(
        OUT_XML,
        label="External Security Toolbox",
        description=(
            "LAB-EXTERNAL-EVALUATION-GARAK · REPLAY · External evidence is "
            "not authorization; Splunk is not the PDP."
        ),
        definition=definition,
    )
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
