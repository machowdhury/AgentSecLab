#!/usr/bin/env python3
"""Build the bounded L9 multi-stage incident workbench."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from agentsec_studio import (  # noqa: E402
    FULL, HALF, block, layout, layout_options, markdown, search_ds,
    specimen_dropdown, studio_defaults, table, write_definition, write_studio_xml,
)

LAB = ROOT / "learning" / "level_1" / "LAB-MULTI-STAGE-INCIDENT-001"
SEARCHES = LAB / "searches"
OUT_JSON = LAB / "dashboard.definition.json"
OUT_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_multi_stage_incident.xml"
ATTACK = "2437f64a-fff4-424f-8a83-0f04285662e4"
RETEST = "8d2c016f-cadc-4463-939a-23a183221b3d"


def _spl(name: str) -> str:
    return (SEARCHES / name).read_text(encoding="utf-8").strip()


def build() -> dict:
    visualizations: dict[str, dict] = {}
    data_sources: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str) -> None:
        key, value = markdown(viz_id, body, title)
        visualizations[key] = value

    def add_table(viz_id: str, ds: str, title: str, description: str) -> None:
        key, value = table(
            viz_id, ds, title, description,
            no_data="NO EVIDENCE FOUND / INSUFFICIENT EVIDENCE. This is not SAFE and does not prove prevention.",
        )
        visualizations[key] = value

    def add_ds(ds_id: str, name: str, query: str) -> None:
        key, value = search_ds(ds_id, name, query)
        data_sources[key] = value

    timeline = _spl("Q-L9-TIMELINE.spl").replace("__RUN_ID__", '"$incident_run_id$"')
    compare = _spl("Q-L9-COMPARE.spl").replace("__ATTACK_RUN_ID__", f'"{ATTACK}"').replace("__RETEST_RUN_ID__", f'"{RETEST}"')
    add_ds("ds_discover", "Q-L9-DISCOVER", _spl("Q-L9-DISCOVER.spl"))
    add_ds("ds_timeline", "Q-L9-TIMELINE", timeline)
    add_ds("ds_compare", "Q-L9-COMPARE", compare)
    add_ds("ds_external", "Q-L9-EXTERNAL-PIVOT", _spl("Q-L9-EXTERNAL-PIVOT.spl"))
    add_ds("ds_detection", "Q-L9-DETECTION-CANDIDATE", _spl("Q-L9-DETECTION-CANDIDATE.spl"))
    add_ds("ds_hunt", "Q-L9-HUNT", _spl("Q-L9-HUNT.spl"))

    add_md("viz_incident", """
# ACME BANK INCIDENT AGENT-2026-009

**REPLAY workshop. Path A begins in Splunk Search; Path B is a review key, not policy.**

Security Operations identified unusual activity in an AI-assisted lending customer workflow between approximately **2026-09-20 19:37:40Z and 19:38:00Z**.

Available telemetry suggests external context may have influenced agent behavior and a privileged customer-information tool may have been requested.

Determine what actually occurred, whether unauthorized execution took place, what synthetic data was affected, which controls succeeded or failed, and how the architecture should change.

Starting observables: affected workflow · possible privileged request · possible untrusted context.

Write your initial hypothesis now. No run ID, attack family, decision, execution state, root cause, or data-impact answer is supplied here.
""", "INCIDENT BRIEF")
    add_md("viz_method", """
# Multi-stage analytical model

ENTRY → INFLUENCE → CONTEXT → INTENT / GOAL → REQUEST → AUTHORITY → EXECUTION → OUTCOME → PERSISTENCE → OBSERVABILITY

This is an investigation model, not a universal attack sequence. Classify every stage textually:

**PROVEN · SUPPORTED · OBSERVED · INFERRED · NOT OBSERVED · NOT MODELED · NOT PROVEN · REFUTED**

`CLAIM STRENGTH <= EVIDENCE STRENGTH`
""", "METHOD · EVIDENCE STATES")
    add_md("viz_modes", """
# Same incident, three modes

**GUIDED** — incident window, observables, and progressive hints.

**INVESTIGATOR** — incident brief and approximate window; construct SPL.

**ADVANCED / ARCHITECT** — brief, architecture, and evidence access only; independently classify stages, controls, response, and redesign.

Do not force RAG, Memory, Goal, Identity, MCP, scanner, and garak into one explanation. Ruling a domain out is valid analysis.
""", "LEARNER MODE")

    add_md("viz_hypothesis", """
# Decompose the hypothesis

Example to test—not an answer: “Untrusted retrieved content caused the agent to request and execute an unauthorized customer-data operation.”

Ask separately: Was untrusted content present and retrieved? Did equivalent content persist and recall? Did behavior form a privileged request? Was it authorized? Was the handler invoked? Did it complete? What synthetic data was returned? What remains unknown?

The full chain is not established unless each required link has evidence.
""", "HYPOTHESIS")
    add_md("viz_hints", """
# Progressive hints

**HINT 1 — plane:** start with runtime tool-control decisions in the bounded window.

**HINT 2 — evidence type:** pivot candidate run IDs into memory, MCP authorization, execution, and outcome.

**HINT 3 — fields:** sequence, event.name, content.hash, memory.id, source_run_id, requested/allowed scope, decision, reason, outcome.

**HINT 4 — SPL:** Q-L9-DISCOVER → Q-L9-TIMELINE → Q-L9-COMPARE, only after recording a hypothesis.
""", "HINT SYSTEM")
    add_table("viz_discover", "ds_discover", "Candidate discovery", "Bounded tool-control candidates. A candidate is not an incident and a request is not execution.")

    add_md("viz_timeline_help", """
# Reconstruct, do not collapse

Prove each transition independently:

REQUEST → DECISION → INVOCATION → COMPLETION → OUTCOME

Use runtime `agentsec.sequence` within a run. Use `source_run_id`, memory ID, and canonical hash across write/recall. Hash equality supports byte equality; it does not establish a direct retrieve-output-to-write causal edge.
""", "TIMELINE METHOD")
    add_table("viz_timeline", "ds_timeline", "Selected candidate timeline", "Sequence-ordered evidence for the selected candidate. Dropdown labels intentionally do not reveal the answer.")
    add_md("viz_graph", """
# Bounded evidence graph

Use only explicit edges: **PRECEDES · CORRELATES_WITH · REQUESTS · AUTHORIZED_BY · EXECUTED_BY · PRODUCED · REFERENCES**.

Do not write `CAUSED` unless causality is independently established. UI color is never the state; every node needs textual evidence state and identifier.

Missing event → `NOT OBSERVED`, not prevention. Missing capability → `NOT MODELED`. Unsupported conclusion → `NOT PROVEN`.
""", "EVIDENCE GRAPH")

    add_md("viz_ledger", """
# Incident evidence ledger

For every claim record: evidence ID · plane · state · alternative explanation · missing evidence.

Separate runtime (`otel:agentic:json`), scanner (`agentsec:scanner:finding`), and evaluation (`agentsec:external:evaluation`) planes. Correlation is not causation.

Challenge your first hypothesis with contradictory evidence and valid alternate explanations.
""", "EVIDENCE")
    add_table("viz_external", "ds_external", "Adjacent external evidence", "Scanner and garak evidence for triage. No automatic causal join to runtime.")
    add_md("viz_false_lead", """
# False-lead test

A Cisco mcp-scanner finding reports native **HIGH / PROMPT INJECTION**. Determine whether its description hash matches the incident fingerprint and whether a runtime join exists.

A garak evaluation PASS targets a local model and carries no AgentSec runtime run ID. Decide whether it supports, contextualizes, or fails to correlate with this incident.

Scanner HIGH != exploitation. Evaluation PASS != safe. External evidence remains adjacent.
""", "CHALLENGE THE HYPOTHESIS")

    add_md("viz_controls", """
# Control analysis

For each stage record threat · control · preventive/detective/corrective/recovery · OBSERVE/ENFORCE · result · evidence.

Distinguish **CONTROL PRESENT · TRIGGERED · SUCCEEDED · FAILED · NOT APPLICABLE · NOT MODELED**.

RAG and Memory controls classify influence. CTRL-MCP-001 decides tool authority before invocation. Splunk investigates downstream. Goal and Identity must not be blamed without evidence.
""", "CONTROLS")
    add_table("viz_compare", "ds_compare", "ATTACK / RETEST comparison", "Compare shared influence with authorization and execution. Duplicate indexed copies are not additional executions.")

    add_md("viz_data", """
# Data / privacy impact

Ask separately: Was the action authorized? Did execution occur? What synthetic data was supplied or returned? Was every field necessary? Where did it travel or appear in telemetry? Was it persisted? What field-level impact is proven?

The packet supports a synthetic customer-tier result. It does not establish production customer exposure, field-level necessity, provider retention, or a breach.

Authorized execution does not establish appropriate data use.
""", "DATA IMPACT")
    add_md("viz_identity_memory", """
# Persistence and identity

Memory involvement requires WRITE → PERSIST → RECALL → REUSE evidence. `source_run_id`, memory ID, and hash support the bounded write/recall link.

Identity/Delegation control events are **NOT OBSERVED** in this packet. Authentication, production IAM, human approval, and cryptographic delegation are **NOT MODELED**. A caller claim would not establish authentication.
""", "MEMORY · IDENTITY")

    add_md("viz_respond", """
# Respond

**Immediate containment:** restrict or disable the affected fixture workflow; remove suspect context; isolate associated memory; constrain tool scope; preserve evidence. Educational recommendations only—perform no real-world action.

**Root-cause remediation:** remove the vulnerable fail-open experiment condition and preserve fail-safe CTRL-MCP-001 behavior.

**Architectural hardening:** retrieval/memory scoping, least privilege, argument minimization, downstream authorization, telemetry completeness, bounded retention, and tested recovery.

Containment != remediation != architectural hardening.
""", "CONTAINMENT · REMEDIATION")
    add_md("viz_retest", """
# Retest

Compare the same canonical influence fingerprint and same privileged request.

Record what stayed identical, what ExperimentContext/control result changed, whether invocation began, whether expected legitimate functionality remained, and what evidence proves each claim.

Defense success is not merely “handler zero”; it also requires the intended authorization result and preserved legitimate behavior. One RETEST does not prove universal resistance.
""", "RETEST")

    add_md("viz_detection_help", """
# Candidate detection—not installed

INCIDENT → OBSERVABLES → CANDIDATE SPL → ATTACK → RETEST → BASELINE → FALSE-POSITIVE REVIEW → DETECTION CANDIDATE

The candidate hunts authority mismatch followed by execution. Validate it against ATTACK, RETEST, and benign `lookup_policy` activity. Do not create a saved search or call silence SAFE.
""", "DETECTION ENGINEERING")
    add_table("viz_detection", "ds_detection", "Candidate SPL result", "Experimental detection logic. This is not a packaged detector or production alert.")
    add_md("viz_hunt_help", """
# Hunt expansion

Ask whether similar authority-mismatch behavior occurred elsewhere without starting from a known run ID.

Document hypothesis, time range, candidates, pivots, exclusions, conclusion, and limitations. Broad matches require control-reason and execution review.
""", "THREAT HUNT")
    add_table("viz_hunt", "ds_hunt", "Expanded 30-day hunt", "Candidate list requiring analyst review. Empty is NO EVIDENCE FOUND, not SAFE.")

    add_md("viz_updates", """
# Feed operations back into architecture

**Threat-model update:** customer information and grant integrity are assets; RAG/memory are influence boundaries; MCP is the authority boundary; a vulnerable fail-open condition is a control gap; telemetry needs cross-run reconstruction.

**Privacy-model update:** customer-tier data is part of the inventory; purpose and minimization need explicit evidence; tool result and telemetry are exposure paths; retention remains NOT MODELED.

Record residual security and privacy risk after the defended comparison.
""", "THREAT · PRIVACY MODEL UPDATE")
    add_md("viz_reports", """
# Communicate three times

**SOC / Incident Response:** detailed evidence IDs, SPL, sequence, alternative explanations, gaps, containment.

**Engineering / Architecture:** root-cause remediation, control placement, tests, observability, data minimization.

**Executive / CISO:** what occurred, bounded business/data impact, proven facts, uncertainty, containment, recommended actions, residual risk.

No sensational language. Do not claim a production breach.
""", "REPORT")

    add_md("viz_answer", """
# Path B · bounded reference reasoning

Open only after completing an initial hypothesis, candidate timeline, evidence ledger, and challenge step.

The canonical packet shows untrusted retrieved content, fixture-equivalent persisted bytes, later recall, and a privileged `lookup_customer_tier / customer:read` request. RAG and Memory controls stayed OBSERVE and did not mint authority.

On ATTACK, CTRL-MCP-001 recorded a labeled vulnerable fail-open ALLOW before handler invocation; runtime handler count was 1, followed by `mcp.started`, `mcp.completed`, and a successful fixture outcome. On RETEST, the same influence fingerprint and request reached CTRL-MCP-001, which DENIED `tool_not_granted`; handler count was 0.

Goal and Identity failure are NOT OBSERVED. Authentication and production impact are NOT MODELED. Direct retrieve-output → write causality and field-level privacy necessity are NOT PROVEN.
""", "PATH B")
    add_md("viz_commander", """
# Incident commander view

**What happened?** A bounded untrusted-context/memory chain formed a privileged request; vulnerable authorization allowed fixture execution.

**What is proven?** Request, ATTACK ALLOW, invocation, completion, synthetic result; RETEST DENY and handler zero.

**What is not proven?** Production breach, authentication, goal/identity failure, direct retrieve-to-write causality, universal safety.

**Controls:** RAG/Memory observed; vulnerable MCP condition failed; defended MCP succeeded; Splunk reconstructed.

**Now:** contain workflow/context/memory, preserve evidence, enforce least privilege, retest, validate candidate detection and hunt.
""", "COMMANDER SUMMARY")
    add_md("viz_frameworks", """
# EDUCATIONAL MAPPING

Relate only relevant concepts through previously validated OWASP, MITRE ATLAS, CSA MAESTRO, NIST AI RMF, and NIST Privacy Framework lenses.

No unverified identifier is introduced. This is not certification. This is not compliance validation. This is not complete framework coverage. This is not a legal determination.
""", "FRAMEWORK SYNTHESIS")
    add_md("viz_failures", """
# Failure-state language

Splunk unavailable → INVESTIGATION EVIDENCE UNAVAILABLE. HEC unavailable → EXPORT PATH UNAVAILABLE. Incomplete run → INSUFFICIENT EVIDENCE. Missing event → NOT OBSERVED. Missing correlation → NO JUSTIFIED JOIN. Empty hunt → NO EVIDENCE FOUND.

Never replace any of these with SAFE.
""", "FAILURE STATES")

    inputs = dict([
        specimen_dropdown(
            "input_incident_run", token="incident_run_id", default=ATTACK,
            items=[("Candidate 01", ATTACK), ("Candidate 02", RETEST)],
            title="Investigate selected candidate",
        )
    ])
    tabs = [
        ("layout_incident", "INCIDENT"), ("layout_investigate", "INVESTIGATE"),
        ("layout_timeline", "TIMELINE"), ("layout_evidence", "EVIDENCE"),
        ("layout_controls", "CONTROLS"), ("layout_data", "DATA IMPACT"),
        ("layout_respond", "RESPOND"), ("layout_model", "THREAT MODEL"),
        ("layout_report", "REPORT"), ("layout_answer", "PATH B"),
    ]
    definitions = {
        "layout_incident": layout([block("viz_incident", 0, 0, FULL, 620), block("viz_method", 0, 620, HALF, 520), block("viz_modes", HALF, 620, HALF, 520)], 1160),
        "layout_investigate": layout([block("viz_hypothesis", 0, 0, HALF, 600), block("viz_hints", HALF, 0, HALF, 600), block("viz_discover", 0, 600, FULL, 440)], 1060),
        "layout_timeline": layout([block("viz_timeline_help", 0, 0, FULL, 470), block("viz_timeline", 0, 470, FULL, 520), block("viz_graph", 0, 990, FULL, 500)], 1510),
        "layout_evidence": layout([block("viz_ledger", 0, 0, FULL, 470), block("viz_external", 0, 470, FULL, 480), block("viz_false_lead", 0, 950, FULL, 520)], 1490),
        "layout_controls": layout([block("viz_controls", 0, 0, FULL, 620), block("viz_compare", 0, 620, FULL, 500)], 1140),
        "layout_data": layout([block("viz_data", 0, 0, HALF, 650), block("viz_identity_memory", HALF, 0, HALF, 650)], 670),
        "layout_respond": layout([block("viz_respond", 0, 0, HALF, 700), block("viz_retest", HALF, 0, HALF, 700), block("viz_detection_help", 0, 700, FULL, 500), block("viz_detection", 0, 1200, FULL, 420), block("viz_hunt_help", 0, 1620, FULL, 450), block("viz_hunt", 0, 2070, FULL, 500)], 2590),
        "layout_model": layout([block("viz_updates", 0, 0, FULL, 620), block("viz_frameworks", 0, 620, FULL, 460)], 1100),
        "layout_report": layout([block("viz_reports", 0, 0, FULL, 620), block("viz_failures", 0, 620, FULL, 500)], 1140),
        "layout_answer": layout([block("viz_answer", 0, 0, FULL, 880), block("viz_commander", 0, 880, FULL, 760)], 1660),
    }
    definition = {
        "title": "Acme Bank Incident AGENT-2026-009",
        "description": "LAB-MULTI-STAGE-INCIDENT-001 bounded REPLAY integration workbench.",
        "defaults": studio_defaults(),
        "inputs": inputs,
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "options": layout_options(),
            "globalInputs": ["input_incident_run"],
            "layoutDefinitions": definitions,
            "tabs": {"options": {"barPosition": "top"}, "items": [{"layoutId": layout_id, "label": label} for layout_id, label in tabs]},
        },
        "applicationProperties": {"collapseNavigation": False, "downsampleVisualizations": False},
    }
    validate(definition)
    return definition


def validate(definition: dict) -> None:
    expected = ["INCIDENT", "INVESTIGATE", "TIMELINE", "EVIDENCE", "CONTROLS", "DATA IMPACT", "RESPOND", "THREAT MODEL", "REPORT", "PATH B"]
    assert [row["label"] for row in definition["layout"]["tabs"]["items"]] == expected
    early_ids = tuple(f"layout_{name}" for name in ("incident", "investigate", "timeline", "evidence", "controls", "data", "respond", "model", "report"))
    early = "\n".join(definition["visualizations"][row["item"]]["options"]["markdown"] for lid in early_ids for row in definition["layout"]["layoutDefinitions"][lid]["structure"] if definition["visualizations"][row["item"]]["type"] == "splunk.markdown")
    for leaked in ("On ATTACK, CTRL-MCP-001 recorded", "handler count was 1", "vulnerable authorization allowed fixture execution"):
        if leaked in early:
            raise ValueError(f"Path B answer leaked: {leaked}")
    payload = json.dumps(definition)
    for forbidden in ("index=*", "universal attack graph", "compliance score", '"semantic": "CAUSED"'):
        if forbidden in payload:
            raise ValueError(f"forbidden implication: {forbidden}")


def main() -> None:
    definition = build()
    write_definition(OUT_JSON, definition)
    write_studio_xml(OUT_XML, definition, label="Acme Bank Incident AGENT-2026-009", description="L9 bounded multi-stage REPLAY investigation.")
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
