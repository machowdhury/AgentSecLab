#!/usr/bin/env python3
"""Build the L10 advanced capstone mastery workspace.

REPLAY investigation only. Does not install a detector or change authorization.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from agentsec_studio import (  # noqa: E402
    FULL, HALF, block, layout, layout_options, markdown, search_ds,
    studio_defaults, table, write_definition, write_studio_xml,
)

LAB = ROOT / "learning" / "level_1" / "LAB-ADVANCED-CAPSTONE-MASTERY-001"
SEARCHES = LAB / "searches"
OUT_JSON = LAB / "dashboard.definition.json"
OUT_XML = (
    ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
    / "ws_lab_advanced_capstone.xml"
)
NO_DATA = "NO EVIDENCE FOUND / INSUFFICIENT EVIDENCE / NOT PROVEN. This is not SAFE."


def _spl(name: str) -> str:
    return (SEARCHES / name).read_text(encoding="utf-8").strip()


def _path_b(packet: dict) -> str:
    runs = packet["canonical_runs"]
    lines = [
        "# Path B review key",
        "",
        "REPLAY reference. Not policy. Not a fresh execution. Indexed copies are not extra executions.",
        "",
        "## Hypothesis disposition",
    ]
    for row in packet["initial_hypotheses"]:
        lines.append(f"- {row['id']} disposition is {row['disposition']}. {row['why']}")
    lines.append("")
    lines.append("## Runs discovered from the window")
    for key in ("baseline", "attack", "retest"):
        run = runs[key]
        lines.append(
            f"- {run['mode']} {run['run_id']}: goal {run['goal_decision']} {run['goal_reason']}; "
            f"MCP {run['mcp_decision']} {run['mcp_reason']} {run['mcp_tool']}; "
            f"effective action {run['effective_action']}; "
            f"in-task handler {run['in_task_handler']}; wrong-goal handler count was {run['wrong_goal_handler']}; "
            f"distinct events {run['distinct_raw']}; indexed rows measured {run['indexed_rows_measured']}."
        )
    shared = packet["shared_fingerprints"]
    lines.extend([
        "",
        f"Shared task hash {shared['task_hash']}. Shared instruction hash {shared['instruction_hash']}.",
        shared["note"],
        "",
        "## False leads",
    ])
    for lead in packet["false_leads"]:
        lines.append(f"- {lead['id']} {lead['name']}: {lead['classification']}. {lead['why']}")
    gap = packet["evidence_gap"]
    lines.extend([
        "",
        f"## Evidence gap",
        f"{gap['question']} State: {gap['state']}. {gap['why']}",
        "",
        "## Causal rules",
    ])
    lines.extend(f"- {rule}" for rule in packet["causal_rules"])
    lines.extend(["", "## Controls"])
    for control in packet["controls"]:
        lines.append(f"- {control['id']}: {json.dumps(control, ensure_ascii=False)}")
    lines.extend(["", "## Containment"])
    lines.extend(f"- {item}" for item in packet["containment"])
    lines.extend(["", "## Remediation"])
    for item in packet["remediation"]:
        lines.append(
            f"- Problem: {item['problem']} Control: {item['control']} Placement: {item['placement']} "
            f"Expected effect: {item['expected_effect']} Evidence: {item['evidence_required']} "
            f"Residual risk: {item['residual_risk']}"
        )
    detection = packet["detection_candidate"]
    hunt = packet["hunt"]
    revised = packet["revised_threat_model"]
    lines.extend([
        "",
        "## Detection candidate",
        f"Installed: {detection['installed']}. {detection['hypothesis']}",
        f"Expected ATTACK {detection['expected_attack']}. Expected RETEST {detection['expected_retest']}. Expected BASELINE {detection['expected_baseline']}.",
        f"False positives: {detection['false_positives']} Blind spots: {detection['blind_spots']}",
        "",
        "## Hunt",
        hunt["hypothesis"],
        hunt["conclusion"],
        "",
        "## Revised threat model",
        f"Wrong assumption: {revised['wrong_assumption']}",
        f"Missed threat: {revised['missed_threat']}",
        f"Boundary: {revised['boundary']}. Authority: {revised['authority']}.",
        f"Missing telemetry: {revised['missing_telemetry']}.",
        f"Control change: {revised['control_change']}. Residual risk: {revised['residual_risk']}",
        "",
        "## Example outputs",
        f"SOC: {packet['reports']['soc']}",
        f"Engineering: {packet['reports']['engineering']}",
        f"Executive: {packet['reports']['executive']}",
        "",
        "Educational mappings only: OWASP excessive agency, MITRE ATLAS influence versus execution, CSA MAESTRO agent-goal layer, NIST AI RMF measure and manage, NIST Privacy Framework minimization. Not compliance.",
    ])
    return "\n".join(lines) + "\n"


def build() -> dict:
    packet = json.loads((LAB / "incident.json").read_text(encoding="utf-8"))
    visualizations: dict[str, dict] = {}
    data_sources: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str) -> None:
        key, value = markdown(viz_id, body, title)
        visualizations[key] = value

    def add_table(viz_id: str, ds: str, title: str, description: str) -> None:
        key, value = table(viz_id, ds, title, description, no_data=NO_DATA)
        visualizations[key] = value

    def add_ds(ds_id: str, name: str, query: str) -> None:
        key, value = search_ds(ds_id, name, query)
        data_sources[key] = value

    add_ds("ds_discover", "Q-L10-DISCOVER", _spl("Q-L10-DISCOVER.spl"))
    add_ds("ds_sequence", "Q-L10-SEQUENCE", _spl("Q-L10-SEQUENCE.spl"))
    add_ds("ds_external", "Q-L10-EXTERNAL", _spl("Q-L10-EXTERNAL.spl"))
    add_ds("ds_hunt", "Q-L10-HUNT", _spl("Q-L10-HUNT.spl"))
    add_ds("ds_compare", "Q-L10-COMPARE", _spl("Q-L10-COMPARE.spl"))
    add_ds("ds_detection", "Q-L10-DETECTION-CANDIDATE", _spl("Q-L10-DETECTION-CANDIDATE.spl"))

    add_md("viz_mission", """
# ACME BANK CAPSTONE MASTER-2026-001

**REPLAY workshop. Path A is your investigation. Path B is a review key, not policy.**

## Expert mode

Business context: AcmeBank uses an agent-assisted lending-policy workflow. The assistant can retrieve a bounded internal policy fixture and invoke one granted lookup tool. The business objective is a summary of lending policy options.

Architecture: task contract, untrusted instruction, goal check, tool authorization, tool handler, telemetry, Splunk, and two adjacent external evidence planes.

Incident window: 2026-09-18 22:47:40Z through 22:48:10Z.

Splunk access: index agentsec_telemetry. Runtime sourcetype otel:agentic:json. Adjacent sourcetypes agentsec:scanner:finding and agentsec:external:evaluation.

Deliverables: architecture, initial threat model, hypotheses, evidence ledger, timeline, data bound, control plan, containment, remediation, retest design, detection candidate, hunt, revised threat model, and SOC, engineering, and executive notes.

No starting run identifier is provided.
""", "MISSION")
    add_md("viz_concepts", """
# Concept help

Optional. These definitions do not identify the incident.

An authorization decision is a control result such as ALLOW, DENY, or OBSERVE, with a reason, recorded before the dangerous operation. A request is not that decision.

dc(_raw) counts distinct raw events. stats count counts indexed rows. Repeated indexing is not repeated execution.

A trust boundary is where data from one authority meets a component that can influence, authorize, execute, or only observe.

NOT PROVEN means the available evidence does not establish the claim. It does not mean the claim is false, and it does not mean SAFE.

CORRELATED is not CAUSED. PRECEDES is not CAUSED. The same hash is not the same execution. Events in one run did not each cause every other event.
""", "CONCEPT HELP")
    add_md("viz_architecture", """
# Architecture worksheet

Before you search, name:

- Components
- Data flows
- Trust boundaries
- Assets
- Authority boundaries: who can influence, who can authorize, who can execute, who only observes
- Observability points
- External evidence planes
- Known unknowns

Initial threat model, in this order: system, assets, actors, flows, boundaries, authority, attack surface, threats, controls, telemetry, assumptions, gaps.

You will revise this model after the evidence. Do not fill it from Path B.
""", "ARCHITECTURE")
    add_md("viz_hypotheses", """
# Investigation workflow

DISCOVER, then SCOPE, then IDENTIFY, then CORRELATE, then SEQUENCE, then VALIDATE, then CHALLENGE, then CONCLUDE.

Write at least three plausible hypotheses before you trust a table. Expect a mixture of real signal, benign activity, control success, a control gap, irrelevant evidence, missing evidence, and ambiguous evidence.

Use these states on every material claim: PROVEN, SUPPORTED, OBSERVED, INFERRED, REFUTED, NOT OBSERVED, NOT MODELED, NOT PROVEN.

The discovery search uses the incident window only. It does not start from a run identifier. Empty results are NO EVIDENCE FOUND or INSUFFICIENT EVIDENCE. Never write SAFE.
""", "INVESTIGATE")
    add_md("viz_ledger", """
# Evidence ledger

Keep this for the whole investigation.

Claim. Evidence. Plane. State. Alternative explanation. Missing evidence.

Planes you may need: runtime telemetry, authorization evidence, execution evidence, outcome evidence, memory or context evidence, privacy or data evidence, external security evidence, Splunk investigation artifacts.

Absence of a plane is not evidence of safety. Not every plane has to contain evidence.

Separate request, authorization decision, invocation, handler or execution, completion, and business or data outcome. One counter does not stand for the whole chain.
""", "EVIDENCE")
    add_md("viz_timeline_help", """
# Timeline

For each important row: time, component, event, correlation, evidence state.

Prove important relationships. Two events in the same second did not automatically cause each other. A shared hash does not make two executions the same. A shared run does not make every event a cause of every other event.
""", "TIMELINE")
    add_md("viz_data", """
# Data and privacy

Answer separately:

- What data was required for the business objective?
- What data was available to the tool?
- What data was sent?
- What data was returned?
- What data was logged?
- What data may have persisted?
- What is actually proven?

An authorized tool action can still be a data-handling problem. If you cannot see a customer channel or a changed business record, say NOT PROVEN. Do not invent a breach.
""", "DATA")
    add_md("viz_controls", """
# Controls

Classify each relevant control as preventive, detective, corrective, or recovery, and as observe or enforce.

Outcome vocabulary: SUCCEEDED, FAILED, NOT TRIGGERED, NOT APPLICABLE, NOT MODELED, UNKNOWN.

Place any recommendation at a real layer: input, context or retrieval, memory, goal or task, authorization, tool, downstream system, data, telemetry, or monitoring.

"Add AI security" is not a placement.
""", "CONTROLS")
    add_md("viz_detect", """
# Detection candidate and hunt

Write one candidate. Do not install it.

Include: hypothesis, observables, SPL, expected attack result, expected retest result, expected baseline result, false-positive considerations, known blind spots.

ATTACK versus RETEST is not enough. Compare BASELINE and say which signals separate inappropriate behavior from legitimate use of the same tool.

Hunt without a known incident identifier. Include: hunt hypothesis, time range, behavior, search, candidates, pivots, exclusions, conclusion.

If the hunt table is empty, write NO EVIDENCE FOUND. That is not SAFE.
""", "DETECT AND HUNT")
    add_md("viz_respond", """
# Respond

Containment must be proportional to proven or supported risk. Separate justified actions from speculative ones.

Each remediation item needs: problem, control, placement, expected effect, evidence required to validate, residual risk.

Design the retest before you read the comparison. Preserve the same relevant input, the same business objective, the same influence condition, the expected control change, and the expected legitimate functionality.

Then compare that design with the bounded comparison in this window.
""", "RESPOND")
    add_md("viz_report", """
# Reports, mastery, reflection

SOC note: scope, evidence, timeline, authorization, execution, outcome, affected data, false leads, unresolved questions, containment, candidate detection, hunt recommendations.

Engineering note: contributing conditions, control changes, placement, telemetry requirements, validation tests, retest criteria, residual risk.

Executive note: what happened, which business process, what impact is proven, what is not proven, whether existing controls worked, what we are doing now, what should change, what risk remains.

Do not write BREACH, COMPROMISED, or SAFE unless the evidence actually establishes that absolute claim. This packet does not.

Mastery states, with evidence of what you did: DEMONSTRATED, PARTIALLY DEMONSTRATED, NOT YET DEMONSTRATED, NOT ASSESSED.

Opening a tab is not mastery. A demonstrated claim needs work product: a search, a classification, a rejected false lead, a reconstructed chain, a bounded data statement, a placed control, a hunt, or a bounded executive explanation.

Reflection, not a score: which assumption changed, which evidence mattered, which evidence misled you, what you could not prove, which control you would prioritize, what you would instrument, and how you would start the next unfamiliar incident.
""", "REPORT")
    add_md("viz_path_b", _path_b(packet), "PATH B")

    add_table("viz_discover", "ds_discover", "Window discovery", "Distinct events versus indexed rows. No run identifier is supplied.")
    add_table("viz_sequence", "ds_sequence", "Window sequence", "Order is not causation.")
    add_table("viz_external", "ds_external", "Adjacent external evidence", "Presence is not correlation to a runtime run.")
    add_table("viz_compare", "ds_compare", "Mode comparison", "Same tool is not the same execution. Include the benign mode.")
    add_table("viz_hunt", "ds_hunt", "Behavior-first hunt", "Goal-integrity decisions. Does not start from an incident identifier.")
    add_table("viz_detection", "ds_detection", "Reference detection candidate", "Review key only. Not an installed detector.")

    tabs = [
        ("layout_mission", "MISSION"),
        ("layout_architecture", "ARCHITECTURE"),
        ("layout_investigate", "INVESTIGATE"),
        ("layout_evidence", "EVIDENCE"),
        ("layout_timeline", "TIMELINE"),
        ("layout_data", "DATA"),
        ("layout_controls", "CONTROLS"),
        ("layout_detect", "DETECT & HUNT"),
        ("layout_respond", "RESPOND"),
        ("layout_report", "REPORT"),
        ("layout_path_b", "PATH B"),
    ]
    definitions = {
        "layout_mission": layout([
            block("viz_mission", 0, 0, HALF, 720),
            block("viz_concepts", HALF, 0, HALF, 720),
        ], 740),
        "layout_architecture": layout([block("viz_architecture", 0, 0, FULL, 640)], 660),
        "layout_investigate": layout([
            block("viz_hypotheses", 0, 0, FULL, 520),
            block("viz_discover", 0, 520, FULL, 480),
        ], 1020),
        "layout_evidence": layout([
            block("viz_ledger", 0, 0, FULL, 560),
            block("viz_external", 0, 560, FULL, 420),
        ], 1000),
        "layout_timeline": layout([
            block("viz_timeline_help", 0, 0, FULL, 360),
            block("viz_sequence", 0, 360, FULL, 520),
        ], 900),
        "layout_data": layout([block("viz_data", 0, 0, FULL, 560)], 580),
        "layout_controls": layout([
            block("viz_controls", 0, 0, FULL, 480),
            block("viz_compare", 0, 480, FULL, 460),
        ], 960),
        "layout_detect": layout([
            block("viz_detect", 0, 0, FULL, 560),
            block("viz_hunt", 0, 560, FULL, 480),
        ], 1060),
        "layout_respond": layout([block("viz_respond", 0, 0, FULL, 560)], 580),
        "layout_report": layout([block("viz_report", 0, 0, FULL, 780)], 800),
        "layout_path_b": layout([
            block("viz_path_b", 0, 0, FULL, 980),
            block("viz_detection", 0, 980, FULL, 420),
        ], 1420),
    }
    definition = {
        "title": "Acme Bank Capstone MASTER-2026-001",
        "description": "LAB-ADVANCED-CAPSTONE-MASTERY-001 bounded REPLAY mastery workspace.",
        "defaults": studio_defaults(),
        "inputs": {},
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "options": layout_options(),
            "globalInputs": [],
            "layoutDefinitions": definitions,
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [{"layoutId": layout_id, "label": label} for layout_id, label in tabs],
            },
        },
        "applicationProperties": {"collapseNavigation": False, "downsampleVisualizations": False},
    }
    validate(definition, packet)
    return definition


def validate(definition: dict, packet: dict) -> None:
    labels = [row["label"] for row in definition["layout"]["tabs"]["items"]]
    assert labels[-1] == "PATH B"
    assert "MISSION" in labels
    early_ids = [row["layoutId"] for row in definition["layout"]["tabs"]["items"] if row["label"] != "PATH B"]
    early = "\n".join(
        definition["visualizations"][row["item"]]["options"]["markdown"]
        for lid in early_ids
        for row in definition["layout"]["layoutDefinitions"][lid]["structure"]
        if definition["visualizations"][row["item"]]["type"] == "splunk.markdown"
    )
    for run in packet["canonical_runs"].values():
        if run["run_id"] in early:
            raise ValueError("Path B run id leaked onto an earlier tab")
    for leaked in ("H1 disposition is SUPPORTED", "H2 disposition is REFUTED", "wrong-goal handler count was 1"):
        if leaked in early:
            raise ValueError(f"Path B answer leaked: {leaked}")
    payload = json.dumps(definition)
    if "index=*" in payload or '"semantic": "CAUSED"' in payload:
        raise ValueError("forbidden search or causal edge")
    if definition["inputs"]:
        raise ValueError("expert mission must not ship a run-id dropdown")


def main() -> None:
    definition = build()
    write_definition(OUT_JSON, definition)
    write_studio_xml(
        OUT_XML,
        definition,
        label="Acme Bank Capstone MASTER-2026-001",
        description="LAB-ADVANCED-CAPSTONE-MASTERY-001 REPLAY mastery workspace. Learning metadata is not policy.",
    )
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
