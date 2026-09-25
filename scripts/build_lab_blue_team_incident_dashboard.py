#!/usr/bin/env python3
"""Build the REPLAY blue-team investigation workbench.

The dashboard reuses validated Capstone evidence. It does not launch attacks,
authorize tools, create a detector, or modify runtime security semantics.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "learning" / "level_1" / "LAB-BLUE-TEAM-INCIDENT-001"
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
    / "ws_lab_blue_team_incident.xml"
)
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"

ATTACK_RECALL = "2437f64a-fff4-424f-8a83-0f04285662e4"
RETEST_RECALL = "8d2c016f-cadc-4463-939a-23a183221b3d"
BENIGN_RUN = "db514fd8-dbf4-49f3-a2cb-6bd2bfe92987"

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
WHITE = "#FFFFFF"
FULL = 1440
HALF = 720


def load_spl(name: str) -> str:
    return (SEARCHES / name).read_text(encoding="utf-8").strip()


def bind_run(spl: str, run_id: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError("query does not contain __RUN_ID__")
    return spl.replace("__RUN_ID__", f'"{run_id}"')


def bind_compare(spl: str) -> str:
    return spl.replace("__ATTACK_RUN_ID__", f'"{ATTACK_RECALL}"').replace(
        "__RETEST_RUN_ID__", f'"{RETEST_RECALL}"'
    )


def markdown(body: str) -> dict:
    text = textwrap.dedent(body).strip() + "\n"
    if "| --- |" in text:
        raise ValueError("use accessible lists instead of markdown pipe tables")
    return {
        "type": "splunk.markdown",
        "options": {
            "markdown": text,
            "fontColor": TEXT,
            "backgroundColor": WHITE,
            "fontSize": "large",
        },
    }


def table(ds: str, title: str, description: str, no_data: str) -> dict:
    return {
        "type": "splunk.table",
        "title": title,
        "description": description,
        "dataSources": {"primary": ds},
        "showProgressBar": True,
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


def block(item: str, x: int, y: int, w: int, h: int) -> dict:
    return {"item": item, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}


def layout(structure: list[dict], height: int) -> dict:
    return {
        "type": "grid",
        "options": {
            "backgroundColor": BG,
            "display": "auto-scale",
            "gutterSize": 8,
            "width": FULL,
            "height": height,
        },
        "structure": structure,
    }


def build() -> dict:
    candidates = load_spl("Q-INCIDENT-CANDIDATES.spl")
    timeline = load_spl("Q-INCIDENT-TIMELINE.spl").replace(
        "__RUN_ID__", '"$incident_run_id$"'
    )
    compare = bind_compare(load_spl("Q-INCIDENT-COMPARE.spl"))
    benign = bind_run(load_spl("Q-INCIDENT-TIMELINE.spl"), BENIGN_RUN)

    data_sources = {
        "ds_candidates": {
            "type": "ds.search",
            "name": "Q-INCIDENT-CANDIDATES",
            "options": {"query": candidates},
        },
        "ds_timeline": {
            "type": "ds.search",
            "name": "Q-INCIDENT-TIMELINE",
            "options": {"query": timeline},
        },
        "ds_compare": {
            "type": "ds.search",
            "name": "Q-INCIDENT-COMPARE",
            "options": {"query": compare},
        },
        "ds_benign": {
            "type": "ds.search",
            "name": "Expected BASELINE tool timeline",
            "options": {"query": benign},
        },
    }

    visualizations = {
        "viz_mission": markdown(
            f"""
            # AcmeBank Incident AI-2026-001

            SOC received a report:

            > An AI-assisted banking workflow may have attempted or performed an action outside its intended authority.

            Incident window: **2026-09-20 19:37:40Z–19:38:00Z**

            **REPLAY workshop.** This is historical validated evidence, not a launch you just minted.

            This is an unfamiliar-incident assignment. Do not infer the attack family, decision, execution state, root cause, or solution from the title.

            **Write an initial hypothesis before opening INVESTIGATE.**

            [Open Splunk Search]({SEARCH_URL})

            REPLAY evidence · runtime schema **1.9.0** · ExternalEvidence **1.0.0**
            """
        ),
        "viz_method": markdown(
            """
            # Investigation method

            OBSERVATION → INITIAL HYPOTHESIS → EVIDENCE REQUIRED → SEARCH → TIMELINE → CORRELATION → CONTROL ANALYSIS → SUPPORT / REFUTE → REVISED HYPOTHESIS → CONCLUSION → EVIDENCE GAPS → RECOMMENDATION

            Repeatedly ask WHO, WHAT, WHEN, WHERE, WHY, AUTHORITY, EXECUTION, OUTCOME, EVIDENCE, and UNKNOWN.

            - Observation is not authorization.
            - Authorization is not execution.
            - Execution started is not completion.
            - Correlation is not causation.
            - No evidence is not safe.
            - Splunk is downstream evidence, not the PDP.
            """
        ),
        "viz_levels": markdown(
            """
            # Choose your investigation level

            **LEVEL 1 — GUIDED ANALYST**

            Use the incident window and candidate-search table. Then pivot each candidate run ID into the timeline. Determine what occurred; no conclusion is supplied.

            **LEVEL 2 — INVESTIGATOR**

            Use the description and approximate window. Construct the search. Do not initially use the full SPL, complete event IDs, root cause, or final decision.

            **LEVEL 3 — THREAT HUNTER**

            Hypothesis: an agent may have requested a privileged tool outside its intended task. Define evidence needed, search strategy, candidate runs, pivots, supporting and contradicting evidence, conclusion, and limitations.

            All levels use the same telemetry. No duplicate dataset and no new attack.
            """
        ),
        "viz_hints": markdown(
            """
            # Progressive hints

            Stop after the first hint that gets you moving.

            **HINT 1 — Direction**

            Start with tool-control decisions in the incident window. A request is not execution.

            **HINT 2 — Evidence source**

            Pivot from each candidate run ID to runtime `event.name` and `agentsec.sequence`.

            **HINT 3 — Field strategy**

            Inspect memory ID, source run ID, content hash, requested scope, allowed scope, and later `mcp.*` events. Equality and correlation do not establish direct causality.

            **HINT 4 — Example SPL**

            Use `Q-INCIDENT-CANDIDATES`, bind `Q-INCIDENT-TIMELINE` to each candidate, and compare only after recording a hypothesis.
            """
        ),
        "viz_ledger": markdown(
            """
            # Evidence ledger

            For every conclusion record:

            - Claim
            - FACT / INFERENCE / HYPOTHESIS / UNKNOWN
            - Evidence source and identifier
            - Confidence HIGH / MEDIUM / LOW, with reason
            - Alternative explanation
            - Missing evidence

            Avoid false numerical precision. A field is evidence for a bounded claim, not the entire incident.
            """
        ),
        "viz_candidates": table(
            "ds_candidates",
            "Candidate discovery",
            "Bounded control-decision search. It reveals candidates and authority mismatch, not execution or root cause.",
            "NO EVIDENCE FOUND in the bounded window. This is not SAFE. Check Splunk availability, index, sourcetype, timestamp extraction, and evidence-pack availability.",
        ),
        "viz_timeline": table(
            "ds_timeline",
            "Selected candidate timeline",
            "Sequence-ordered runtime evidence. Read request, classifier, PDP, invocation, completion/failure, and outcome as separate stages.",
            "NO EVIDENCE FOUND for the selected candidate. This is not DENY or prevention; the copy may be absent or incomplete.",
        ),
        "viz_workbench": markdown(
            """
            # Workbench questions

            1. What was requested?
            2. What authority was coded?
            3. Which control decided?
            4. Was the handler requested, authorized, invoked, and completed?
            5. What changed between candidates?
            6. What evidence contradicts your first hypothesis?
            7. What remains NOT MODELED, NOT OBSERVED, or NOT PROVEN?

            Build chronology with `agentsec.sequence`; do not blindly use `transaction`.
            """
        ),
        "viz_external": markdown(
            """
            # Adjacent external evidence

            Cisco scanner findings and garak evaluations may suggest hypotheses, but remain separate evidence planes.

            - Runtime: `otel:agentic:json`
            - Static finding: `agentsec:scanner:finding`
            - Adversarial evaluation: `agentsec:external:evaluation`

            The Cisco hash does not match this Capstone content hash. Garak carries no AgentSec run ID. No causal join is defensible here.

            External evidence causing or blocking this incident: **NOT OBSERVED**.

            **Controlled failure states**

            - Splunk unavailable or HEC unavailable: investigation evidence is unavailable or may be incomplete; do not conclude SAFE.
            - Missing REPLAY packet: record NO EVIDENCE FOUND and verify the pack/index path.
            - Malformed Cisco or unavailable garak evidence: mark that external plane unavailable; do not change the runtime conclusion.
            - No matching correlation: record NO JUSTIFIED JOIN; do not manufacture causality.
            """
        ),
        "viz_answer": markdown(
            """
            # Path B — review key

            Open only after you record an initial and revised hypothesis. This is an answer key, not policy.

            The two recall runs carry the same malicious-memory fingerprint and request the same privileged tool/scope. Memory classification remains OBSERVE. The vulnerable specimen records CTRL-MCP-001 ALLOW, then `mcp.started` and `mcp.completed`. The defended specimen records CTRL-MCP-001 DENY `tool_not_granted` and has no indexed follow-on execution event.

            The defensible result is:

            **SAME ADVERSARIAL INFLUENCE. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

            Root cause of the ATTACK authorization in this controlled specimen: the explicitly labeled vulnerable fail-open experiment overlay at CTRL-MCP-001. Retrieved content and memory did not mint authority. Splunk did not prevent RETEST.

            Direct retrieve-output → write causality is NOT MODELED. Authentication is NOT MODELED. Goal/Identity failure is NOT OBSERVED. Universal resistance is NOT PROVEN.
            """
        ),
        "viz_compare": table(
            "ds_compare",
            "ATTACK / RETEST comparison",
            "Live-validated REPLAY query. Shared memory hash is context; decisions and mcp.* establish different bounded facts.",
            "NO EVIDENCE FOUND. Do not infer safety or control effectiveness from an empty comparison.",
        ),
        "viz_false_positive": markdown(
            """
            # False-positive exercise

            A broad rule such as “any tool execution is malicious” also matches expected `lookup_policy` activity.

            Compare the real BASELINE specimen below:

            - requested `policy:read`
            - coded authority includes `policy:read`
            - CTRL-MCP-001 reason is `tool_granted`

            **MATCH != MALICIOUS.** Context, intended task, authority, control reason, and outcome change interpretation.
            """
        ),
        "viz_benign": table(
            "ds_benign",
            "Expected BASELINE comparison",
            "Real runtime REPLAY evidence for an expected governed tool path; not a fabricated benign event.",
            "NO EVIDENCE FOUND for the baseline specimen. Missing evidence does not make the candidate malicious or safe.",
        ),
        "viz_report": markdown(
            """
            # Finish the investigation

            Submit:

            **Executive Summary · What Happened · Timeline · Evidence · Authorization Analysis · Execution Analysis · Root Cause or LIKELY CONTRIBUTING FACTOR · Evidence Gaps · Control Recommendations · Residual Risk · Confidence / Limitations**

            Explain it twice:

            - Technical: evidence IDs, SPL, controls, execution states, uncertainty.
            - Executive: what happened, impact, unauthorized execution status, control behavior, change, and uncertainty.

            Detection bridge: known incident → observables → candidate SPL → ATTACK → RETEST → BASELINE → false-positive analysis → detection candidate. This phase creates no saved search.

            Threat-model bridge: asset, actor, entry point, trust boundary, authority, control placement, observability, missing telemetry, residual risk.
            """
        ),
    }

    definition = {
        "title": "AcmeBank Incident AI-2026-001",
        "description": "LAB-BLUE-TEAM-INCIDENT-001 REPLAY investigation. Splunk is downstream evidence, not the PDP.",
        "inputs": {
            "input_incident_run": {
                "type": "input.dropdown",
                "title": "Investigate selected candidate run",
                "options": {
                    "token": "incident_run_id",
                    "defaultValue": ATTACK_RECALL,
                    "items": [
                        {"label": "Candidate 01", "value": ATTACK_RECALL},
                        {"label": "Candidate 02", "value": RETEST_RECALL},
                    ],
                },
            }
        },
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "options": {
                "submitButton": False,
                "submitOnDashboardLoad": True,
                "showTitleAndDescription": True,
            },
            "globalInputs": ["input_incident_run"],
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_incident", "label": "INCIDENT"},
                    {"layoutId": "layout_investigate", "label": "INVESTIGATE"},
                    {"layoutId": "layout_evidence", "label": "EVIDENCE · WORKBENCH"},
                    {"layoutId": "layout_answers", "label": "PATH B · ANSWERS"},
                ],
            },
            "layoutDefinitions": {
                "layout_incident": layout(
                    [
                        block("viz_mission", 0, 0, FULL, 520),
                        block("viz_method", 0, 520, FULL, 500),
                    ],
                    1040,
                ),
                "layout_investigate": layout(
                    [
                        block("viz_levels", 0, 0, FULL, 620),
                        block("viz_hints", 0, 620, FULL, 820),
                        block("viz_ledger", 0, 1440, FULL, 460),
                    ],
                    1920,
                ),
                "layout_evidence": layout(
                    [
                        block("viz_workbench", 0, 0, FULL, 430),
                        block("viz_candidates", 0, 430, FULL, 300),
                        block("viz_timeline", 0, 730, FULL, 430),
                        block("viz_external", 0, 1160, FULL, 500),
                    ],
                    1680,
                ),
                "layout_answers": layout(
                    [
                        block("viz_answer", 0, 0, FULL, 760),
                        block("viz_compare", 0, 760, FULL, 360),
                        block("viz_false_positive", 0, 1120, HALF, 520),
                        block("viz_benign", HALF, 1120, HALF, 520),
                        block("viz_report", 0, 1640, FULL, 700),
                    ],
                    2360,
                ),
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
    labels = [row["label"] for row in definition["layout"]["tabs"]["items"]]
    expected = ["INCIDENT", "INVESTIGATE", "EVIDENCE · WORKBENCH", "PATH B · ANSWERS"]
    if labels != expected:
        raise ValueError(f"unexpected tabs: {labels}")
    used = {
        viz["dataSources"]["primary"]
        for viz in definition["visualizations"].values()
        if viz.get("dataSources")
    }
    if used != set(definition["dataSources"]):
        raise ValueError(f"data-source mismatch: {set(definition['dataSources']) ^ used}")
    incident_items = {
        row["item"]
        for row in definition["layout"]["layoutDefinitions"]["layout_incident"]["structure"]
    }
    incident_text = "\n".join(
        definition["visualizations"][item]["options"]["markdown"] for item in incident_items
    )
    for leaked in ("vulnerable_profile_fail_open", "tool_not_granted", "handler count"):
        if leaked in incident_text:
            raise ValueError(f"answer leaked on INCIDENT tab: {leaked}")
    queries = "\n".join(ds["options"]["query"] for ds in definition["dataSources"].values())
    if "index=*" in queries or "transaction" in queries:
        raise ValueError("unbounded index or transaction is not allowed")
    if "DET-" in queries:
        raise ValueError("this phase creates no detector")


def main() -> None:
    definition = build()
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(definition, indent=2) + "\n", encoding="utf-8")
    payload = json.dumps(definition, indent=2)
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<dashboard version="2" theme="light">\n'
        "  <label>AcmeBank Incident AI-2026-001</label>\n"
        "  <description>LAB-BLUE-TEAM-INCIDENT-001 REPLAY investigation. Splunk is downstream evidence, not the PDP.</description>\n"
        "  <definition><![CDATA[\n"
        f"{payload}\n"
        "  ]]></definition>\n"
        "</dashboard>\n"
    )
    OUT_XML.parent.mkdir(parents=True, exist_ok=True)
    OUT_XML.write_text(xml, encoding="utf-8")
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
