#!/usr/bin/env python3
"""Build the Splunk Defender Bridge REPLAY workbench.

The bridge teaches investigation process between L5 and L6.
It does not launch an attack, authorize a tool, or enable a detector.
"""

from __future__ import annotations

import json
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

LAB = ROOT / "learning" / "level_1" / "LAB-SPLUNK-DEFENDER-BRIDGE"
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
    / "ws_lab_splunk_defender_bridge.xml"
)
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

NO_EVIDENCE = (
    "NO EVIDENCE FOUND for this question and time range. "
    "Empty is not a safety verdict and not proof the activity did not occur."
)
INSUFFICIENT = (
    "INSUFFICIENT EVIDENCE. A stage that is absent stays absent. Do not fill it in."
)
NO_CORRELATION = (
    "CORRELATION NOT ESTABLISHED. This result does not identify a runtime run "
    "or an authorization decision."
)


def load_spl(name: str) -> str:
    text = (SEARCHES / name).read_text(encoding="utf-8").strip()
    if UUID.search(text):
        raise ValueError(f"{name} must not embed a run.id")
    if "index=*" in text or text.startswith("index=*"):
        raise ValueError(f"{name} is unbounded")
    return text


def build() -> dict:
    visualizations: dict[str, dict] = {}
    data_sources: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str | None = None) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    def add_table(viz_id: str, ds: str, title: str, description: str, no_data: str) -> str:
        key, viz = table(viz_id, ds, title, description, no_data=no_data)
        visualizations[key] = viz
        return key

    def add_search(ds_id: str, name: str, filename: str) -> str:
        key, ds = search_ds(ds_id, name, load_spl(filename))
        data_sources[key] = ds
        return key

    add_search("ds_discover", "Q-BRIDGE-DISCOVER", "Q-BRIDGE-DISCOVER.spl")
    add_search("ds_fields", "Q-BRIDGE-FIELDS", "Q-BRIDGE-FIELDS.spl")
    add_search("ds_narrow", "Q-BRIDGE-NARROW", "Q-BRIDGE-NARROW.spl")
    add_search("ds_sequence", "Q-BRIDGE-SEQUENCE", "Q-BRIDGE-SEQUENCE.spl")
    add_search("ds_compare", "Q-BRIDGE-COMPARE", "Q-BRIDGE-COMPARE.spl")
    add_search("ds_compare_exec", "Q-BRIDGE-COMPARE-EXECUTION", "Q-BRIDGE-COMPARE-EXECUTION.spl")
    add_search("ds_dup", "Q-BRIDGE-DUPLICATES", "Q-BRIDGE-DUPLICATES.spl")
    add_search("ds_dup_mode", "Q-BRIDGE-DUPLICATES-BY-MODE", "Q-BRIDGE-DUPLICATES-BY-MODE.spl")
    add_search("ds_external", "Q-BRIDGE-EXTERNAL", "Q-BRIDGE-EXTERNAL.spl")
    add_search("ds_stats", "Q-BRIDGE-STATS", "Q-BRIDGE-STATS.spl")

    add_md(
        "viz_mission",
        f"""
# Splunk Defender Bridge

You are between the guided L5 investigation and independent L6 work.

**Security question.** A banking agent may have asked a tool to do something outside the authority it was given. What can indexed evidence show about that request, and what can it not show?

**Write a hypothesis before you search.** Name the asset, the trust boundary, and the claim you hope to support or drop. Do not start from a run identifier. A run identifier is something you may discover later.

**REPLAY workshop.** This page does not launch an attack. It uses evidence already in `index=agentsec_telemetry`. It is not an eighth LIVE lab. CTRL-MCP-001 remains the tool policy decision point. Splunk remains downstream evidence. Splunk is not policy.

**Same evidence for every learner.**

- **Beginner.** Use DISCOVER in order. Read each hint before you edit SPL.
- **Practitioner.** Use the security question and the investigation objectives. Open a hint only when you are stuck.
- **Advanced.** Stay in [Search]({SEARCH_URL}) until CHALLENGE. Hints are optional.

Opening this mission does not tell you the ATTACK, RETEST, or BASELINE result. You produce that comparison after you have rows.
""",
        title="MISSION",
    )
    add_md(
        "viz_mission_process",
        """
# Process you are practicing

security question → hypothesis → evidence source → time scope → fields → candidate activity → candidate run → correlation → sequence → authorization versus execution → ATTACK / RETEST / BASELINE → alternative explanation → missing evidence → bounded conclusion

Claim strength stays at or below evidence strength.

Two vocabularies stay separate. How evidence was obtained: MEASURED, OBSERVED, DOCUMENTED, REPLAYED, SIMULATED. What you may claim: PROVEN, SUPPORTED, OBSERVED, INFERRED, NOT OBSERVED, NOT MODELED, NOT PROVEN, REFUTED.

This workshop is REPLAY / static investigation unless you later measure a fresh launch yourself. A row on this page is not a new experiment.
""",
    )

    add_md(
        "viz_discover",
        f"""
# Exercise 1 — Discovery

**REPLAY workshop.** Path A is [Search]({SEARCH_URL}). Path B is the last tab. Path B is an answer key, not policy.

Start here. Do not paste a run identifier.

```
index=agentsec_telemetry sourcetype=otel:agentic:json
```

Set a time range before you trust a row count. These teaching searches use `earliest=0` because this lab volume holds historical specimens. If you narrow the picker and the table says NO EVIDENCE FOUND, that window has no matching rows. That is not a safety verdict.

**Hint 1.** You are looking for tool-authorization activity, not a named incident.

**Hint 2.** Stay on `index=agentsec_telemetry` and `sourcetype=otel:agentic:json`. Start with control-decision events.

**Hint 3.** Useful fields, when the field summary shows them, include `event.name`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `gen_ai.tool.name`, `agentsec.testbed.mode`, and `agentsec.run.id`. Do not invent a field the summary does not list.

**Exercise 2 — field discovery.** From the field summary, write down which fields you need to answer: was a tool request decided, and in which testbed mode?
""",
        title="DISCOVER",
    )
    add_table(
        "viz_discover_table",
        "ds_discover",
        "Broad control-decision sample",
        "Inspection sample. Not a verdict and not a supplied run identifier.",
        NO_EVIDENCE,
    )
    add_table(
        "viz_fields_table",
        "ds_fields",
        "Field summary for control decisions",
        "Use this to choose fields. A field that is absent is not a hidden grant.",
        NO_EVIDENCE,
    )
    add_md(
        "viz_narrow_prompt",
        """
# Exercise 6 — write a stats search

In [Search]({SEARCH_URL}), write the command yourself. Path A does not contain the finished pipeline. Path B does, after you try.

**Goal.** For CTRL-MCP-001 control decisions, report indexed events, distinct raw events, and distinct run identifiers in each testbed mode and each decision. The mode column must not multiply an event just because the mode field repeats the same value.

**Fields.** `_raw`, `agentsec.run.id`, `agentsec.testbed.mode`, `agentsec.control.decision`, `event.name`, `agentsec.control.id`.

**Hint.** Check `mvcount` on `agentsec.testbed.mode` before you group. If one event holds the same mode more than once, deduplicate that value before `stats` uses it in `by`.
""",
    )

    add_md(
        "viz_investigate",
        """
# Exercise 3 — candidate run

**Hint 4.** Use `agentsec.control.id` CTRL-MCP-001 and decision DENY only to find candidate runs. The run identifier in that result is discovered evidence.

If several runs return, pick one and say why. If none return, write NO EVIDENCE FOUND. Do not turn that into a safety verdict.

**Exercise 4 — timeline.** Pivot on the run id you found. Do not add `agentsec.control.id` to that pivot. List every event name that search returns, in time order. The sequence table samples denied-authorization runs the same way: the control id is only inside the search that chooses run ids.

**Exercise 5 — authorization versus execution.** Keep the two questions separate.

Authorization evidence is the control-decision event: `agentsec.control.id`, decision, reason, and tool.

Execution and outcome evidence is whatever else shares that `agentsec.run.id`: `agentsec.mcp.started`, `agentsec.mcp.completed`, `agentsec.mcp.failed`, hop outcome, run completion. Those events often have no `agentsec.control.id`. An empty control id on them is a field fact, not a missing run.

- decision: only `agentsec.control.decision` on the control event
- invoked: `agentsec.mcp.started` is present for that run
- completed: `agentsec.mcp.completed` is present for that run
- outcome: only an outcome value that is on an event for that run

A missing stage stays **NOT OBSERVED**. ALLOW is not execution. DENY is not universal prevention. ERROR is not ALLOW and not DENY. An event present is not compromise. An event absent is not proof of safety.
""",
        title="INVESTIGATE",
    )
    add_table(
        "viz_narrow_table",
        "ds_narrow",
        "Denied CTRL-MCP-001 decisions by run",
        "Candidate runs. Indexed row count is not an execution count.",
        NO_EVIDENCE,
    )
    add_table(
        "viz_sequence_table",
        "ds_sequence",
        "Events for denied-authorization runs, in time order",
        "Control id chose the runs. It is not required on later events. Empty cells stay empty.",
        INSUFFICIENT,
    )
    add_md(
        "viz_compare_prompt",
        """
# Exercise 7 — controlled comparison

Compare ATTACK, RETEST, and BASELINE as controlled labels in `agentsec.testbed.mode`. They are not universal compromise, universal security, or a permanent baseline of safety.

Read the authorization table first: what CTRL-MCP-001 decided. Then read the execution and outcome table: which follow-on events exist, and which outcomes they carry. Do not collapse those into one yes or no. ERROR stays ERROR. Counts describe this index, not every future run. Do not copy a verdict from this heading.
""",
    )
    add_table(
        "viz_compare_table",
        "ds_compare",
        "Authorization comparison — CTRL-MCP-001 decisions",
        "Decisions only. A decision row is not an execution row.",
        NO_EVIDENCE,
    )
    add_table(
        "viz_compare_exec_table",
        "ds_compare_exec",
        "Execution and outcome comparison",
        "These events are not filtered by control id. An empty outcome stays empty.",
        INSUFFICIENT,
    )
    add_table(
        "viz_dup_table",
        "ds_dup",
        "No-split count, distinct raw, distinct runs, mode values",
        "No by clause. Compare indexed rows with distinct raw before you explain a gap. mode_value_count is values inside the field, not extra runs.",
        NO_EVIDENCE,
    )
    add_table(
        "viz_dup_mode_table",
        "ds_dup_mode",
        "Mode groups after one mode value per event",
        "Mode was deduplicated before stats by. This is not an execution count.",
        NO_EVIDENCE,
    )

    add_md(
        "viz_challenge",
        f"""
# Exercise 8 — evidence gap

Leave at least one claim **NOT PROVEN**. Example: this index does not prove what the agent would do on a later day.

Leave at least one claim **NOT MODELED**. Example: customer impact, production identity, and a change ticket are not modeled by these events.

# Exercise 9 — false lead

Cisco mcp-scanner findings and garak evaluations are adjacent evidence. A scanner severity, including HIGH, is not a CTRL-MCP-001 DENY. A garak pass or fail is not a runtime authorization decision. Neither tool authorizes the agent.

Ask of the external table:

- What does this evidence tell us?
- What does it not tell us?
- Can it establish runtime execution?
- Can it establish authorization?
- Can it establish causality?
- Can it be correlated by `agentsec.run.id`?

Scanner correlation, where the event carries it, is hash-based (`correlation.method`, description hash to `agentsec.content.hash`). Do not invent a runtime run identifier the event does not contain. If distinct runtime run identifiers are empty, write **CORRELATION NOT ESTABLISHED**.

Zero external findings are not trust. HEC accepted is not the same as searchable evidence.

# Exercise 10 — report

Write five separate lines from your rows, not from this heading:

- authorization evidence: the CTRL-MCP-001 decision, reason, and tool
- execution evidence: started, completed, or failed events for that run, or **NOT OBSERVED**
- outcome evidence: hop or run outcome values that are present, or **NOT OBSERVED**
- external evidence: what scanner or garak shows, and **CORRELATION NOT ESTABLISHED** when no runtime run id is present
- missing evidence: at least one **NOT PROVEN** claim

Use this shape and fill the blanks from the rows:

Splunk evidence shows CTRL-MCP-001 made a decision for a request. Events correlated by the run id you found show the execution or outcome that is actually present. The available evidence does not establish an unsupported claim.

# Failure language

Use NO EVIDENCE FOUND, INSUFFICIENT EVIDENCE, or CORRELATION NOT ESTABLISHED. Do not claim the lab is protected, and do not claim there was no hostile activity, unless the rows actually establish that bounded statement. They usually do not.

# Counts are not causes

`count` is indexed rows in that aggregation. `dc(_raw)` is distinct raw events. `dc(agentsec.run.id)` is distinct run identifiers. `mvcount` is how many values one field holds. An execution count is a separate question, answered only when an execution event is present.

`stats by` a multivalue field can raise `count` even when `dc(_raw)` does not. Find out why the numbers differ before you name a cause. Compare a search with no `by` clause first. None of these numbers is an execution count by itself.

# Where this stops

An investigation query reconstructs a known question. A hunt query looks for behavior without a supplied run identifier. A candidate detection is unscheduled SPL. A validated detection has been tested against known cases. An enabled detector is scheduled. This bridge creates no detector and does not enable DET-MCP-001.

L6 remains the deeper incident hunt. This page only gets you from unknown activity to a candidate investigation.

Open [Search]({SEARCH_URL}) for Path A. Path B is a review key, not policy.
""",
        title="CHALLENGE",
    )
    add_table(
        "viz_external_table",
        "ds_external",
        "External evidence plane",
        "Scanner and garak rows. Not a runtime authorization decision.",
        NO_CORRELATION,
    )

    add_md(
        "viz_path_b",
        """
# Path B — review after you investigate

**REPLAY workshop.** This is Path B, an answer key, not policy. Splunk does not enforce. CTRL-MCP-001 remains the tool policy decision point.

**Discovery.** You should have started from the index and sourcetype, then control-decision events, with no run identifier in the opening search.

**Stats you were asked to write.** The control id stays on this authorization summary. Mode is reduced to one value before `by`, because a repeated value inside the field would multiply `count`.

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0
"event.name"=agentsec.control.decision "agentsec.control.id"=CTRL-MCP-001
| eval mode=mvindex(mvdedup('agentsec.testbed.mode'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| stats count as indexed_rows dc(_raw) as distinct_raw dc(agentsec.run.id) as distinct_runs by mode decision
| sort mode decision
```

**How to read the two comparison tables.** The authorization table is CTRL-MCP-001 decisions only. The execution table is started, completed, failed, hop, and run-completion events, and it does not require `agentsec.control.id`. A DENY with no `agentsec.mcp.started` for that run leaves invocation **NOT OBSERVED**. An ALLOW with a started event supports indexed execution for that run and does not prove the next request is allowed. ERROR stays ERROR. BASELINE is a controlled comparison, not a proof of safety. Do not treat a row count from one volume as a permanent product result.

**Sequence.** `agentsec.control.id` chooses candidate runs. The pivot is `agentsec.run.id`. Later events may have an empty control id, an empty decision, and a populated outcome. Empty is **NOT OBSERVED** for that field, not a second decision.

**Counts.** Read the no-split table first. If indexed rows equal distinct raw, this search is not showing extra indexed copies. `mode_value_count` tells you how many values the mode field holds. Grouping by that field before deduplicating it can make `count` larger than `dc(_raw)` without any additional event. Do not invent a cause for that gap. None of these figures is an execution count.

**False lead.** Reject "scanner HIGH means the tool was denied" and "garak PASS means the runtime allowed the call." Those claims are **NOT PROVEN**. No runtime run id on those events is **CORRELATION NOT ESTABLISHED**. Production customer harm is **NOT MODELED**.

**Bounded conclusion shape.** Fill this from your rows. "Splunk evidence shows CTRL-MCP-001 made this decision for this request. Events correlated by this run id show this execution or outcome, or those stages are **NOT OBSERVED**. External evidence does not establish runtime authorization. The evidence does not establish the unsupported claim."

If your table is empty, your conclusion is NO EVIDENCE FOUND for this Splunk volume, not a control result.
""",
        title="PATH B",
    )
    add_table(
        "viz_stats_table",
        "ds_stats",
        "Completed stats check",
        "Compare this with the command you wrote. Row counts are indexed evidence, not execution counts.",
        NO_EVIDENCE,
    )

    definition = {
        "title": "Splunk Defender Bridge",
        "description": (
            "LAB-SPLUNK-DEFENDER-BRIDGE REPLAY investigation between L5 and L6. "
            "Splunk is downstream evidence, not the PDP."
        ),
        "inputs": {},
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "options": layout_options(),
            "globalInputs": [],
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_mission", "label": "MISSION"},
                    {"layoutId": "layout_discover", "label": "DISCOVER"},
                    {"layoutId": "layout_investigate", "label": "INVESTIGATE"},
                    {"layoutId": "layout_challenge", "label": "CHALLENGE"},
                    {"layoutId": "layout_path_b", "label": "PATH B · REVIEW"},
                ],
            },
            "layoutDefinitions": {
                "layout_mission": layout(
                    [
                        block("viz_mission", 0, 0, FULL, 520),
                        block("viz_mission_process", 0, 520, FULL, 280),
                    ],
                    820,
                ),
                "layout_discover": layout(
                    [
                        block("viz_discover", 0, 0, FULL, 520),
                        block("viz_discover_table", 0, 520, FULL, 320),
                        block("viz_fields_table", 0, 840, FULL, 320),
                        block("viz_narrow_prompt", 0, 1160, FULL, 360),
                    ],
                    1540,
                ),
                "layout_investigate": layout(
                    [
                        block("viz_investigate", 0, 0, FULL, 640),
                        block("viz_narrow_table", 0, 640, FULL, 300),
                        block("viz_sequence_table", 0, 940, FULL, 320),
                        block("viz_compare_prompt", 0, 1260, FULL, 240),
                        block("viz_compare_table", 0, 1500, FULL, 280),
                        block("viz_compare_exec_table", 0, 1780, FULL, 300),
                        block("viz_dup_table", 0, 2080, FULL, 220),
                        block("viz_dup_mode_table", 0, 2300, FULL, 240),
                    ],
                    2560,
                ),
                "layout_challenge": layout(
                    [
                        block("viz_challenge", 0, 0, FULL, 980),
                        block("viz_external_table", 0, 980, FULL, 320),
                    ],
                    1320,
                ),
                "layout_path_b": layout(
                    [
                        block("viz_path_b", 0, 0, FULL, 920),
                        block("viz_stats_table", 0, 920, FULL, 320),
                    ],
                    1260,
                ),
            },
        },
        "defaults": studio_defaults(),
    }
    validate(definition)
    return definition


def _tab_markdown(definition: dict, layout_id: str) -> str:
    items = definition["layout"]["layoutDefinitions"][layout_id]["structure"]
    parts = []
    for row in items:
        viz = definition["visualizations"][row["item"]]
        if viz.get("type") == "splunk.markdown":
            parts.append(viz["options"]["markdown"])
    return "\n".join(parts)


def validate(definition: dict) -> None:
    labels = [row["label"] for row in definition["layout"]["tabs"]["items"]]
    expected = ["MISSION", "DISCOVER", "INVESTIGATE", "CHALLENGE", "PATH B · REVIEW"]
    if labels != expected:
        raise ValueError(f"unexpected tabs: {labels}")
    if definition["inputs"] != {}:
        raise ValueError("bridge does not start from a specimen dropdown")
    mission = _tab_markdown(definition, "layout_mission")
    if UUID.search(mission):
        raise ValueError("mission supplies a run identifier")
    for banned in ("was denied", "did not execute", "NO ATTACK", "is secure", "SAFE"):
        if re.search(rf"\b{re.escape(banned)}\b", mission, flags=re.IGNORECASE):
            raise ValueError(f"mission states a verdict: {banned}")
    if "indexed_rows dc(_raw)" in mission:
        raise ValueError("mission includes the completed stats command")
    path_a = _tab_markdown(definition, "layout_discover") + _tab_markdown(
        definition, "layout_investigate"
    )
    if "mvindex(mvdedup('agentsec.testbed.mode'),0)" in path_a:
        raise ValueError("Path A includes the finished mode normalization")
    path_b = _tab_markdown(definition, "layout_path_b")
    if "restaged" in path_b.lower() or "restaged" in _tab_markdown(definition, "layout_challenge").lower():
        raise ValueError("workshop claims restaged copies")
    sequence = definition["dataSources"]["ds_sequence"]["options"]["query"]
    outer, _, inner = sequence.partition("[")
    if "CTRL-MCP-001" in outer:
        raise ValueError("sequence requires control id before the run pivot")
    if "agentsec.outcome" not in sequence:
        raise ValueError("sequence does not project outcome")
    if "agentsec.mcp.started" in definition["dataSources"]["ds_compare"]["options"]["query"]:
        raise ValueError("authorization comparison includes execution events")
    execution = definition["dataSources"]["ds_compare_exec"]["options"]["query"]
    if "CTRL-MCP-001" in execution or "agentsec.mcp.started" not in execution:
        raise ValueError("execution comparison is filtered like an authorization search")
    for required in ("NOT PROVEN", "NOT MODELED", "not policy", "CTRL-MCP-001", "Path B"):
        if required not in path_b:
            raise ValueError(f"path B missing {required}")
    queries = "\n".join(ds["options"]["query"] for ds in definition["dataSources"].values())
    if "index=*" in queries or "DET-" in queries:
        raise ValueError("unbounded index or detector search is not allowed")
    if UUID.search(queries):
        raise ValueError("a bridge search embeds a run identifier")


def main() -> None:
    definition = build()
    write_studio_xml(
        OUT_XML,
        definition,
        definition_path=OUT_JSON,
        label="Splunk Defender Bridge",
        description=(
            "LAB-SPLUNK-DEFENDER-BRIDGE REPLAY investigation between L5 and L6. "
            "Splunk is downstream evidence, not the PDP."
        ),
    )
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
