#!/usr/bin/env python3
"""Build the Detection Engineering REPLAY workshop.

The workshop teaches a learner to author and bound a candidate.
It does not enable DET-MCP-001, schedule a search, or launch an attack.
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

LAB = ROOT / "learning" / "level_1" / "LAB-DETECTION-ENGINEERING"
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
    / "ws_lab_detection_engineering.xml"
)
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

NO_ROWS = (
    "No rows for this predicate and time range. "
    "Empty is not a safety verdict and not proof the behavior did not occur."
)


def load_spl(name: str) -> str:
    text = (SEARCHES / name).read_text(encoding="utf-8").strip()
    if UUID.search(text):
        raise ValueError(f"{name} must not embed a run.id")
    if "earliest=0" not in text:
        raise ValueError(f"{name} needs an explicit earliest=0")
    if "index=*" in text:
        raise ValueError(f"{name} is unbounded")
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

    add_search("ds_events", "Q-DET-EVENTS", "Q-DET-EVENTS.spl")
    add_search("ds_broad", "Q-DET-BROAD", "Q-DET-BROAD.spl")
    add_search("ds_tuned", "Q-DET-TUNED", "Q-DET-TUNED.spl")

    add_md(
        "viz_mission",
        f"""
# Detection Engineering — Prove Your Coverage

You are a detection engineer. You are not handed a finished detector.

**Security question.** Can we detect a tool execution that occurs after CTRL-MCP-001 denied that same tool?

**Write the hypothesis before you search.** Name the behavior, the trust boundary, and what would disprove the claim. Do not start from a run identifier.

**REPLAY workshop.** This page sits after L6. It is not L11 and not a LIVE lab. It does not launch an attack. CTRL-MCP-001 remains the tool policy decision point. Splunk remains downstream. A row here does not ALLOW, DENY, or declare an incident.

**Same evidence for every learner.**

- **Beginner.** Read the hypothesis, the field list, and one hint. Use the partial search. Stop before you copy a finished correlation.
- **Practitioner.** Write the broad search, tune it, compare ATTACK, RETEST, and BASELINE, and write the coverage statement.
- **Expert.** Start from the behavior. Derive the fields. Challenge `agentsec.operation.outcome=prevented` as proof. Separate the simulated positive from the index.

Work in [Search]({SEARCH_URL}). Path B is an answer key, not policy. Opening this mission does not tell you the ATTACK, RETEST, or BASELINE result.

The principle you have to earn: detection coverage is a claim that must be proven. A logically valid detection can still miss the attack you thought it covered.
""",
        title="MISSION",
    )

    add_md(
        "viz_hypothesis",
        f"""
# Hypothesis

**Behavior that matters.** A tool starts after CTRL-MCP-001 has denied that same tool in the same run.

**Authorization evidence.** `event.name=agentsec.control.decision`, `agentsec.control.decision=DENY`, and `agentsec.control.id=CTRL-MCP-001`. Those fields are on the decision event.

**Execution evidence.** `event.name=agentsec.mcp.started` for a tool. That event sets `agentsec.operation.executed` true. It does not carry `agentsec.control.id` or `agentsec.control.decision`.

**Not proof.** `agentsec.operation.executed=false` and `agentsec.operation.outcome=prevented` describe the decision event. They do not prove a later start is absent. ALLOW is not execution. DENY is not a safety verdict.

**Field names that exist.** `event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.testbed.mode`.

**Names that are not emitted.** `agentsec.event.name` and `agentsec.tool.name`.

**Hint 1.** Deduplicate a repeated field with `mvindex(mvdedup(...),0)` before you group. A larger `mvcount` is not extra executions until `dc(_raw)` says so.

**Partial search.** Finish it yourself in [Search]({SEARCH_URL}). Use `earliest=0` on this lab index. The disabled saved search looks back 24 hours and is not this exercise.

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0
("event.name"=agentsec.control.decision OR "event.name"=agentsec.mcp.started)
```

The table below only shows which event names exist in each mode. It is not your detection.
""",
        title="HYPOTHESIS",
    )
    add_table(
        "viz_events",
        "ds_events",
        "Event names by mode",
        "Inventory only. A count of starts is not a detection match.",
    )

    add_md(
        "viz_correlate",
        f"""
# Correlate, then write

**Broad candidate.** Same `agentsec.run.id` has a CTRL-MCP-001 DENY and any `agentsec.mcp.started`. No tool key. No sequence test. Write this in [Search]({SEARCH_URL}).

**Hint 2.** Same run is not the same tool. A denied tool and an allowed tool can share a run.

**Hint 3.** Order uses `agentsec.sequence`, not `_time` alone. A start counts only when its sequence is greater than the DENY sequence for that same tool. A start at sequence 4 is not after a DENY at sequence 9.

**Hint 4.** Put `agentsec.control.id=CTRL-MCP-001` on the decision test only. Do not require that field on `agentsec.mcp.started`. The shipped file `DET-MCP-001.spl` checks DENY and does not filter the control id. Your tuned predicate should add that filter. Do not edit `savedsearches.conf`.

**Tuned candidate.** Same run, same `gen_ai.tool.name`, start sequence greater than the DENY sequence, control id constrained on the decision. Keep the decision row and the start row as different events.

Then run the tuned search three times, or add `agentsec.testbed.mode` after you deduplicate it, so you can compare ATTACK, RETEST, and BASELINE. Do not assume ATTACK matches. Do not assume RETEST is empty. Do not assume BASELINE is empty.
""",
        title="CORRELATE",
    )

    add_md(
        "viz_compare",
        """
# Compare, break, and tune

**ATTACK.** Ask whether the tuned predicate matched. Then look at CTRL-MCP-001 decisions whose reason begins with `vulnerable_profile_fail_open`. If those rows are ALLOW followed by `agentsec.mcp.started`, your DENY-then-start predicate does not cover that path. A non-match is not proof the attack failed.

**RETEST.** A DENY can be attempt evidence while the denied tool never starts. A start of a different tool in that run is not execution of the denied tool. Separate attempt, authorization failure, same-tool execution, and impact. Impact may be NOT OBSERVED.

**BASELINE.** A non-match says this predicate did not flag the available baseline rows. It does not establish a false-positive rate.

**What tuning gains.** Same tool and later sequence drop a run that denies one tool and starts another.

**What tuning loses.** A start with no tool name, a start of a different tool you still find suspicious, execution recorded only as `agentsec.mcp.completed` or `agentsec.mcp.failed`, and every fail-open ALLOW. Those silences are scope. They are not health.

**False positive to test.** What legitimate or merely different behavior satisfies the broad search? Use a row you found. Do not invent an approval workflow this index does not show.

**False negative to test.** How can the tuned search miss a real start? Missing `agentsec.mcp.started`, a control id required on that start event, a different tool, and the 24-hour saved-search window are the relevant gaps. Mark each one as something you saw or something you are only reasoning about.

Do not add filters until BASELINE disappears. BASELINE emptiness is not the goal.
""",
        title="COMPARE",
    )

    add_md(
        "viz_coverage",
        """
# Detection coverage statement

Write this yourself. Path B does not contain your filled statement.

Answer each line:

- What behavior does this detection look for?
- What behavior does it not look for?
- What evidence does it depend on?
- What correlation does it require?
- Which scenarios were tested?
- What matched, and was that row indexed or simulated?
- What did not match?
- What could cause a false positive?
- What could cause a false negative?
- What remains untested?
- What conclusion is justified?
- What conclusion is not justified?
- What would still be required before anyone enabled a detector?

At least one of NOT OBSERVED, NOT PROVEN, or CORRELATION NOT ESTABLISHED belongs in the statement when the evidence has that gap.

A match is not an incident. A finding is not an incident. No match is not a safety verdict. RETEST is not universal safety. BASELINE is not a false-positive rate. Scanner HIGH is not DENY. Garak PASS is not a safety verdict. External evidence has no runtime run id in this lab's measured external plane: CORRELATION NOT ESTABLISHED.

Do not write SAFE, SECURE, or NO ATTACK as the conclusion. Do not write that the system is secure.

The positive control file `learning/level_1/LAB-MCP-001/searches/DET-MCP-001-POSITIVE-CONTROL.spl` is `makeresults` with `evidence_class=SIMULATED`. It is a logic check. It is not an indexed attack. DET-MCP-001 stays disabled.
""",
        title="COVERAGE",
    )

    add_md(
        "viz_path_b",
        """
# Path B · review

Path B is an answer key, not policy. Use it after you have written a search and a coverage statement.

**Broad candidate.** Same run, CTRL-MCP-001 DENY, any `agentsec.mcp.started`. No tool key. No sequence test. The panel under this note runs that search with `earliest=0`.

Two RETEST runs were measured with a DENY of `lookup_customer_tier` at sequence 9 and an earlier start of `lookup_policy`:

- `0ab10594-a7fc-48b6-81bf-4cbca54a64c6`: ALLOW of `lookup_policy` at sequence 3, start at sequence 4, DENY of `lookup_customer_tier` at sequence 9.
- `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`: start of `lookup_policy` at sequence 5, DENY of `lookup_customer_tier` at sequence 9.

Do not describe the `lookup_policy` start as occurring after the `lookup_customer_tier` DENY. The policy start is not after that DENY. The broad search matches because it ignores tool and sequence. Your own search is the evidence if the index changes. These identifiers are previously measured specimens, not a promise that the table never grows.

**Tuned candidate.** Same run and same `gen_ai.tool.name`, start sequence greater than the DENY sequence, and `agentsec.control.id=CTRL-MCP-001` only inside the DENY test. The second panel runs that search. Empty is not a safety verdict.

The shipped file `DET-MCP-001.spl` groups by run and tool and requires `sequence>deny_sequence`. Its `is_deny` test does not include `control_id="CTRL-MCP-001"`. `eventstats` copies `control_id` with `latest()` and takes the DENY sequence with `min()`. If one run and tool had two DENY rows, those functions could describe different rows. That split was not an indexed same-tool match. Do not edit the saved search. It stays disabled. Its dispatch window is 24 hours, which is not `earliest=0`.

**What the tuned predicate does not cover.** Fail-open ALLOW followed by `agentsec.mcp.started`. That is the principal ATTACK shape this predicate misses on purpose. A non-match there does not mean the attack was stopped.

**Simulated positive.** `DET-MCP-001-POSITIVE-CONTROL.spl` returns a labeled `SIMULATED` row. Logic tested with synthetic SPL input is not scenario validation.

**Coverage claim you may make.** The tuned predicate looks for a later start of the same tool after a CTRL-MCP-001 DENY, on the fields above, inside the window you actually searched. You may not claim universal detection, a production false-positive rate, or that zero rows made the system secure.

Detection coverage is a claim that must be proven.
""",
        title="PATH B · REVIEW",
    )
    add_table(
        "viz_broad",
        "ds_broad",
        "Path B broad candidate",
        "Run-id correlation only. A row here is not same-tool execution after denial.",
    )
    add_table(
        "viz_tuned",
        "ds_tuned",
        "Path B tuned candidate",
        "Same tool and later sequence. Empty is not a safety verdict.",
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
                    {"layoutId": "layout_hypothesis", "label": "HYPOTHESIS"},
                    {"layoutId": "layout_correlate", "label": "CORRELATE"},
                    {"layoutId": "layout_compare", "label": "COMPARE"},
                    {"layoutId": "layout_coverage", "label": "COVERAGE"},
                    {"layoutId": "layout_path_b", "label": "PATH B · REVIEW"},
                ]
            },
            "layoutDefinitions": {
                "layout_mission": layout([block("viz_mission", 0, 0, FULL, 720)], 760),
                "layout_hypothesis": layout(
                    [
                        block("viz_hypothesis", 0, 0, FULL, 860),
                        block("viz_events", 0, 860, FULL, 360),
                    ],
                    1260,
                ),
                "layout_correlate": layout([block("viz_correlate", 0, 0, FULL, 720)], 760),
                "layout_compare": layout([block("viz_compare", 0, 0, FULL, 820)], 860),
                "layout_coverage": layout([block("viz_coverage", 0, 0, FULL, 860)], 900),
                "layout_path_b": layout(
                    [
                        block("viz_path_b", 0, 0, FULL, 980),
                        block("viz_broad", 0, 980, FULL, 320),
                        block("viz_tuned", 0, 1300, FULL, 320),
                    ],
                    1660,
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
        "HYPOTHESIS",
        "CORRELATE",
        "COMPARE",
        "COVERAGE",
        "PATH B · REVIEW",
    ]
    if labels != expected:
        raise ValueError(f"unexpected tabs: {labels}")
    if definition["inputs"] != {}:
        raise ValueError("workshop does not start from a specimen dropdown")
    path_a = "\n".join(
        _tab_markdown(definition, layout_id)
        for layout_id in (
            "layout_mission",
            "layout_hypothesis",
            "layout_correlate",
            "layout_compare",
            "layout_coverage",
        )
    )
    if UUID.search(path_a):
        raise ValueError("Path A supplies a run identifier")
    if "eventstats" in path_a:
        raise ValueError("Path A includes the finished correlation")
    if "by run_id, tool" in path_a or "by run_id tool" in path_a:
        raise ValueError("Path A includes the tuned grouping")
    path_b = _tab_markdown(definition, "layout_path_b")
    for required in (
        "0ab10594-a7fc-48b6-81bf-4cbca54a64c6",
        "23c222ea-6a87-40b7-a3e9-f12a5b572fa1",
        "not after",
        "CTRL-MCP-001",
        "earliest=0",
        "SIMULATED",
        "not policy",
        "detection coverage is a claim that must be proven",
    ):
        if required.lower() not in path_b.lower():
            raise ValueError(f"path B missing {required}")
    tuned = definition["dataSources"]["ds_tuned"]["options"]["query"]
    if 'control_id="CTRL-MCP-001"' not in tuned:
        raise ValueError("tuned search does not constrain the decision control id")
    if "agentsec.mcp.started" not in tuned:
        raise ValueError("tuned search drops the start event")
    broad = definition["dataSources"]["ds_broad"]["options"]["query"]
    if "by run_id, tool" in broad or "by run_id tool" in broad:
        raise ValueError("broad search is already same-tool")
    if "sequence>" in broad:
        raise ValueError("broad search already requires order")
    queries = "\n".join(ds["options"]["query"] for ds in definition["dataSources"].values())
    if "index=*" in queries or "disabled = 0" in queries:
        raise ValueError("unbounded index or enabled detector")
    if "savedsearches.conf" in path_a and "Do not edit" not in path_a:
        raise ValueError("Path A invites a saved-search edit")


def main() -> None:
    definition = build()
    write_definition(OUT_JSON, definition)
    write_studio_xml(
        OUT_XML,
        definition,
        label="Detection Engineering — Prove Your Coverage",
        description=(
            "LAB-DETECTION-ENGINEERING REPLAY workshop after L6. "
            "Splunk is downstream evidence, not the PDP. DET-MCP-001 stays disabled."
        ),
    )
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
