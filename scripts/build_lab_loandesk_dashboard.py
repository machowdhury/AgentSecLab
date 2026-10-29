#!/usr/bin/env python3
"""Build the LAB-LOANDESK-001 Dashboard Studio view from the committed searches. LIVE evidence, one run.id token."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agentsec_studio import (  # noqa: E402
    FULL,
    bind_run_id,
    block,
    layout,
    layout_options,
    markdown,
    search_ds,
    studio_defaults,
    table,
    write_studio_xml,
)

LAB = "LAB-LOANDESK-001"
VIEW = "ws_lab_loandesk_001"
TITLE = "Loan Desk: Agent-Authored Content"
BASE = ROOT / "learning" / "level_1" / LAB
DEFINITION = BASE / "dashboard.definition.json"
XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / f"{VIEW}.xml"
NONE = "none"  # sentinel run.id: matches nothing, so every table stays empty until the learner pastes a run.id

PANELS = [  # (key, search file, title, description, empty text)
    ("proposed", "Q-LOANDESK-PROPOSED", "1 · Model-proposed actions", "What the model asked for. Proposal is not permission.", "No proposals found for this run.id."),
    ("decisions", "Q-LOANDESK-DECISIONS", "2 · Policy authorization decisions", "CTRL-LOANDESK-001 decides. ALLOW is a decision, not an execution.", "No decisions found for this run.id."),
    ("executed", "Q-LOANDESK-EXECUTED", "3 · Executed actions", "A handler ran only if agentsec.mcp.started is recorded.", "No handler start events for this run.id."),
    ("denied", "Q-LOANDESK-DENIED", "4 · Denied actions", "Denied proposals, and whether any handler started anyway (it must not).", "No denied actions for this run.id (that is a fact about this run, not proof of safety)."),
    ("queue", "Q-LOANDESK-QUEUE", "5 · What was filed in the underwriter queue", "The handler's result as recorded. Empty when no review was filed.", "Nothing was filed for this run.id."),
    ("evidence", "Q-LOANDESK-EVIDENCE", "6 · Evidence availability", "Are all of this run's events indexed? Empty is not safe.", "No events indexed for this run.id yet."),
    ("business", "Q-LOANDESK-BUSINESS", "7 · Business task completion vs security outcome", "Blocked and complete are different facts.", "No run end event for this run.id yet."),
]


def build() -> dict:
    mission = markdown("viz_mission", """# Loan Desk: agent-authored content

A real local model proposes actions. **CTRL-LOANDESK-001** decides. A handler runs only after ALLOW. Splunk observes; it never authorizes.

## How to use this view

1. Run the Loan Desk mission in the Academy (**Loan Desk Mission**) and copy the run.id it shows.
2. Paste it into the **LIVE: your run.id** box at the top, then open **INVESTIGATE**.
3. Read the seven panels top to bottom. Each answers one question and no more.

## What this view separates

- **Proposed** is what the model asked for. **Decided** is what policy answered. **Executed** is whether a handler began. **Denied** is what policy refused.
- **Evidence availability** says whether the record is complete. **Business task** says whether the loan review finished; **security outcome** says whether anything was blocked.

An empty panel means no events were found for that run.id. It does not mean the run was safe.
""")
    howto = markdown("viz_reference", """# Reference

- Event family: `agentsec.loan_desk_event` 1.0.0, or 1.1.0 when the run's model identity was recorded (separate from `security_event` 1.9.0).
- Posture: `agentsec.defense.posture` is `baseline` (free-text review note) or `hardened` (reason codes only).
- Every field is stored more than once in this index (index-time JSON plus search-time JSON), so the searches use `mvindex(mvdedup(...),0)`.
- The searches are in `learning/level_1/LAB-LOANDESK-001/searches/` and are the same ones this view runs.
- The page cannot reach Splunk. SPLUNK-VERIFIED in the mission comes from the host verifier's fixed searches, not from this view.
""")
    visualizations = {mission[0]: mission[1], howto[0]: howto[1]}
    sources = {}
    for key, name, title, desc, empty in PANELS:
        spl = bind_run_id((BASE / "searches" / f"{name}.spl").read_text(encoding="utf-8").strip(), "live_run_id")
        ds_id, ds = search_ds(f"ds_{key}", title, spl)
        sources[ds_id] = ds
        vid, viz = table(f"viz_{key}", ds_id, title, desc, no_data=empty)
        visualizations[vid] = viz
    recent = (
        'index=agentsec_telemetry sourcetype=otel:agentic:json earliest=-24h "agentsec.schema.name"=agentsec.loan_desk_event '
        '("event.name"=agentsec.run.completed OR "event.name"=agentsec.run.failed) '
        '| eval run_id=mvindex(mvdedup(\'agentsec.run.id\'),0), posture=mvindex(mvdedup(\'agentsec.defense.posture\'),0), '
        'stop=mvindex(mvdedup(\'agentsec.agent.stop_reason\'),0), denied=mvindex(mvdedup(\'agentsec.tools.denied\'),0), '
        'executed=mvindex(mvdedup(\'agentsec.tools.executed\'),0) '
        '| table _time, run_id, posture, stop, denied, executed | sort - _time | head 20'
    )
    ds_id, ds = search_ds("ds_recent", "Recent Loan Desk runs", recent)
    sources[ds_id] = ds
    vid, viz = table("viz_recent", ds_id, "Recent Loan Desk runs (last 24 hours)", "Copy a run_id from here into the run.id box on INVESTIGATE.", no_data="No Loan Desk runs in the last 24 hours.")
    visualizations[vid] = viz

    tabs = [("layout_mission", "MISSION", ["viz_mission"]), ("layout_investigate", "INVESTIGATE", [f"viz_{p[0]}" for p in PANELS]),
            ("layout_recent", "RECENT RUNS", ["viz_recent"]), ("layout_reference", "REFERENCE", ["viz_reference"])]
    layout_defs = {}
    for lid, _label, items in tabs:
        structure, y = [], 0
        for item in items:
            h = 640 if item in ("viz_mission", "viz_reference") else 460 if item in ("viz_proposed", "viz_decisions", "viz_executed", "viz_denied") else 300
            structure.append(block(item, 0, y, FULL, h))
            y += h
        layout_defs[lid] = layout(structure, y + 40)
    return {
        "visualizations": visualizations, "dataSources": sources, "defaults": studio_defaults(),
        "inputs": {"input_live_run": {"type": "input.text", "title": "LIVE: your run.id", "options": {"token": "live_run_id", "defaultValue": NONE}}},
        "layout": {"type": "grid", "options": {**layout_options(), "submitButton": False, "submitOnDashboardLoad": True}, "globalInputs": ["input_live_run"],
                   "tabs": {"items": [{"layoutId": lid, "label": label} for lid, label, _ in tabs]},
                   "layoutDefinitions": layout_defs},
    }


def main() -> None:
    definition = build()
    if "| --- |" in json.dumps(definition):
        raise SystemExit("Studio markdown must not contain a GFM table")
    write_studio_xml(XML, definition, definition_path=DEFINITION, label=TITLE,
                     description="LAB-LOANDESK-001. LIVE Loan Desk evidence: proposed, decided, executed, denied, availability, business task.")
    print(f"wrote {DEFINITION}\nwrote {XML}")


if __name__ == "__main__":
    main()
