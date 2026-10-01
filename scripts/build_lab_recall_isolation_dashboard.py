#!/usr/bin/env python3
"""Build the bounded memory-ownership Studio dashboard."""

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

LAB = "LAB-RECALL-ISOLATION"
TITLE = "Memory Ownership and Isolation"
DEFINITION = ROOT / "learning" / "level_1" / LAB / "dashboard.definition.json"
XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_recall_isolation.xml"
)
SEARCH = (ROOT / "learning" / "level_1" / LAB / "searches" / "Q-RECALL-CONTRAST.spl").read_text(
    encoding="utf-8"
).strip()


def build() -> dict:
    sections = [
        (
            "viz_mission",
            "MISSION",
            """# Memory ownership and isolation

This is a REPLAY workshop. Path A is the ledger you fill before Path B. The packet is not policy.

Write is not ownership. Recall is not authorization. A memory id is not an owner. The same agent is not the same user. Stored is not retained forever.

Deletion and retention are NOT MEASURED. Do not call this secure deletion.
""",
        ),
        (
            "viz_object",
            "OBJECT",
            """# Memory record

- memory id: mem.lending-preference.normal
- owner: user-a
- writer: acme-agent-memory-001
- deletion status: NOT MEASURED
- retention status: NOT MEASURED

The writer agent is the same in every mode. The reader user is the boundary.
""",
        ),
        (
            "viz_request",
            "REQUEST",
            """# Recall request

ATTACK and RETEST use reader `user-b` for memory owned by `user-a`.

BASELINE uses reader `user-a`.

Write whether the reader is the owner before you open Path B. Recall does not invoke CTRL-MCP-001.
""",
        ),
        (
            "viz_ledger",
            "LEDGER",
            """# Evidence ledger

- ATTACK reader: user-b. Recall: ______. Isolation: ______. Tool decision: NOT INVOKED.
- RETEST reader: user-b. Recall: ______. Isolation: ______. Tool decision: NOT INVOKED.
- BASELINE reader: user-a. Recall: ______. Isolation: ______. Tool decision: NOT INVOKED.
- Deletion: NOT MEASURED. Retention: NOT MEASURED. Resource impact: NOT PROVEN.
""",
        ),
        (
            "viz_pathb",
            "PATH B · REVIEW",
            """# Path B — review

- ATTACK: reader user-b, recall RETURNED, isolation CROSSED, reason vulnerable_profile_fail_open:cross_user_recall.
- RETEST: reader user-b, recall ISOLATED, isolation HELD, reason cross_user_recall_denied.
- BASELINE: reader user-a, recall RETURNED, isolation OWNER. Owner recall is not tool authorization.

CTRL-MCP-001 remains the tool PDP and is not invoked here. Deletion remains NOT MEASURED.
""",
        ),
        (
            "viz_contrast",
            "CONTRAST",
            """# Historical recall control

The search counts CTRL-MEMORY-CONTEXT-001 rows and labels them **HISTORICAL RECALL OBSERVE — NOT AN OWNERSHIP DECISION**. Isolation and deletion on those rows are not measured by this packet.
""",
        ),
    ]
    visualizations = {}
    tabs = []
    for viz_id, label, body in sections:
        visualizations[viz_id] = markdown(viz_id, body)[1]
        tabs.append((f"layout_{viz_id}", label, [viz_id]))
    ds_id, ds = search_ds("ds_recall", "Recall contrast", SEARCH)
    table_id, table_viz = table(
        "viz_contrast_table",
        "ds_recall",
        "Historical recall observations",
        "Not an ownership decision.",
        no_data="No CTRL-MEMORY-CONTEXT-001 rows. Empty is not isolation.",
    )
    visualizations[table_id] = table_viz
    tabs[-1][2].append(table_id)
    layout_definitions = {}
    for layout_id, _label, items in tabs:
        structure = []
        y = 0
        for item in items:
            height = 280 if item == table_id else 560
            structure.append(block(item, 0, y, FULL, height))
            y += height
        layout_definitions[layout_id] = layout(structure, y + 40)
    return {
        "visualizations": visualizations,
        "dataSources": {ds_id: ds},
        "defaults": studio_defaults(),
        "inputs": {},
        "layout": {
            "type": "grid",
            "options": layout_options(),
            "tabs": {
                "items": [
                    {"layoutId": layout_id, "label": label} for layout_id, label, _ in tabs
                ]
            },
            "layoutDefinitions": layout_definitions,
        },
    }


def main() -> None:
    definition = build()
    if "| --- |" in json.dumps(definition):
        raise SystemExit("Studio markdown must not contain a GFM table")
    write_definition(DEFINITION, definition)
    write_studio_xml(
        XML,
        definition,
        label=TITLE,
        description="LAB-RECALL-ISOLATION. SIMULATED / REPLAYED memory ownership workshop.",
    )


if __name__ == "__main__":
    main()
