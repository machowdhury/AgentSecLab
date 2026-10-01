#!/usr/bin/env python3
"""Build the bounded RAG purpose-authorization Studio dashboard."""

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

LAB = "LAB-RAG-PURPOSE"
TITLE = "RAG Purpose Authorization"
DEFINITION = ROOT / "learning" / "level_1" / LAB / "dashboard.definition.json"
XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_purpose_authorization.xml"
)
SEARCH = (ROOT / "learning" / "level_1" / LAB / "searches" / "Q-PURPOSE-CONTRAST.spl").read_text(
    encoding="utf-8"
).strip()


def build() -> dict:
    sections = [
        (
            "viz_mission",
            "MISSION",
            """# RAG purpose authorization

This is a REPLAY workshop. Path A is the ledger you fill before Path B. The packet is not policy.

A document can be retrieved and still be unauthorized for the purpose in front of you.

Retrieved is not authorized for this principal. Authorized for a principal is not authorized for this purpose. Retrieval is not tool authorization. Vector similarity is not authorization.
""",
        ),
        (
            "viz_object",
            "OBJECT",
            """# Retrieved object

- principal: applicant-web
- query: lending policy
- object: doc.lending-policy.normal
- classification: internal
- allowed purpose: applicant-education
- retrieval: RETRIEVED
- vector similarity: NOT USED

This object already exists as a RAG fixture. This workshop does not add a vector database.

Historical CTRL-RAG-CONTEXT-001 rows are retrieved-context observations. They are not this purpose decision.
""",
        ),
        (
            "viz_request",
            "REQUEST",
            """# Requested purpose

ATTACK and RETEST request purpose `executive-decision` for the same retrieved object.

BASELINE requests purpose `applicant-education`.

Write whether each requested purpose is the allowed purpose before you open Path B. CTRL-MCP-001 is not invoked by retrieval.
""",
        ),
        (
            "viz_ledger",
            "LEDGER",
            """# Evidence ledger

- ATTACK purpose: executive-decision. Relation: ______. Downstream use: ______. Tool decision: NOT INVOKED.
- RETEST purpose: executive-decision. Relation: ______. Downstream use: ______. Tool decision: NOT INVOKED.
- BASELINE purpose: applicant-education. Relation: ______. Downstream use: ______. Tool decision: NOT INVOKED.
- Resource impact: NOT PROVEN
""",
        ),
        (
            "viz_pathb",
            "PATH B · REVIEW",
            """# Path B — review

- ATTACK: purpose not allowed, FAIL_OPEN, reason vulnerable_profile_fail_open:purpose_not_checked, downstream use USED.
- RETEST: purpose not allowed, DENY, reason purpose_not_allowed, downstream use NOT USED.
- BASELINE: purpose allowed, ALLOW, reason purpose_allowed, used for the allowed purpose. That is not a tool grant.

CTRL-MCP-001 remains the tool PDP and is not invoked here.
""",
        ),
        (
            "viz_contrast",
            "CONTRAST",
            """# Historical context control

The search counts CTRL-RAG-CONTEXT-001 rows and labels them **HISTORICAL RETRIEVED-CONTEXT OBSERVE — NOT A PURPOSE DECISION**. Purpose authorization on those rows is NOT OBSERVED.
""",
        ),
    ]
    visualizations = {}
    tabs = []
    for viz_id, label, body in sections:
        visualizations[viz_id] = markdown(viz_id, body)[1]
        tabs.append((f"layout_{viz_id}", label, [viz_id]))
    ds_id, ds = search_ds("ds_purpose", "Purpose contrast", SEARCH)
    table_id, table_viz = table(
        "viz_contrast_table",
        "ds_purpose",
        "Historical context observations",
        "Not a purpose decision.",
        no_data="No CTRL-RAG-CONTEXT-001 rows. Empty is not a purpose denial.",
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
    write_studio_xml(
        XML,
        definition,
        definition_path=DEFINITION,
        label=TITLE,
        description="LAB-RAG-PURPOSE. SIMULATED / REPLAYED purpose authorization workshop.",
    )


if __name__ == "__main__":
    main()
