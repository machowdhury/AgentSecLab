#!/usr/bin/env python3
"""Build the IT and cloud change-bounds dashboard."""

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
    studio_defaults,
    write_definition,
    write_studio_xml,
)

LAB = ROOT / "learning" / "level_1" / "LAB-CHANGE-BOUNDS"
DEFINITION = LAB / "dashboard.definition.json"
XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_change_bounds.xml"
)


def build() -> dict:
    sections = [
        (
            "viz_mission",
            "MISSION",
            """# Change bounds

This is a REPLAY workshop. Path A is the ledger you fill before Path B. The packet is not policy.

Tool access is not change authority. Change authority is not unlimited blast radius. A started action is not a successful change. No cloud account credential is used.
""",
        ),
        (
            "viz_debt",
            "DEBT",
            """# Bounded record

- credential: sim-cred-ops-001
- credential scope: resource:inspect
- delegated operation: inspect_resource
- approved operation: inspect_resource
- approval authority: NOT PROVEN
""",
        ),
        (
            "viz_request",
            "REQUEST",
            """# Request

ATTACK and RETEST submit `delete_resource`. The delegated and approved operation is `inspect_resource`.

BASELINE submits `inspect_resource`.

Write whether a simulated start would prove the resource changed. It does not.
""",
        ),
        (
            "viz_pathb",
            "PATH B · REVIEW",
            """# Path B — review

- ATTACK: binding MISMATCH, ALLOW only as vulnerable_profile_fail_open:change_scope_not_checked, simulated start, completion NOT OBSERVED, impact NOT PROVEN.
- RETEST: binding MISMATCH, DENY change_not_granted, do not infer execution.
- BASELINE: binding MATCH, ALLOW tool_granted, start observed, completion NOT OBSERVED. A start is not a successful change.

Rollback is NOT RECORDED. Resource impact is NOT PROVEN.
""",
        ),
    ]
    visualizations = {}
    tabs = []
    for viz_id, label, body in sections:
        visualizations[viz_id] = markdown(viz_id, body)[1]
        tabs.append((f"layout_{viz_id}", label, [viz_id]))
    layout_definitions = {}
    for layout_id, _label, items in tabs:
        layout_definitions[layout_id] = layout([block(items[0], 0, 0, FULL, 640)], 680)
    return {
        "visualizations": visualizations,
        "dataSources": {},
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
        raise SystemExit("GFM table")
    write_definition(DEFINITION, definition)
    write_studio_xml(
        XML,
        definition,
        label="Change Bounds",
        description="LAB-CHANGE-BOUNDS. Simulated change authority. No cloud credential.",
    )


if __name__ == "__main__":
    main()
