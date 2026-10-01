#!/usr/bin/env python3
"""Build the educational asset-inventory dashboard from the documented packet."""

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

LAB = ROOT / "learning" / "level_1" / "LAB-ASSET-INVENTORY"
PACKET = json.loads((LAB / "inventory.packet.json").read_text(encoding="utf-8"))
DEFINITION = LAB / "dashboard.definition.json"
XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_asset_inventory.xml"
)
SEARCH = (
    "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0\n"
    "| head 1\n"
    "| stats count\n"
    '| eval inventory="NOT AN INDEXED AI-BOM"\n'
    '| eval note="This search does not prove the component list is complete or trusted"'
)


def _lines() -> str:
    rows = []
    for row in PACKET["components"]:
        rows.append(
            f"- {row['kind']}: {row['name']}; version {row['version']}; "
            f"source {row['source']}; evidence {row['evidence_source']}; trust {row['trust']}"
        )
    return "\n".join(rows)


def build() -> dict:
    sections = [
        (
            "viz_mission",
            "MISSION",
            """# Asset inventory

This is a REPLAY workshop. Path A is your own reading of the list before Path B. The list is not policy.

You cannot govern what you cannot inventory. Inventory is not trust. Inventory is not authorization. Presence in a list is not safety.

Cisco AI-BOM compatibility is **NOT CLAIMED**. It remains NEEDS_EXTERNAL_VALIDATION. This file is not `cisco-aibom` output.
""",
        ),
        (
            "viz_list",
            "INVENTORY",
            "# Documented components\n\n" + _lines() + "\n",
        ),
        (
            "viz_pathb",
            "PATH B · REVIEW",
            """# Path B — review

The Ollama image is `ollama/ollama:latest`. That version is unpinned. The model name `llama3.2:1b` is a configured name, not a measured digest.

`lookup_policy` on the list is not a grant. CTRL-MCP-001 remains the tool PDP. A scanner row is not a DENY. A garak row is not safety.

Owners are NOT RECORDED. Completeness is NOT PROVEN.
""",
        ),
    ]
    visualizations = {}
    tabs = []
    for viz_id, label, body in sections:
        visualizations[viz_id] = markdown(viz_id, body)[1]
        tabs.append((f"layout_{viz_id}", label, [viz_id]))
    ds_id, ds = search_ds("ds_inventory", "Inventory absence", SEARCH)
    table_id, table_viz = table(
        "viz_table",
        "ds_inventory",
        "Index is not the inventory",
        "Empty is not a complete inventory.",
        no_data="No rows. Absence is not a complete inventory.",
    )
    visualizations[table_id] = table_viz
    tabs.append(("layout_gap", "GAP", [table_id]))
    layout_definitions = {}
    for layout_id, _label, items in tabs:
        structure = []
        y = 0
        for item in items:
            height = 280 if item == table_id else 640
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
        raise SystemExit("GFM table")
    write_studio_xml(
        XML,
        definition,
        definition_path=DEFINITION,
        label="AI Asset Inventory",
        description="LAB-ASSET-INVENTORY. Documented component list. Not a Cisco AI-BOM.",
    )


if __name__ == "__main__":
    main()
