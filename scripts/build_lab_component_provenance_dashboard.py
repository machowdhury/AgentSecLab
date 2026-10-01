#!/usr/bin/env python3
"""Build the component-provenance teaching dashboard."""

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

LAB = ROOT / "learning" / "level_1" / "LAB-COMPONENT-PROVENANCE"
DEFINITION = LAB / "dashboard.definition.json"
XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_component_provenance.xml"
)


def build() -> dict:
    sections = [
        (
            "viz_mission",
            "MISSION",
            """# Component provenance

This is a REPLAY workshop. Path A is the ledger you fill before Path B. The packet is not policy.

A known component is not a trusted component. A scanned component is not a safe component. An identified component is not an authorized component.

Cisco mcp-scanner stays static evidence. garak stays model-evaluation evidence. Neither authorizes a tool.
""",
        ),
        (
            "viz_debt",
            "DEBT",
            """# What the repository shows

- `docker-compose.yml` uses `ollama/ollama:latest`. That pin was not resolved. No digest was measured, so none is invented here.
- `pyproject.toml` pins `flask==3.0.3` and leaves `pytest>=8.3.0` and `setuptools>=69` as floors.
- The asset inventory lists these names. Listing them did not make them trusted.
""",
        ),
        (
            "viz_request",
            "REQUEST",
            """# Request

ATTACK and RETEST present the same privileged tool, `lookup_customer_tier`, beside the unpinned Ollama image.

BASELINE presents `lookup_policy` beside the pinned Flask requirement.

Write the CTRL-MCP-001 decision yourself before Path B. Provenance is not the decision.
""",
        ),
        (
            "viz_pathb",
            "PATH B · REVIEW",
            """# Path B — review

- ATTACK: UNPINNED image, ALLOW only as the packet reason vulnerable_profile_fail_open:known_component_treated_as_grant.
- RETEST: same image and tool, DENY, reason provenance_is_not_a_grant, do not infer execution.
- BASELINE: pinned Flask name, ALLOW tool_granted. The pin did not authorize the tool.

Resource impact is NOT PROVEN. The Ollama image remains unpinned in compose.
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
        label="Component Provenance",
        description="LAB-COMPONENT-PROVENANCE. Known is not trusted. Scanned is not safe.",
    )


if __name__ == "__main__":
    main()
