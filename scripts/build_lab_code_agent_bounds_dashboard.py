#!/usr/bin/env python3
"""Build the software-engineering agent bounds dashboard."""

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

LAB = ROOT / "learning" / "level_1" / "LAB-CODE-AGENT-BOUNDS"
DEFINITION = LAB / "dashboard.definition.json"
XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_code_agent_bounds.xml"
)


def build() -> dict:
    sections = [
        (
            "viz_mission",
            "MISSION",
            """# Code-generation agent bounds

This is a REPLAY workshop. Path A is the ledger you fill before Path B. The packet is not policy.

A code-generation agent's authority must be bounded and evidenced. Identity claim is not authentication. Delegation is not authorization. Approval of a read is not approval of an install. A current credential is not a tool grant. No GitHub credential is used and no external repository is modified.
""",
        ),
        (
            "viz_debt",
            "DEBT",
            """# Bounded record

- claimed agent: acme-agent-coder-001
- authentication: SIMULATED AUTHENTICATION RESULT
- delegated operation: read_repository
- approved operation: read_repository
- approval authority: NOT PROVEN
- credential: sim-cred-coder-001, status CURRENT
- dependency name: example-lib, not installed
""",
        ),
        (
            "viz_request",
            "REQUEST",
            """# Request

ATTACK and RETEST submit `install_dependency`. The delegated and approved operation is `read_repository`.

BASELINE submits `read_repository`.

Pull request and deploy stay NOT OPENED or NOT REQUESTED. Write the binding before Path B.
""",
        ),
        (
            "viz_pathb",
            "PATH B · REVIEW",
            """# Path B — review

- ATTACK: binding MISMATCH, ALLOW only as vulnerable_profile_fail_open:code_agent_scope_not_checked, simulated start, pull request NOT OPENED.
- RETEST: binding MISMATCH, DENY operation_not_granted, do not infer execution.
- BASELINE: binding MATCH, ALLOW tool_granted. A read grant is not authority to install, open a pull request, or deploy.

Resource impact is NOT PROVEN.
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
    write_studio_xml(
        XML,
        definition,
        definition_path=DEFINITION,
        label="Code Agent Bounds",
        description="LAB-CODE-AGENT-BOUNDS. Simulated code-agent authority. No GitHub credential.",
    )


if __name__ == "__main__":
    main()
