#!/usr/bin/env python3
"""Build the bounded HITL approval Studio dashboard. Static packet only."""

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

LAB = "LAB-HITL-APPROVAL"
VIEW = "ws_lab_hitl_approval"
TITLE = "Human Approval and Action Binding"
DEFINITION = ROOT / "learning" / "level_1" / LAB / "dashboard.definition.json"
XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / f"{VIEW}.xml"
SEARCH = (
    ROOT / "learning" / "level_1" / LAB / "searches" / "Q-APPROVAL-CONTRAST.spl"
).read_text(encoding="utf-8").strip()


def build() -> dict:
    mission = markdown(
        "mission",
        """# Human approval and action binding

This is a REPLAY workshop. Path A is the ledger you fill before Path B. The packet is not policy.

You are reviewing whether an approval still covers the action that was submitted.

The packet is **SIMULATED / REPLAYED**. It is not a runtime approval service and not historical MCP-004 evidence.

## Security question

An approval exists for `lookup_policy` / `lending-basics`. The submitted action is `lookup_policy` / `executive-restricted`. What does the approval cover, and what does CTRL-MCP-001 decide?

## What this does not prove

- Approval is not authentication.
- Authentication is not approval authority.
- Approval is not authorization.
- A binding match is not an ALLOW.
- A binding mismatch is not automatically a DENY.
- Execution is not resource impact.
""",
    )
    approve = markdown(
        "approve",
        """# Simulated approval decision

- Record label: SIMULATED APPROVAL DECISION
- Approval id: sim-approval-001
- Claimed approver: approver-sam
- Approver authentication: SIMULATED APPROVER AUTHENTICATION RESULT
- Approver type: packet label only; not schema principal.type; not proof of a person
- Credential reference: sim-auth-ref-approver-001
- Approval authority: NOT PROVEN
- Decision: APPROVE
- Approved tool: lookup_policy
- Approved resource: lending-basics
- Action reference: sim-action-lending-basics
- Window: 2026-10-01T15:05:00Z to 2026-10-01T16:05:00Z

The action reference is a correlation id. It is not a hash, a signature, or a tamper-proof binding.

Replay of the same approval id on a second request is **DEFERRED** in this packet.
""",
    )
    request = markdown(
        "request",
        """# Submitted action

ATTACK and RETEST submit the same action:

- tool `lookup_policy`
- resource `executive-restricted`
- action reference `sim-action-executive-restricted`
- time `2026-10-01T15:20:00Z` (inside the approval window)

BASELINE submits the approved action:

- tool `lookup_policy`
- resource `lending-basics`
- action reference `sim-action-lending-basics`

Write MATCH or MISMATCH for each mode before you open Path B. Expiry is not the difference.
""",
    )
    authorize = markdown(
        "authorize",
        """# CTRL-MCP-001

CTRL-MCP-001 remains the tool decision. This workshop does not add an approval decision to the runtime.

A MATCH is not an ALLOW. A MISMATCH is not a DENY. Write the binding on the ledger before you open Path B.

Any ALLOW that accepts a mismatched action must carry an explicitly labeled vulnerable teaching reason. That reason is packet evidence. It is not implemented in `authorize.py`, and it is not the MCP-004 resource reason `vulnerable_profile_fail_open:resource_not_granted`.
""",
    )
    contrast = markdown(
        "contrast",
        """# Historical resource decisions are not approvals

The search below counts historical CTRL-MCP-001 resource reasons. Those rows are **HISTORICAL RESOURCE DECISION — NOT AN APPROVAL**. Do not relabel them as HITL.
""",
    )
    ledger = markdown(
        "ledger",
        """# Evidence ledger

Copy one line per mode. Fill binding, CTRL-MCP-001, and execution yourself.

- Approval id for all modes: sim-approval-001
- Approved tool for all modes: lookup_policy
- Approved resource for all modes: lending-basics
- ATTACK submitted resource: executive-restricted. Binding: ______. Decision: ______. Execution: ______.
- RETEST submitted resource: executive-restricted. Binding: ______. Decision: ______. Execution: ______.
- BASELINE submitted resource: lending-basics. Binding: ______. Decision: ______. Execution: ______.
- Resource impact for all modes: NOT PROVEN
""",
    )
    path_b = markdown(
        "pathb",
        """# Path B — review

- ATTACK: binding MISMATCH, CTRL-MCP-001 ALLOW, reason vulnerable_profile_fail_open:stale_approval_accepted, separate simulated start.
- RETEST: binding MISMATCH, CTRL-MCP-001 DENY, reason approval_binding_mismatch, execution not observed; do not infer a start.
- BASELINE: binding MATCH, CTRL-MCP-001 ALLOW, reason tool_granted, separate simulated start.

Approval authority remains NOT PROVEN. Resource impact remains NOT PROVEN. Replay remains DEFERRED.
""",
    )
    visualizations = {}
    for viz_id, viz in (mission, approve, request, authorize, contrast, ledger, path_b):
        visualizations[viz_id] = viz
    ds_id, ds = search_ds("ds_contrast", "Contrast", SEARCH)
    table_id, table_viz = table(
        "viz_contrast_table",
        "ds_contrast",
        "Historical resource decisions — not approvals",
        "CTRL-MCP-001 resource reasons. Not an approval record.",
        no_data="No historical resource-decision rows in this volume.",
    )
    visualizations[table_id] = table_viz
    tabs = [
        ("layout_mission", "MISSION", ["viz_mission"]),
        ("layout_approve", "APPROVE", ["viz_approve"]),
        ("layout_request", "REQUEST", ["viz_request"]),
        ("layout_authorize", "AUTHORIZE", ["viz_authorize"]),
        ("layout_contrast", "CONTRAST", ["viz_contrast", "viz_contrast_table"]),
        ("layout_ledger", "LEDGER", ["viz_ledger"]),
        ("layout_pathb", "PATH B · REVIEW", ["viz_pathb"]),
    ]
    layout_definitions = {}
    for layout_id, _label, items in tabs:
        structure = []
        y = 0
        for item in items:
            height = 320 if item == "viz_contrast_table" else 640
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
    blob = json.dumps(definition)
    if "| --- |" in blob:
        raise SystemExit("Studio markdown must not contain a GFM table")
    write_studio_xml(
        XML,
        definition,
        definition_path=DEFINITION,
        label=TITLE,
        description="LAB-HITL-APPROVAL. SIMULATED / REPLAYED human approval binding workshop.",
    )
    print(f"wrote {DEFINITION}")
    print(f"wrote {XML}")


if __name__ == "__main__":
    main()
