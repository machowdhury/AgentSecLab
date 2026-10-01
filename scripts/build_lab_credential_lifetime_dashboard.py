#!/usr/bin/env python3
"""Build the bounded short-lived credential Studio dashboard. Synthetic references only."""

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

LAB = "LAB-CREDENTIAL-LIFETIME"
TITLE = "Short-Lived Credential Lifetime"
DEFINITION = ROOT / "learning" / "level_1" / LAB / "dashboard.definition.json"
XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_credential_lifetime.xml"
)
SEARCH = (
    ROOT / "learning" / "level_1" / LAB / "searches" / "Q-CREDENTIAL-ABSENCE.spl"
).read_text(encoding="utf-8").strip()


def build() -> dict:
    mission = markdown(
        "viz_mission",
        """# Short-lived credential lifetime

This is a REPLAY workshop. Path A is the ledger you fill before Path B. The packet is not policy.

## Security question

An expired synthetic credential is presented with a privileged tool request. Does the credential's lifetime decide the tool, or does CTRL-MCP-001?

## Distinctions

- Identity is not a credential.
- A credential is not authority.
- A current credential is not tool authorization.
- An expired credential is not valid authority.
- Approval expiry is a different clock from credential expiry.
- Execution is not resource impact.
""",
    )
    issue = markdown(
        "viz_issue",
        """# Simulated credential references

No secret, private key, certificate, OAuth token, or production PKI is in this packet.

Expired reference `sim-cred-expired-001`:

- subject acme-agent-fulfillment-006
- audience teaching-tool-gateway
- scope policy:read
- issued_at 2026-10-01T12:00:00Z
- not_before 2026-10-01T12:00:00Z
- expires_at 2026-10-01T13:00:00Z
- status EXPIRED
- rotation NOT DEMONSTRATED
- revocation NOT REVOKED, and revocation enforcement is NOT DEMONSTRATED

Current reference `sim-cred-current-001` expires at 2026-10-01T18:00:00Z and is status CURRENT.

The approval clock in the neighboring workshop expires at 2026-10-01T16:05:00Z. That is not this credential's expiry.
""",
    )
    request = markdown(
        "viz_request",
        """# Presented request

ATTACK and RETEST present the same request at 2026-10-01T15:20:00Z:

- credential sim-cred-expired-001
- tool lookup_customer_tier
- resource cust-001

BASELINE presents a different request with the current credential:

- credential sim-cred-current-001
- tool lookup_policy
- resource lending-basics

Write whether each credential is inside its lifetime before you open Path B. A current credential still does not authorize the tool by itself.
""",
    )
    authorize = markdown(
        "viz_authorize",
        """# CTRL-MCP-001

CTRL-MCP-001 remains the tool decision. Credential status is evidence the decision can consider. It is not the decision.

An expired credential beside an ALLOW is a labeled teaching fault, not a production result. The reason string is packet evidence and is not implemented in `authorize.py`.
""",
    )
    contrast = markdown(
        "viz_contrast",
        """# Indexed credential lifetime

The search below does not find a credential lifetime field. It labels the result **NOT OBSERVED**. An empty result is not proof that credentials are safe.
""",
    )
    ledger = markdown(
        "viz_ledger",
        """# Evidence ledger

- ATTACK credential: sim-cred-expired-001. Status: ______. Tool: lookup_customer_tier. Decision: ______. Execution: ______.
- RETEST credential: sim-cred-expired-001. Status: ______. Tool: lookup_customer_tier. Decision: ______. Execution: ______.
- BASELINE credential: sim-cred-current-001. Status: ______. Tool: lookup_policy. Decision: ______. Execution: ______.
- Resource impact for all modes: NOT PROVEN
- Rotation: NOT DEMONSTRATED
""",
    )
    path_b = markdown(
        "viz_pathb",
        """# Path B — review

- ATTACK: credential EXPIRED, CTRL-MCP-001 ALLOW, reason vulnerable_profile_fail_open:expired_credential_accepted, separate simulated start.
- RETEST: credential EXPIRED, CTRL-MCP-001 DENY, reason expired_credential, execution not observed; do not infer a start.
- BASELINE: credential CURRENT, CTRL-MCP-001 ALLOW, reason tool_granted. The current credential did not itself authorize the tool.

Resource impact remains NOT PROVEN. Revocation enforcement remains NOT DEMONSTRATED.
""",
    )
    visualizations = {}
    for viz_id, viz in (mission, issue, request, authorize, contrast, ledger, path_b):
        visualizations[viz_id] = viz
    ds_id, ds = search_ds("ds_absence", "Credential absence", SEARCH)
    table_id, table_viz = table(
        "viz_absence_table",
        "ds_absence",
        "Credential lifetime not observed",
        "This search does not prove credential safety.",
        no_data="No rows. Absence is not safety.",
    )
    visualizations[table_id] = table_viz
    tabs = [
        ("layout_mission", "MISSION", ["viz_mission"]),
        ("layout_issue", "ISSUE", ["viz_issue"]),
        ("layout_request", "REQUEST", ["viz_request"]),
        ("layout_authorize", "AUTHORIZE", ["viz_authorize"]),
        ("layout_contrast", "ABSENCE", ["viz_contrast", "viz_absence_table"]),
        ("layout_ledger", "LEDGER", ["viz_ledger"]),
        ("layout_pathb", "PATH B · REVIEW", ["viz_pathb"]),
    ]
    layout_definitions = {}
    for layout_id, _label, items in tabs:
        structure = []
        y = 0
        for item in items:
            height = 280 if item == "viz_absence_table" else 640
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
        description="LAB-CREDENTIAL-LIFETIME. SIMULATED / REPLAYED credential lifetime workshop.",
    )


if __name__ == "__main__":
    main()
