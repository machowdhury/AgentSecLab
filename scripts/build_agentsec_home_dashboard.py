#!/usr/bin/env python3
"""Build the AgentSec Home landing Dashboard Studio view.

No SPL. No detectors. Orientation only.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from agentsec_studio import (  # noqa: E402
    FULL,
    HALF,
    THIRD,
    block,
    layout,
    layout_options,
    markdown,
    studio_defaults,
    write_definition,
    write_studio_xml,
)

OUT_JSON = ROOT / "learning" / "home" / "dashboard.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_agentsec_home.xml"
)


def build() -> dict:
    visualizations: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str | None = None) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    add_md(
        "viz_hero",
        """
# AgentSec

A learning and SOC evidence range for agentic AI security.

Investigate what an agent was authorized to do, what it attempted, and what
actually executed. Splunk is the evidence workbench. Splunk does not grant
or deny authority.
""",
        title="HOME",
    )
    add_md(
        "viz_path",
        """
# Learning path

1. **LEARN** — understand the security boundary
2. **BASELINE** — record the defended / normal run
3. **ATTACK** — run a controlled vulnerable scenario
4. **OBSERVE** — inspect agent telemetry
5. **HUNT** — reconstruct what happened
6. **DETECT** — decide whether evidence justifies a detector
7. **DEFEND** — apply the server-owned control
8. **RETEST** — same adversarial input, defended path
9. **COMPARE** — identical input, different control outcome
10. **PROVE** — answer the question from evidence

Empty hunt rows are not SAFE. ALLOW is not execution. OBSERVE is not ALLOW.
""",
        title="HOW TO LEARN",
    )
    add_md(
        "viz_attacks",
        """
# Attack Labs

**Prompt injection**
- Direct Prompt Injection

**MCP security**
- Tool Authorization
- Scope Escalation
- Parameter / Resource Authorization
- Tool Result Trust
- Confused Deputy
- Tool Catalog

Open the matching item from the **Attack Labs** menu.
""",
        title="ATTACK LABS",
    )
    add_md(
        "viz_context",
        """
# Context and agent authority

**Context security**
- RAG / Retrieved Context
- Persistent Memory

**Agent authority**
- Goal / Instruction Integrity

**Supply chain**
- Scanner + Runtime Evidence

Identity / delegation workshop is not published yet.
""",
        title="CONTEXT / AUTHORITY",
    )
    add_md(
        "viz_soc",
        """
# SOC investigation

Each workshop HUNT tab reuses a validated hunt (for example Q-GOAL-INTEGRITY-AUTHORITY or Q-MCP-AUTHZ).

Pick **Investigate specimen** on a workshop. Canonical LIVE BASELINE / ATTACK / RETEST are bound automatically.

DET-MCP-001 is the packaged detector (disabled). Silence is not SAFE. No workshop enables it.
""",
        title="SOC",
    )
    add_md(
        "viz_ref",
        """
# Reference

- Schema `agentsec.security_event` **1.9.0**
- Index `agentsec_telemetry`
- Sourcetype `otel:agentic:json`
- One operational detector: DET-MCP-001 (execution after tool DENY)
- Splunk != enforcement
- LIVE evidence is not SIMULATED
- Runtime handler counts are authoritative for execution / non-execution

Use **Search** in the app bar for ad-hoc SPL. Do not treat Home as a directory of LAB-* IDs.
""",
        title="REFERENCE",
    )

    return {
        "title": "Home",
        "description": (
            "Orientation only. Splunk does not grant or deny authority."
        ),
        "defaults": studio_defaults(),
        "visualizations": visualizations,
        "layout": {
            "options": layout_options(),
            "layoutDefinitions": {
                "layout_home": layout(
                    [
                        block("viz_hero", 0, 0, FULL, 220),
                        block("viz_path", 0, 220, HALF, 460),
                        block("viz_attacks", HALF, 220, HALF, 460),
                        block("viz_context", 0, 680, THIRD, 400),
                        block("viz_soc", THIRD, 680, THIRD, 400),
                        block("viz_ref", THIRD * 2, 680, THIRD, 400),
                    ],
                    1100,
                )
            },
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [{"layoutId": "layout_home", "label": "HOME"}],
            },
        },
        "applicationProperties": {
            "collapseNavigation": False,
            "downsampleVisualizations": False,
        },
    }


def main() -> None:
    definition = build()
    write_definition(OUT_JSON, definition)
    write_studio_xml(
        OUT_XML,
        definition,
        label="Home",
        description="AgentSec landing. Orientation only. Splunk does not ALLOW or DENY.",
    )
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
