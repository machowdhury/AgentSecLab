#!/usr/bin/env python3
"""Build the AgentSec Mastery Check view.

Markdown only. No SPL dataSources. No detectors. Learning metadata is not policy.
Splunk does not ALLOW or DENY. Studio 10.2 cannot hide Path B.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
from agentsec.academy import (  # noqa: E402
    challenges_for,
    load_assessments,
    path_b_spl,
)
from agentsec_studio import (  # noqa: E402
    FULL,
    HALF,
    block,
    layout,
    layout_options,
    markdown,
    studio_defaults,
    write_definition,
    write_studio_xml,
)

OUT_JSON = ROOT / "learning" / "academy" / "mastery.definition.json"
OUT_XML = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_agentsec_mastery.xml"
)
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
ATTACK_URL = "http://127.0.0.1:5001/"
PI_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001"
CAPSTONE_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agentsec_capstone"
HOME_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"


def _bullets(items: list[str]) -> str:
    if not items:
        return "- (none for this challenge)"
    return "\n".join(f"- {item}" for item in items)


RUN_ID_LABELS = {
    "specimen": "specimen",
    "attack": "ATTACK",
    "retest": "RETEST",
    "replay_attack_recall": "official REPLAY ATTACK recall",
    "replay_retest_recall": "official REPLAY RETEST recall",
}


def _runs(row: dict) -> str:
    run_ids = row.get("run_ids") or {}
    if not run_ids:
        return "No run.id. This is a reasoning challenge, not a launch."
    lines = []
    for key, value in run_ids.items():
        label = RUN_ID_LABELS.get(key, key.replace("_", " "))
        lines.append(f"- **{label}:** `{value}`")
    return "\n".join(lines)


def challenge_markdown(row: dict, titles: dict[str, str]) -> str:
    mode = row["evidence_mode"]
    skill = row["splunk_skill"]
    header = f"**{row['competency_level']}** · evidence **{mode}**"
    if skill:
        header += f" · Splunk skill {skill}"
    nxt = row.get("next_assessment")
    next_line = (
        f"**Next challenge:** {titles[nxt]}."
        if nxt
        else "**Next:** use the RUBRIC tab. This is the last challenge."
    )
    spl = path_b_spl(row)
    if spl:
        path_b_body = (
            "Copyable existing Q-* hunt. It is an answer key, not policy.\n\n"
            f"```\n{spl}\n```"
        )
        if row["assessment_id"] == "MA-PT1-CAPSTONE-GATE":
            path_b_body = (
                "This AUTHZ query is bound to the official historical **REPLAY** recall UUID. "
                "It is a fragment of the recall-run tool PDP. It is **not** the 15-point "
                "readout. Completing Path B is not mastery. Preferred evidence is a fresh "
                "LIVE retrieve/write/recall triple from Attack Service.\n\n"
                + path_b_body
            )
    else:
        path_b_body = row["expected_reasoning"]
    if row["evidence_mode"] == "NONE":
        path_a_search = (
            "You do not need Splunk Search for this challenge. Answer from reasoning."
        )
    else:
        path_a_search = f"[Open Splunk Search]({SEARCH_URL})"
    return f"""
# {row['title']}

{header}

**Security question:** {row['security_question']}

{row['task']}

**Run ids**

{_runs(row)}

**Path A — try it yourself**

{row['starter_context']}

{path_a_search}

**Hint 1**

{row['hint_1']}

**Hint 2**

{row['hint_2']}

**Path B — show solution**

Studio cannot hide this. Attempt Path A first. Path B is optional.

{path_b_body}

**What this supports**

{_bullets(row['supported_claims'])}

**What this corroborates**

{_bullets(row['corroborated_claims'])}

**What is not proven**

{_bullets(row['not_proven_claims'])}

**Incorrect claims (do not write these)**

{_bullets(row['incorrect_claims'])}

**Attacker controlled:** {row['attacker_controlled']}

**Server owned:** {row['server_owned']}

**Observability only:** {row['observability_only']}

{next_line}
"""


def build() -> dict:
    catalog = load_assessments()
    visualizations: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str | None = None) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    add_md(
        "viz_intro",
        f"""
# Mastery Check

This is a **self-assessed reasoning gate**, not a certificate and not a score.

It answers: can you show, with evidence, that you understand agentic security — not that you can click the next tab.

There is no percentage. Prefer **NOT ATTEMPTED**, **IN PROGRESS**, **DEMONSTRATED**, or **NEEDS REVIEW**. Nothing is stored. Do not send identity, email, or free-text answers to AgentSec.

An instructor can say: {catalog['instructor_prompt']}

A self-study learner may still use Hint 1, Hint 2, and Path B.
""",
        title="WHAT THIS IS",
    )
    add_md(
        "viz_how",
        f"""
# How to work a challenge

1. Read the **security question**.
2. Stay on **Path A**. Open [Splunk Search]({SEARCH_URL}).
3. Start with `index=agentsec_telemetry sourcetype=otel:agentic:json` and a quoted `agentsec.run.id` when a specimen is given.
4. Use Hint 1, then Hint 2, only if you are stuck.
5. Open Path B after you have a draft answer. Studio 10.2 cannot hide Path B. That is a product limit, not a security gate.
6. Classify claims: SUPPORTED, CORROBORATED, NOT PROVEN, INCORRECT.
7. Take the next challenge. Skip FOUNDATIONAL if you already know the vocabulary — go to PRACTITIONER.

**LIVE** means you mint a fresh run.id in [Attack Service]({ATTACK_URL}). **REPLAY** means a canonical specimen already in the index. Never present REPLAY as a launch you just minted.

If you have not taken the labs yet, start at [Home]({HOME_URL}) then [Direct Prompt Injection]({PI_URL}).
""",
        title="PATH A FIRST",
    )
    add_md(
        "viz_levels",
        """
# Competency labels (internal)

**FOUNDATIONAL** — architecture: who enforces, who observes, how to rewrite indefensible sentences.

**PRACTITIONER** — find a run, reconstruct sequence, name the PDP, separate decision from execution.

**INVESTIGATOR** — compare ATTACK and RETEST. Same request. Different defense. Evidence required.

**ADVANCED** — ALLOW is not the goal. OBSERVE is not authentication. Missing mcp.started is not prevention. Do not collapse every lab into prompt injection.

**PURPLE TEAM** — capstone readout. Prefer a fresh LIVE pair. Official historical ids are REPLAY fallback.

Splunk skills S1–S8 are mapped onto these challenges. They are not extra labs.

This is **not** industry certification.
""",
        title="LEVELS",
    )

    titles = {row["assessment_id"]: row["title"] for row in catalog["challenges"]}
    for row in challenges_for("FOUNDATIONAL"):
        add_md(
            f"viz_{row['assessment_id']}",
            challenge_markdown(row, titles),
            title=row["title"],
        )
    for row in challenges_for("PRACTITIONER"):
        add_md(
            f"viz_{row['assessment_id']}",
            challenge_markdown(row, titles),
            title=row["title"],
        )
    for row in challenges_for("INVESTIGATOR"):
        add_md(
            f"viz_{row['assessment_id']}",
            challenge_markdown(row, titles),
            title=row["title"],
        )
    for row in challenges_for("ADVANCED"):
        add_md(
            f"viz_{row['assessment_id']}",
            challenge_markdown(row, titles),
            title=row["title"],
        )
    for row in challenges_for("PURPLE TEAM"):
        add_md(
            f"viz_{row['assessment_id']}",
            challenge_markdown(row, titles),
            title=row["title"],
        )

    add_md(
        "viz_capstone_readout",
        f"""
# Capstone 15-point readout

Produce this after [Lending Assistant Investigation]({CAPSTONE_URL}) ATTACK and RETEST. Prefer fresh LIVE ids. If you use the official historical recall ids, label them REPLAY.

1. Attack objective
2. Attacker-controlled input
3. Server-owned security configuration
4. Relevant trust boundaries
5. Relevant controls
6. Actual PDP
7. ATTACK authorization
8. ATTACK execution
9. RETEST authorization
10. RETEST execution
11. What remained identical
12. What changed
13. Why the outcome changed
14. What Splunk proves
15. What Splunk cannot prove

Answer key (self-check, not auto-graded): attacker controls retrieved/memory fixture bytes; server owns grants/profile; RAG and memory OBSERVE; CTRL-MCP-001 is the tool PDP; ATTACK overlay ALLOW + handler 1; RETEST DENY tool_not_granted + handler 0; same ungranted request; different ExperimentContext; Splunk copies a complete index; Splunk does not enforce, authenticate, or prove completeness from HEC 200; Goal/Identity 0 rows does not mean those domains never fail; one RETEST is not universal RAG/memory resistance.
""",
        title="READOUT",
    )

    rubric_blocks = []
    for dim in catalog["rubric"]["dimensions"]:
        rubric_blocks.append(
            f"**{dim['title']}**\n\n"
            f"- NEEDS REVIEW — {dim['needs_review']}\n"
            f"- DEMONSTRATED — {dim['demonstrated']}\n"
            f"- ADVANCED — {dim['advanced']}"
        )
    add_md(
        "viz_rubric",
        """
# Evidence-based rubric

No percentage. No leaderboard. Mark yourself NEEDS REVIEW, DEMONSTRATED, or ADVANCED on each dimension after the challenges.

"""
        + "\n\n".join(rubric_blocks)
        + """

Unacceptable sentences to rewrite: "Splunk blocked the attack." "The agent was authenticated." "The RAG document was trusted." "The memory was safe." "MCP ALLOW means the goal was approved." "No event means it did not execute." "The RETEST proves prompt injection is solved."
""",
        title="RUBRIC",
    )

    return {
        "title": "Mastery Check",
        "description": (
            "Learner mastery challenges. Not authorization. Splunk does not grant or deny."
        ),
        "defaults": studio_defaults(),
        "visualizations": visualizations,
        "layout": {
            "options": layout_options(),
            "layoutDefinitions": {
                "layout_intro": layout(
                    [
                        block("viz_intro", 0, 0, FULL, 360),
                        block("viz_how", 0, 360, HALF, 520),
                        block("viz_levels", HALF, 360, HALF, 520),
                    ],
                    900,
                ),
                "layout_foundational": layout(
                    [
                        block("viz_MA-F1-WHO-ENFORCES", 0, 0, HALF, 1280),
                        block("viz_MA-F2-REWRITE-CLAIMS", HALF, 0, HALF, 1280),
                    ],
                    1300,
                ),
                "layout_practitioner": layout(
                    [
                        block("viz_MA-P1-FIND-THE-RUN", 0, 0, HALF, 1280),
                        block("viz_MA-P2-CONTROL-AND-EXECUTION", HALF, 0, HALF, 1280),
                    ],
                    1300,
                ),
                "layout_investigator": layout(
                    [
                        block("viz_MA-I1-ATTACK-RETEST", 0, 0, FULL, 1280),
                    ],
                    1300,
                ),
                "layout_advanced": layout(
                    [
                        block("viz_MA-A1-ALLOW-IS-NOT-GOAL", 0, 0, HALF, 1280),
                        block("viz_MA-A2-OBSERVE-IS-NOT-AUTHN", HALF, 0, HALF, 1280),
                        block("viz_MA-A3-MISSING-STARTED", 0, 1280, HALF, 1200),
                        block("viz_MA-X1-CROSS-DOMAIN", HALF, 1280, HALF, 1200),
                    ],
                    2500,
                ),
                "layout_purple": layout(
                    [
                        block("viz_MA-PT1-CAPSTONE-GATE", 0, 0, FULL, 1280),
                        block("viz_capstone_readout", 0, 1280, FULL, 640),
                    ],
                    1940,
                ),
                "layout_rubric": layout(
                    [
                        block("viz_rubric", 0, 0, FULL, 980),
                    ],
                    1000,
                ),
            },
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_intro", "label": "INTRO"},
                    {"layoutId": "layout_foundational", "label": "FOUNDATIONAL"},
                    {"layoutId": "layout_practitioner", "label": "PRACTITIONER"},
                    {"layoutId": "layout_investigator", "label": "INVESTIGATOR"},
                    {"layoutId": "layout_advanced", "label": "ADVANCED"},
                    {"layoutId": "layout_purple", "label": "PURPLE TEAM"},
                    {"layoutId": "layout_rubric", "label": "RUBRIC"},
                ],
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
        label="Mastery Check",
        description="Learner mastery challenges. Not authorization. Splunk does not ALLOW or DENY.",
    )
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
