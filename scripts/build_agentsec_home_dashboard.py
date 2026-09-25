#!/usr/bin/env python3
"""Build the AgentSec Home academy landing view.

No SPL. No detectors. Orientation and curriculum only.
Learning metadata is not policy. Splunk does not ALLOW or DENY.
"""

from __future__ import annotations

import json
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
CURRICULUM = ROOT / "learning" / "academy" / "curriculum.json"

PI_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001"
SEARCH_URL = "http://127.0.0.1:8000/en-US/app/search/search"
ATTACK_URL = "http://127.0.0.1:5001/"
CAPSTONE_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agentsec_capstone"
BLUE_TEAM_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_blue_team_incident"
MASTERY_URL = "http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_mastery"


def _mode_line(labs: list[dict]) -> str:
    lines = []
    for lab in labs:
        marker = "LIVE" if lab["mode"] == "LIVE" else "REPLAY"
        lines.append(f"- **{lab['title']}** — {marker}")
    return "\n".join(lines)


def build() -> dict:
    curriculum = json.loads(CURRICULUM.read_text(encoding="utf-8"))
    visualizations: dict[str, dict] = {}

    def add_md(viz_id: str, body: str, title: str | None = None) -> str:
        key, viz = markdown(viz_id, body, title)
        visualizations[key] = viz
        return key

    levels = {row["id"]: row for row in curriculum["levels"]}
    l1 = _mode_line(levels["L1"]["labs"])
    l2 = _mode_line(levels["L2"]["labs"])
    l3 = _mode_line(levels["L3"]["labs"])
    l5 = _mode_line(levels["L5"]["labs"])
    l6 = _mode_line(levels["L6"]["labs"])

    add_md(
        "viz_hero",
        f"""
# Start here

AgentSec is a **hands-on Agentic Security academy**. You launch controlled attacks against a lab agent, observe real telemetry, and investigate the evidence yourself in Splunk.

Splunk is the notebook. Splunk does **not** grant or deny authority.

The runtime (AcmeBank) is the enforcement point. Attack Service is a closed launcher. You do not choose grants, tools, or profiles in the browser.

**Primary action:** begin [Direct Prompt Injection]({PI_URL}).

**If you already know agents, tools, and RAG:** skip ORIENT prose. Open Direct Prompt Injection, then Attack Service. You still need run.id → Search → control vs execution. Mastery Check is after the labs, not a shortcut around launching.

Then keep this loop: LEARN → PREDICT → LAUNCH → OBSERVE → INVESTIGATE in Search → optional solution → DEFEND → RETEST → COMPARE → PROVE.

After the labs, [Mastery Check]({MASTERY_URL}) is optional self-assessment. It is not a certificate and not a score.
""",
        title="START LEARNING",
    )
    add_md(
        "viz_roles",
        f"""
# How this environment works

**Studio (this app)** — syllabus. Read the mission. Do not treat bound tables as a fresh LIVE launch.

**Attack Service** — [closed launcher]({ATTACK_URL}). LIVE labs only. Server-owned specimens.

**AcmeBank / runtime** — where controls decide ALLOW, DENY, or OBSERVE, and where handlers run or do not run.

**Splunk Search** — [your notebook]({SEARCH_URL}). You type SPL. Path A lives here.

LIVE means you mint a fresh run.id. REPLAY means canonical specimens already in the index. REPLAY is not LIVE. BASELINE is not SAFE.
""",
        title="FOUR ROLES",
    )
    add_md(
        "viz_modes",
        """
# Words you will use

**BASELINE** — normal / in-task run. Not an all-clear.

**ATTACK** — labeled vulnerable experiment. Success here is not universal vulnerability.

**RETEST** — same adversarial bytes, defended ExperimentContext. One RETEST is not universal security.

**OBSERVE** — classification. Not ALLOW.

**ALLOW / DENY** — control decisions. ALLOW is not execution. DENY is not proof the handler never ran.

**EXECUTION** — the handler or LLM actually started. Runtime counts are authoritative. Indexed `mcp.started` / `llm.started` corroborate a complete copy.

**SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT** — how you classify claims on PROVE.

Workshop tabs still use LEARN · BASELINE · ATTACK · OBSERVE · HUNT · DETECT · DEFEND · RETEST · COMPARE · PROVE. HUNT is Path A in Search. DETECT is labeled SIMULATED except the one packaged detector DET-MCP-001 (disabled; DENY-then-start only). Detector silence is not SAFE.
""",
        title="LIVE VOCABULARY",
    )

    add_md(
        "viz_orient_agent",
        """
# Agents, tools, and MCP

**LLM** — a model that generates text. It is not a grant engine.

**Agent** — an LLM plus tools, memory, and a task. The security question is what it was authorized to do, what it attempted, and what executed.

**Tool** — a function the agent can request (for example lookup_policy). Requesting a tool is not being granted it.

**MCP** — the lab's tool interface. CTRL-MCP-001 is the tool policy decision point (PDP). JSON-RPC here is in-process, not a production MCP mesh.

**Goal / task** — the authorized purpose. An authorized tool can still be used for an unauthorized purpose.

**Identity / delegation claim** — a statement that authority was handed from A to B. A claim is data. It is not authentication.
""",
        title="AGENT BASICS",
    )
    add_md(
        "viz_orient_context",
        """
# Context, controls, and evidence

**RAG** — retrieved documents used as context. Retrieved content is data. Provenance is not trust.

**Persistent memory** — state written on one run and recalled later. Stored is not trusted. Recalled is not authorized.

**Trust boundary** — where untrusted input, context, a claim, or a request meets a control.

**Control** — a coded check that records a decision and a reason.

**PDP** — the control that actually authorizes or denies the dangerous operation. Some controls only OBSERVE.

**Telemetry** — events the runtime emits (schema 1.9.0). Index `agentsec_telemetry`, sourcetype `otel:agentic:json`.

**Fingerprint** — SHA-256 of the bytes under test for that object (prompt, document, memory body, instruction, or request — whichever the lab names). Matching fingerprints on ATTACK and RETEST support equivalent hashed bytes of that object. They do not prove the same fixture name, hop, grant, or request hash unless those fields are also compared.

**Overlay** — a labeled lab-only fail-open on the vulnerable profile. Not a production IOC. Not a rewritten grant.

**source_run_id** — on memory records, the WRITE run that persisted the bytes later recalled.

**Splunk** — a searchable copy of that telemetry. HEC HTTP 200 is not evidence-ready. Missing events are not prevention. Detector silence is not SAFE.
""",
        title="SECURITY BASICS",
    )
    add_md(
        "viz_inequalities",
        """
# Inequalities you will prove in labs

Do not memorize them as slogans. You will demonstrate each one.

**Start (Foundations):** DATA != AUTHORITY. REQUEST != GRANT. ALLOW != EXECUTION. SPLUNK != ENFORCEMENT. MISSING EVENT != PREVENTION.

**Then (Context):** PROVENANCE != TRUST. STORED != TRUSTED. OBSERVE != ALLOW. REPLAY != LIVE.

**Then (Intent):** AUTHORIZED TOOL != AUTHORIZED GOAL. IDENTITY CLAIM != AUTHENTICATION. DELEGATION CLAIM != AUTHORIZATION.

**Always:** ATTACK SUCCESS != UNIVERSAL VULNERABILITY. RETEST SUCCESS != UNIVERSAL SECURITY. ANOMALY != INCIDENT.

Plain language: untrusted text can change what the agent asks for. Only a coded control can change what it is allowed to do. Splunk watches. Splunk does not block.
""",
        title="WHAT YOU WILL PROVE",
    )

    add_md(
        "viz_path_intro",
        """
# Curriculum

This is the learner path. It is not the order the software was built.

You should always know: where you are, what you are learning, why it matters, and what to do next.

Menus follow this path: **Foundations** → **Context Security** → **Agent Intent** → **Capstone** → **Blue Team**. Then **Mastery Check** (optional). Search stays the notebook.

LIVE labs have Attack Service. REPLAY labs use Investigate specimen plus Search. Do not treat REPLAY as a fresh launch.
""",
        title="WHERE AM I?",
    )
    add_md(
        "viz_path_levels",
        f"""
# Levels

**L0 Orientation (this Home)** — {levels['L0']['learn']} Exit: {levels['L0']['exit']}. Next: Foundations.

**L1 Input and tool authority** — {levels['L1']['learn']} Effort: {levels['L1']['effort']}. Exit: {levels['L1']['exit']}.

{l1}

**L2 Context is data** — {levels['L2']['learn']} Effort: {levels['L2']['effort']}. Exit: {levels['L2']['exit']}.

{l2}

**L3 Intent and identity** — {levels['L3']['learn']} Effort: {levels['L3']['effort']}. Exit: {levels['L3']['exit']}.

{l3}

**L4 Investigation craft** — practiced on every Path A. Not a separate workshop.

**L5 Capstone** — {levels['L5']['learn']} Effort: {levels['L5']['effort']}. Exit: {levels['L5']['exit']}.

{l5}

Open [Lending Assistant Investigation]({CAPSTONE_URL}) only after L1–L3 LIVE. It is graduation, not another random lab.

**L6 Blue-team investigation** — {levels['L6']['learn']} Effort: {levels['L6']['effort']}. Exit: {levels['L6']['exit']}.

{l6}

Open [AcmeBank Incident AI-2026-001]({BLUE_TEAM_URL}) after the Capstone. It is a REPLAY investigation: develop and challenge a hypothesis, reconstruct evidence, and report uncertainty. Capstone remains the last LIVE launcher.

Then [Mastery Check]({MASTERY_URL}) if you want to prove the reasoning without the workshop scaffolding. Skip FOUNDATIONAL if you already know the vocabulary.
""",
        title="PROGRESSION",
    )
    add_md(
        "viz_competency",
        f"""
# What you should be able to do

**FOUNDATIONAL** — explain DATA != AUTHORITY, REQUEST != GRANT, Splunk != enforcement, without launching.

**PRACTITIONER** — launch a closed LIVE experiment, copy run.id, find the control decision, name the PDP.

**INVESTIGATOR** — reconstruct from Search, separate authoritative runtime counts from Splunk corroboration, compare ATTACK and RETEST.

**ADVANCED / PURPLE TEAM** — investigate the capstone chain and rule out domains the evidence does not require.

**BLUE-TEAM INVESTIGATOR** — hunt without a supplied run ID, reconstruct a timeline, challenge a hypothesis, write an evidence ledger, and communicate bounded conclusions.

[Mastery Check]({MASTERY_URL}) uses those labels. There is no certificate and no leaderboard. Viewing a tab is not completion.
""",
        title="COMPETENCY",
    )

    add_md(
        "viz_splunk_boot",
        f"""
# Splunk as notebook

You do not need all of SPL. You need enough to investigate AgentSec.

1. Open [Splunk Search]({SEARCH_URL}).
2. Start with `index=agentsec_telemetry sourcetype=otel:agentic:json`.
3. Filter a quoted `agentsec.run.id`. Do not search `index=*`.
4. Sort by `agentsec.sequence`, not as if `_time` were authority.
5. Read `event.name` to see which evidence plane you are on.
6. Read `agentsec.control.id`, `agentsec.control.decision`, and `agentsec.control.reason`.
7. Read execution events (`llm.started` or `mcp.started`) separately from ALLOW.

`run.id` correlates one experiment. `sequence` orders it. A control decision is not execution. Completeness is local event count versus `dc(_raw)` on a complete copy.
""",
        title="BOOTCAMP",
    )
    add_md(
        "viz_path_ab",
        """
# Path A and Path B

**Path A — try it yourself.** Security question, starting index/sourcetype/run.id, Open Splunk Search, then Hint 1 / Hint 2 if needed. You construct the hunt.

**Path B — show solution.** Copyable SPL from an existing Q-* hunt, expected shape, what it means, what it does not mean. Optional. Not policy.

Beginner labs place Path B after the hints. The capstone treats Path B as a review key. Either way: Search first.

Bound Studio tables use Investigate specimen (often official LIVE or REPLAY ids). Fresh Attack Service ids are not auto-written into Studio.
""",
        title="PATH A / PATH B",
    )
    add_md(
        "viz_check",
        f"""
# Check yourself (not scored)

Classify each claim: SUPPORTED, CORROBORATED, NOT PROVEN, or INCORRECT.

- "The retrieved document granted customer:read."
- "CTRL-MCP-001 authorized the tool on this ATTACK run."
- "Splunk prevented the RETEST."
- "Missing mcp.started proves the handler never ran."
- "BASELINE means the system is SAFE."
- "DET-MCP-001 returned 0 rows, so there was no security issue."
- "One RETEST proves resistance to all RAG and memory attacks."
- "Caller agent id proves the agent authenticated."

Write why. Then begin [Direct Prompt Injection]({PI_URL}) if you have not already. After the labs, [Mastery Check]({MASTERY_URL}) is the longer self-assessed gate.

Schema remains **1.9.0**. One packaged detector exists: DET-MCP-001 (disabled, DENY-then-start only). Silence is not SAFE.
""",
        title="CHECK",
    )

    return {
        "title": "Home",
        "description": (
            "Academy landing. Start here. Splunk does not grant or deny authority."
        ),
        "defaults": studio_defaults(),
        "visualizations": visualizations,
        "layout": {
            "options": layout_options(),
            "layoutDefinitions": {
                "layout_start": layout(
                    [
                        block("viz_hero", 0, 0, FULL, 400),
                        block("viz_roles", 0, 400, HALF, 420),
                        block("viz_modes", HALF, 400, HALF, 420),
                    ],
                    840,
                ),
                "layout_orient": layout(
                    [
                        block("viz_orient_agent", 0, 0, HALF, 520),
                        block("viz_orient_context", HALF, 0, HALF, 520),
                        block("viz_inequalities", 0, 520, FULL, 420),
                    ],
                    960,
                ),
                "layout_path": layout(
                    [
                        block("viz_path_intro", 0, 0, FULL, 280),
                        block("viz_path_levels", 0, 280, FULL, 780),
                        block("viz_competency", 0, 1060, FULL, 380),
                    ],
                    1460,
                ),
                "layout_splunk": layout(
                    [
                        block("viz_splunk_boot", 0, 0, HALF, 560),
                        block("viz_path_ab", HALF, 0, HALF, 560),
                        block("viz_check", 0, 560, FULL, 480),
                    ],
                    1060,
                ),
            },
            "tabs": {
                "options": {"barPosition": "top"},
                "items": [
                    {"layoutId": "layout_start", "label": "START"},
                    {"layoutId": "layout_orient", "label": "ORIENT"},
                    {"layoutId": "layout_path", "label": "PATH"},
                    {"layoutId": "layout_splunk", "label": "SPLUNK"},
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
        label="Home",
        description="AgentSec academy landing. Start here. Splunk does not ALLOW or DENY.",
    )
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_XML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
