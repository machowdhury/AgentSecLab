# Phase 13E — LAB-AGENT-GOAL-INTEGRITY-001 goal / instruction integrity SOC investigation workshop

**Date:** 2026-09-18  
**View:** `ws_lab_agent_goal_integrity`  
**Verdict:** PASS — GOAL / INSTRUCTION INTEGRITY CHAPTER COMPLETE FOR THE DESIGNED PHASE 13A–13E PATH. This file does not authorize Phase 14, identity Studio, A2A transport, rug-pull, Agent Scan, DET-GOAL, or runtime/schema change.

## Purpose

Teach learners how a SOC investigates AUTHORIZED TOOL + UNAUTHORIZED GOAL without collapsing task, instruction, goal decision, tool grant, and execution.

Learner question: **what can I prove from the evidence?** Not: did Splunk block `lookup_policy`?

## Hard stops (observed in this phase)

- No runtime authorization change
- Schema remains **1.9.0**
- No DET-GOAL
- DET-MCP-001 unchanged
- No extra Q-GOAL-* hunt files
- No LLM planner, LangChain, A2A transport, rug-pull, ML implementation
- Phase 14 not started

## Evidence used (validated earlier)

Phase 13C LIVE (not 13B local):

BASELINE `0aced342-1295-4820-b807-9a8718d9e847`  
ATTACK `fd994587-7e1c-4a70-8013-54cb2c85254d`  
RETEST `605ba7c1-449b-4338-92df-7da3b704b08e`  
Task hash (Splunk OBSERVED) `sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c`  
Instruction hash (13B local OBSERVED; Splunk PARTIALLY SUPPORTED) `sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2`  
Proposed-change fingerprint (13B local OBSERVED; Splunk PARTIALLY SUPPORTED) `sha256:6326e3be47ecf73831a06be2b718f42219e0c950d4c989de23aa558bfdc01b34`

ATTACK and RETEST share the authoritative task, malicious instruction, proposed `extract_full_policy`, and `lookup_policy` grant.

ATTACK path: OBSERVE overlay → MCP ALLOW → extract_full_policy (wrong-goal handler 1)  
RETEST path: DENY unauthorized_task_expansion → MCP ALLOW → summarize_lending_policy (wrong-goal 0, in-task 1)

Do not say MCP blocked the attack.

## Workshop flow

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

## Evidence-plane model

1 TASK  
2 INSTRUCTION / INFLUENCE  
3 GOAL DECISION  
4 TOOL AUTHORIZATION  
5 EXECUTION

AUTHORIZED TOOL != AUTHORIZED GOAL. AUTHORIZED TOOL != AUTHORIZED USE OF TOOL. REQUEST != GRANT. OBSERVE != ALLOW. ALLOW != EXECUTION. SPLUNK != ENFORCEMENT.

## Dashboard

GRID 1440 / 12. Tokens: Hunt run_id (defaults BASELINE), BASELINE, ATTACK, RETEST. Full UUIDs and hashes on LEARN / COMPARE / PROVE.

Searches reused (bind only): Q-GOAL-INTEGRITY-AUTHORITY, Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-AFTER-DENY, DET-MCP-001-POSITIVE-CONTROL (SIMULATED). OBSERVE sequence is a Studio view of indexed fields, not a new hunt file.

Rebuild: `python3 scripts/build_lab_agent_goal_integrity_dashboard.py`

## Detection teaching

DETECTION ANALYZED — NO NEW GOAL DETECTOR.

DET-MCP-001 BASELINE = 0 (no tool DENY). ATTACK = 0 (MCP ALLOW path). RETEST = 0 (goal DENY tool name ≠ lookup_policy start). 0 rows is CORRECT. 0 rows != SAFE.

FUTURE — NOT IMPLEMENTED behavioral panel. ANOMALY != INCIDENT. ML MAY PRIORITIZE INVESTIGATION. ML MUST NOT GRANT OR DENY AUTHORITY.

WHAT WE CANNOT PROVE YET telemetry-gap panel.

## UI / KO

Pass-1 and pass-2 reviews: `docs/reviews/ui-review-ws-lab-agent-goal-integrity-2026-09-18.md`.  
KO review: `docs/reviews/splunk-ko-review-goal-integrity-workshop-2026-09-18.md`.

## Contract tests

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`

**MEASURED 2026-09-18:** 699 passed, 2 deselected.

Playwright pass-2: `docs/screenshots/lab-agent-goal-integrity/pass2_validation.json` — 10/10 tabs, 4/4 LIVE tokens. Pytest does **not** prove Splunk rendering, ingestion, or detection effectiveness.

## Limitations

- Pytest does not prove Splunk rendering.
- Playwright captures Studio canvases; GRID below the fold may clip.
- Token input boxes may ellipsize UUIDs; full values are in markdown.
- Studio may render its own empty graphic; documented as a UI limitation, not SAFE.
- Instruction hash / proposed fingerprint remain PARTIALLY SUPPORTED in Splunk.
- Runtime handler counts are authoritative and are taught in markdown, not as first-class indexed fields.

## Stop

Do not start Phase 14, identity Studio, A2A transport, rug-pull, Agent Scan, DET-GOAL, or runtime/schema change from this file.
