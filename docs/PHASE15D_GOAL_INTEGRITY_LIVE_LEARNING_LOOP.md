# Phase 15D — Goal / Instruction Integrity LIVE purple-team learning loop

**Date:** 2026-09-20  
**Mode:** IMPLEMENTATION + VALIDATION  
**Schema:** **1.9.0** unchanged. No DET-GOAL. Runtime authorization **UNCHANGED**.  
**Do not start Phase 15E from this file.** Do not migrate Identity / Delegation. Do not add DET-GOAL, MLTK, LLM planner, or A2A.

Predecessor: Phase 15C PASS (LAB-MEMORY-001 LIVE). Locked 14E/15B/15C reference labs: `LAB-PI-001`, `LAB-MCP-001`, `LAB-RAG-CONTEXT`, `LAB-MEMORY-001`. This phase migrates **existing** `LAB-AGENT-GOAL-INTEGRITY-001` only (Phases 13A–13D architecture).

## Predecessor verification (DOCUMENTED)

Inspected before implementation:

- LAB-AGENT-GOAL-INTEGRITY-001 / GOAL-001 / schema 1.9.0
- CTRL-GOAL-INTEGRITY-001 (task/goal plane) + CTRL-MCP-001 (sole tool PDP)
- TaskContract `summarize_lending_policy_options` / `summarize_lending_policy` / lookup_policy / policy:read / lending-basics
- ProposedTaskChange `extract_full_policy` (not an MCP tool)
- NORMAL_NOTE / MALICIOUS_NOTE fixtures
- Q-GOAL-INTEGRITY-AUTHORITY + Q-MCP-AUTHZ / TOOL / EXECUTED / WHO
- DET-MCP-001 unchanged
- Phase 13C REPLAY ids: BASELINE `0aced342-…` / ATTACK `fd994587-…` / RETEST `605ba7c1-…`
- Phase 13D: DETECTION ANALYZED — NO NEW GOAL DETECTOR
- Existing `ws_lab_agent_goal_integrity` GRID workshop

Discrepancy found (fixed in this phase): Studio labeled 13C ids as LIVE. 15D terms: those ids are **REPLAY**. Fresh Attack Service ids are **LIVE**. `/goal/evaluate` was telemetry-only until this phase; Attack Service had no Goal catalog row.

No predecessor semantics were replaced. Overlay still fail-opens at the **goal** plane, not by MCP-DENYing lookup_policy on RETEST.

## Security property (unchanged)

INV-002 + INV-006.

AUTHORIZED TOOL != AUTHORIZED GOAL  
TOOL AUTHORIZATION != TASK AUTHORIZATION

The authoritative task remains server-owned. Untrusted instructions may propose `extract_full_policy`. They must not independently redefine the task.

ATTACK (vulnerable): same malicious instruction → proposed extract_full_policy → CTRL-GOAL-INTEGRITY-001 fail-open OBSERVE → CTRL-MCP-001 ALLOW tool_granted → wrong-goal handler 1.

RETEST (defended): same malicious bytes → same proposed extract_full_policy → CTRL-GOAL-INTEGRITY-001 DENY unauthorized_task_expansion → original task remains effective → lookup_policy still ALLOW tool_granted → summarize_lending_policy executes → wrong-goal 0 / in-task 1.

RETEST is **not** lookup_policy → MCP DENY. That would destroy the lab.

## Live experiment architecture

Closed ExperimentContext rows:

| Mode | Specimen | Instruction | Profile | Expected |
|------|----------|-------------|---------|----------|
| BASELINE | GOAL-BASELINE | NORMAL_NOTE | defended | GOAL OBSERVE cannot-redefine; MCP ALLOW; in-task 1 |
| ATTACK | GOAL-001 | MALICIOUS_NOTE | vulnerable | GOAL OBSERVE overlay; MCP ALLOW; wrong-goal 1 |
| RETEST | GOAL-001 | **same MALICIOUS_NOTE** | defended | GOAL DENY expansion; MCP ALLOW; wrong-goal 0; in-task 1 |

Browser selects lab/specimen/mode/execution only. Unknown/authority fields → ERROR, not DENY/ALLOW.

Fingerprint = `content.hash` of instruction bytes. ATTACK = RETEST = `sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2`.

Task fingerprint remains `sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c`.

## Learning experience

LEARN → PREDICT → LIVE ATTACK → COPY RUN.ID → INVESTIGATE → EXPLAIN → DEFEND → LIVE RETEST → COMPARE → PROVE.

Dashboard Studio = syllabus. Splunk Search = notebook. Attack Service = closed launcher. AcmeBank = enforcement. Splunk = evidence copy.

Path A: construct the search. Path B: existing Q-GOAL / Q-MCP solution SPL after the attempt. Bound tables are REPLAY. Fresh LIVE stays in Search.

## Detection

**DETECTION ANALYZED — NO NEW GOAL DETECTOR.** DET-MCP-001 unchanged. ATTACK is MCP ALLOW so DET-MCP-001 is 0. RETEST DENYs the **goal** expansion and still starts lookup_policy, so DET-MCP-001 is 0. `0 rows != SAFE`. Silence is not SAFE. Goal-integrity failure and MCP-authorization failure are separate invariants.

## Validation (2026-09-20)

| Claim | Class | Evidence |
|-------|-------|----------|
| Offline pytest | MEASURED | `824 passed, 2 deselected` (`not live_ollama and not live_splunk`) |
| LIVE ATTACK | MEASURED | `dc1f549f-ea1f-4ac5-bc25-5d7cca5b1fe9` GOAL OBSERVE overlay; MCP ALLOW `tool_granted`; wrong-goal 1; local 10 = Splunk `dc(_raw)` 10 |
| LIVE RETEST | MEASURED | `624b4223-510e-4a14-88e2-85f82b32d475` GOAL DENY `unauthorized_task_expansion`; MCP ALLOW `tool_granted`; wrong-goal 0; in-task 1; local 10 = Splunk `dc(_raw)` 10 |
| Same instruction bytes | MEASURED | fingerprint `sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2` on both |
| Overlay leak | MEASURED | AcmeBank `/health` after pair: `security.profile=defended`, `testbed.mode.override=null` |
| Playwright | OBSERVED | 10/10 tabs; Attack Service HTTP 200 at 1440/1280/1024; no unresolved BLOCKER/HIGH |
| Schema | MEASURED | **1.9.0** |
| DET-GOAL | DOCUMENTED | not created; DET-MCP-001 0/0 MEASURED and not SAFE |

Details: `docs/PHASE15D_SPLUNK_LIVE_VALIDATION.md`, `docs/reviews/ui-review-ws-lab-agent-goal-integrity-2026-09-20.md`.

## Stop

Phase 15D stops here. Do not start Identity LIVE, Phase 15E, DET-GOAL, MLTK, LLM planner, A2A, or a schema bump from this file.
