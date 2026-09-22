# LAB-AGENT-GOAL-INTEGRITY-001 Goal / instruction integrity investigation

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.9.0  
**Invariant:** INV-002 (data cannot independently authorize) and INV-006 (privileged workflow transitions require authorized state)  
**Attack:** GOAL-001 (authorized tool used for an unauthorized task expansion)  
**Control:** CTRL-GOAL-INTEGRITY-001 (task integrity) + CTRL-MCP-001 (sole tool PDP)  
**Status:** Phase 15D LIVE purple-team loop on the existing Phase 13E workshop (`ws_lab_agent_goal_integrity`). DET-MCP-001 reused, disabled. **No DET-GOAL.** Detection: **DETECTION ANALYZED — NO NEW GOAL DETECTOR**. Canonical specimen ids below are **REPLAY** (Phase 13C). Fresh LIVE run.ids come from Attack Service.

This lab teaches one idea: **an authorized tool is not an authorized goal**. `lookup_policy` can be granted and still be the wrong use of that tool. Splunk is where you hunt a copy of the telemetry. Splunk does not ALLOW or DENY a tool or a task.

LAB-MCP-001 asked: **was lookup_policy granted?**  
LAB-AGENT-GOAL-INTEGRITY-001 asks: **was lookup_policy used for the authorized task?**

AUTHORIZED TOOL != AUTHORIZED GOAL  
AUTHORIZED TOOL != AUTHORIZED USE OF TOOL  
REQUEST != GRANT  
OBSERVE != ALLOW  
ALLOW != EXECUTION  
goal DENY != MCP DENY  
MISSING SPLUNK EVENT != BLOCKED  
ANOMALY != INCIDENT  
SPLUNK != ENFORCEMENT  
ML != AUTHORIZATION

## Learner objectives

After this lab you should be able to:

1. Reconstruct TASK → INSTRUCTION → PROPOSED GOAL → GOAL DECISION → TOOL AUTHZ → EXECUTION as five evidence planes.
2. Explain why CTRL-GOAL-INTEGRITY-001 is not the MCP tool PDP.
3. Explain why `untrusted_instruction` is classification, not malice.
4. Explain why ATTACK overlay OBSERVE is a labeled lab mechanism, not a production IOC.
5. Explain why RETEST DENYs the expansion while still ALLOWing lookup_policy.
6. Treat runtime wrong-goal handler count 0 as authoritative non-execution of the prohibited action.
7. Treat missing Splunk rows as corroboration only.
8. Explain why DET-MCP-001 is empty on BASELINE, ATTACK, and RETEST — correctly, and not SAFE.
9. Explain why MCP ALLOW on ATTACK and RETEST does not make those runs equivalent.
10. Name the telemetry gaps that block a stronger out-of-task-use detector.

## Prerequisite knowledge

- LAB-PI-001 (`ws_lab_pi_001`)
- LAB-MCP-001 workshop (`ws_lab_mcp_001`) — ALLOW ≠ execution
- Phase 13B runtime (`docs/PHASE13B_GOAL_INTEGRITY_RUNTIME_VALIDATION.md`)
- Phase 13C Splunk (`docs/PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md`)
- Phase 13D analysis (`docs/PHASE13D_GOAL_INTEGRITY_DETECTION_ANALYSIS.md`)

Not required: embeddings, LangChain, A2A transport, rug-pull, identity workshop, ML.

## Lab architecture

```text
AUTHORITATIVE TASK
 → UNTRUSTED INSTRUCTION
 → PROPOSED GOAL / TASK CHANGE
 → CTRL-GOAL-INTEGRITY-001
 → EFFECTIVE TASK
 → CTRL-MCP-001
 → AUTHORIZED TOOL
 → HANDLER / EXECUTION
 → OTel
 → Splunk (observe only)
```

## Canonical REPLAY specimens (Phase 13C)

These Investigate specimen ids are **REPLAY**. Fresh LIVE run.ids come from Attack Service. Do **not** use Phase 13B local IDs.

- BASELINE `0aced342-1295-4820-b807-9a8718d9e847` — defended, OBSERVE cannot-redefine, MCP ALLOW, in-task 1, wrong-goal 0
- ATTACK `fd994587-7e1c-4a70-8013-54cb2c85254d` — **INTENTIONALLY VULNERABLE LAB PROFILE**, OBSERVE overlay, MCP ALLOW, extract_full_policy, wrong-goal 1
- RETEST `605ba7c1-449b-4338-92df-7da3b704b08e` — defended, DENY unauthorized_task_expansion, MCP ALLOW, summarize, wrong-goal 0, in-task 1

Task hash (Splunk OBSERVED): `sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c`

Instruction hash (13B local OBSERVED; Splunk PARTIALLY SUPPORTED): `sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2`

Proposed-change fingerprint (13B local OBSERVED; Splunk PARTIALLY SUPPORTED): `sha256:6326e3be47ecf73831a06be2b718f42219e0c950d4c989de23aa558bfdc01b34`

## How to run the workshop

Open Splunk → AgentSec → **LAB-AGENT-GOAL-INTEGRITY-001 Goal / instruction integrity investigation**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

Hunt run_id defaults to the BASELINE specimen.

## Files

| File | Role |
|------|------|
| `README.md` | This overview |
| `workshop.md` | Ten-stage flow |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `dashboard.md` | How to use `ws_lab_agent_goal_integrity` |
| `dashboard.definition.json` | Studio source |
| `lab-manifest.json` | Closed launch metadata (not policy) |
| `investigations.json` | Path A/B GOAL-I1–I9 (not policy) |
| `searches/Q-GOAL-INTEGRITY-AUTHORITY.spl` | Primary hunt (13C) |

Rebuild: `python3 scripts/build_lab_agent_goal_integrity_dashboard.py`

No DET-GOAL. Phase 15D LIVE loop. Do not start Phase 15E. No A2A. No rug-pull. No ML implementation.
