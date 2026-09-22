# Phase 15C — migrate agent memory security into the AgentSec LIVE purple-team loop

**Date:** 2026-09-19  
**Mode:** IMPLEMENTATION + VALIDATION  
**Schema:** **1.9.0** unchanged. No DET-MEMORY. Runtime authorization **UNCHANGED**.  
**Do not start Phase 15D from this file.** Do not migrate Identity, Goal Integrity, or vector memory.

Predecessor: Phase 15B PASS (LAB-RAG-CONTEXT LIVE). Locked 14E/15B reference labs: `LAB-PI-001`, `LAB-MCP-001`, `LAB-RAG-CONTEXT`. This phase migrates **existing** `LAB-MEMORY-001` only.

## Security property (unchanged)

INV-003: Untrusted memory cannot silently become trusted instruction.

Persisted memory may influence a REQUEST. It cannot independently mint tools, scopes, resources, identity, delegation, approvals, profiles, or authorization configuration.

Teaching statements:

- STORED != TRUSTED
- RECALLED != AUTHORIZED
- MEMORY INFLUENCE != AUTHORITY
- REQUEST != GRANT
- OBSERVE != ALLOW
- ALLOW != EXECUTION
- SPLUNK != ENFORCEMENT

CTRL-MEMORY-CONTEXT-001 remains an **OBSERVATION** control (`memory_context_is_data`). CTRL-MCP-001 remains the tool PDP.

## Memory is not RAG

RAG retrieves a document **during a run**. Memory **writes** in one run, persists a record, and **recalls** it in a later run. `source_run_id` is not the recall `run.id`. Both runs matter for reconstruction.

This lab uses deterministic **in-process** memory. Not a vector database.

## Two-run experiment

| Mode | Specimen | Memory | Profile | Expected follow-on |
|------|----------|--------|---------|--------------------|
| BASELINE | MEMORY-BASELINE | `mem.lending-preference.normal` | defended | no privileged follow-on |
| ATTACK | MEMORY-001 | `mem.lending-preference.malicious` | vulnerable | ALLOW `vulnerable_profile_fail_open:memory_derived_authority`; handler 1 |
| RETEST | MEMORY-001 | **same malicious bytes** | defended | DENY `tool_not_granted`; handler 0 |

A LIVE ATTACK produces `attack_write_run_id` + `attack_recall_run_id`. A LIVE RETEST produces `retest_write_run_id` + `retest_recall_run_id`. Do not collapse these into one `run.id`.

Fingerprint is `content.hash` of the memory bytes. Overlay is per-recall ExperimentContext. It is not stored in the memory record. It is not global policy.

## Duplicate fixture writes

Auto-mode (no `experiment_id`) still ERRORs `duplicate_memory_id`. Experiment-bound launches may replace the **same catalog bytes** so RETEST can write the same `memory.id` after ATTACK in one process. Content that drifted from the fixture is still rejected.

Shared `InProcessMemoryStore` is keyed by `memory.id`. LIVE write+recall pairs are serialized. Concurrent overlapping pairs would otherwise share `source_run_id`. That limitation is documented, not hidden.

## Evidence readiness

WRITE READY and RECALL READY are independent. EXPERIMENT READY requires both searchable. HEC HTTP 200 is not searchable. Timeout is not attack failure. Missing Splunk rows are not prevention.

## Detection

**DETECTION ANALYZED — NO NEW MEMORY DETECTOR.** DET-MCP-001 is unchanged. LIVE Memory ATTACK is ALLOW, so DET-MCP-001 is 0. RETEST DENYs and does not start, so DET-MCP-001 is 0. `0 rows != SAFE`. `DET-MCP-001 silence != SAFE`.

## Stop

Phase 15C stops here. Do not start Identity LIVE, Goal Integrity LIVE, MLTK, vector memory, or Phase 15D from this file.
