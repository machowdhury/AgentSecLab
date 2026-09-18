# Agent memory Splunk investigation (Phase 11C)

**Status:** Phase 11C live Splunk validated. No Dashboard Studio. No DET-MEMORY.  
**Parents:** `docs/PHASE11C_MEMORY_SPLUNK_VALIDATION.md`, `docs/learning-notes/agent-memory-runtime.md`.

---

## WHAT IS IT?

Live proof that schema **1.7.0** memory write/recall fields actually extract in Splunk, and that one hunt can reconstruct write → persist → later recall → classify → request → authorize → execute **across two `run.id` values** without inventing fields.

## WHY DOES IT EXIST?

11B proved the runtime invariant locally. Splunk is the SOC evidence plane. Field names in a schema file are not indexed fields until live discovery. RAG’s one-run hunt cannot answer “which later run recalled what was written.”

## HOW DOES IT WORK?

Fresh A/B/C **pairs** (write then recall) with OTEL on went OTLP → collector → HEC → `index=agentsec_telemetry`. Completeness used `dc(_raw)` vs `events.jsonl` for all six run IDs. Fields were collapsed with `mvindex(mvdedup(…),0)`. Existing Q-MCP searches were reused unchanged on the **recall** run. One new hunt, `Q-MEMORY-CONTEXT-AUTHORITY`, binds write + recall tokens and uses `stats` (not `join`).

## WHERE DOES IT SIT IN AGENTSEC?

After LAB-MEMORY-001 runtime (11B) and before any workshop (11D not started). Same index/sourcetype as MCP/RAG labs. Different control (`CTRL-MEMORY-CONTEXT-001`) than RAG retrieved context.

## WHAT IS THE TRUST BOUNDARY?

Indexed `agentsec.trust_boundary=agent.memory.store` on write/recall/CONTEXT-001. Authorization remains `acmebank.mcp.authorize` on hop-1 CTRL-MCP-001. Splunk does not sit on that boundary.

## WHAT COULD AN ATTACKER CONTROL?

Persisted fixture text (mode-selected). Not grants, not profile, not indexed `control.decision`. Splunk cannot be used to mint ALLOW.

## WHAT CAN GO WRONG?

Treating OBSERVE as ALLOW; treating `untrusted_data` as “malicious”; comparing hop-1 request hashes as memory fingerprints; treating DET-MCP-001 silence as “safe”; treating missing `mcp.started` as prevention; labeling NORMAL SAFE; correlating ATTACK/RETEST by `memory.id` alone; inventing `session.id`.

## WHAT TELEMETRY SHOULD EXIST?

Write: memory id, hash, provenance, `source_run_id` = writer. Recall: same hash, trust `untrusted_data`, `source_run_id` = writer. CONTEXT-001: OBSERVE `memory_context_is_data`. Hop-1: CTRL-MCP-001 ALLOW/DENY. Optional `mcp.started`/`completed`. All were **OBSERVED** live.

## HOW WILL SPLUNK SHOW IT?

Q-MCP-AUTHZ on the recall run shows the OBSERVE row plus hop-1. Q-MCP on write runs is empty. The new hunt adds write/recall columns and collapses one row per specimen. DET-MCP-001 stays 0 on A/B/C.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE` on the **recall** run. Splunk only records it. ATTACK write stays `defended`.

## WHAT TEST PROVES THE LOGIC?

Live `dc(_raw)` COMPLETE on six IDs; B CONTEXT-001/write/recall SHA-256 == C; hunt A `no_followon`, B `mcp.completed_observed`, C `no_indexed_followon_execution_event`; runtime handler 0/1/0.

---

## What I should now be able to explain

1. Why schema 1.7.0 field names still needed live field discovery.
2. Why `dc(_raw)` is the completeness metric, not `stats count`.
3. Why write and recall are different `run.id` values and why `source_run_id` is the link.
4. Why `memory.id` cannot uniquely key ATTACK vs RETEST.
5. Why MEMORY-CONTEXT-001 OBSERVE is indexed on ATTACK as well as BASELINE.
6. Why hop-1 `content.hash` is not the memory fingerprint.
7. Why one Q-MEMORY hunt was justified and five extra Q-MEMORY files were not.
8. Why DET-MCP-001 is silent on the preferred ATTACK.
9. Why missing `mcp.started` is only corroboration, even on a COMPLETE copy.
10. Why CIM does not map `memory.trust`, and why Phase 11D / Studio / DET-MEMORY must not start from this file.
