# Phase 16B — Capstone runtime implementation

**Status:** IMPLEMENTED + locally validated (pytest 878 passed) + LIVE Splunk MEASURED + UI reviewed.  
**Lab:** LAB-AGENTSEC-CAPSTONE-001 (Lending Assistant Investigation)  
**Schema:** 1.9.0 unchanged. No 1.10.0.  
**Detector:** none. No DET-CAPSTONE. DET-MCP-001 reused only.

## Security question

A lending-policy assistant accessed customer-tier information during a workflow that was expected to summarize lending policy. The learner discovers the chain from evidence.

## Architecture (Mode B)

retrieved content → CTRL-RAG-CONTEXT-001 OBSERVE → memory WRITE → later memory RECALL → CTRL-MEMORY-CONTEXT-001 OBSERVE → follow-on request → CTRL-MCP-001 → handler → telemetry → Splunk

ATTACK/RETEST telemetry `agentsec.attack.id` is **RAG-001** (the same malicious fixture). Schema 1.9.0 has no CAPSTONE-001 enum value; a bump was not authorized. BASELINE specimen id `CAPSTONE-BASELINE` is omitted from `agentsec.attack.id` rather than invented.

## Runs

Each LIVE launch mints three UUIDs:

1. RETRIEVE (`POST /rag/retrieve`) — follow-on MCP disabled so the privileged handler is counted once later
2. WRITE (`POST /memory/write`) — same frozen RAG-001 bytes as `mem.capstone.retrieved.*`
3. RECALL (`POST /memory/recall`) — overlay only on ATTACK; CTRL-MCP-001 decides

Correlation without a new field: retrieve `content.hash` = write `content.hash` = recall `content.hash`. Recall `source_run_id` = write `run.id`.

## Check / use

Launch compares retrieve hash, write hash, and ExperimentContext fingerprint. Mismatch is ERROR `check_use_mismatch`, not a silent continue.

## Overlay

ATTACK: `vulnerable_profile_fail_open:memory_derived_authority` on the recall run only.  
RETEST: no overlay. DENY `tool_not_granted`.  
`coded_policy()` remains `lookup_policy` only.

## Goal / Identity

Not active vulnerabilities. Learners must rule them out. Absence is instrumented-experiment evidence, not a universal guarantee.

## Discrepancy vs 16A investigation numbering

16A CAP-I7–I9 emphasized goal/identity as early questions. 16B implements the 16B numbered CAP-I1–I16 (goal/identity as I12/I13) so the learner reconstructs the actual incident first, then rules out irrelevant domains. Same sixteen questions, different order.
