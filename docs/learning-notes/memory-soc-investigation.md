# Persistent-memory SOC investigation workshop

**Status:** Phase 11E Dashboard Studio workshop `ws_lab_memory_security`.

## What is it?

A ten-tab Splunk Dashboard Studio class for LAB-MEMORY-001. It teaches **what a SOC can prove** from persistent-memory evidence: write, later recall, trust classification, request, authorization, and execution are different planes across **two `run.id` values**. Markdown teaches. Tables run Phase 11C-validated `Q-MEMORY-CONTEXT-AUTHORITY` and Q-MCP searches.

## Why does it exist?

Runtime (11B), Splunk (11C), and detection analysis (11D) already exist. Learners still need a clickable SOC path that makes the two-run relationship obvious. The workshop is the teaching surface, not a new control and not a new detector.

## How does it work?

Tokens: Hunt write + Hunt recall default to the BASELINE pair. Six specimen WRITE/RECALL tokens bind Phase 11C LIVE IDs. Q-MEMORY binds both tokens. Q-MCP binds the **recall** run. DETECT right table is **SIMULATED** `makeresults`. Empty teaching is `noDataMessage`.

ATTACK and RETEST share the same malicious memory hash. Authorization is the discriminator.

## Where does it sit in AgentSec?

After 11D analysis, as the learner-facing workshop. Visual sibling of `ws_lab_rag_context`, but **not a RAG copy**: RAG is one-run retrieval; memory is WRITE then later RECALL. Splunk still does not authorize. No DET-MEMORY. Phase 12 not started.

## What is the trust boundary?

PERSISTED MEMORY != TRUSTED INSTRUCTION. FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION. CTRL-MEMORY-CONTEXT-001 classifies; it does not grant. Hop-1 CTRL-MCP-001 is the real follow-on gate. The dashboard is observe-only.

## What could an attacker control?

Persisted **memory body** (here, a MALICIOUS fixture written in an earlier run). Not the coded server grant. Not Splunk.

## What can go wrong?

- Treating write as compromise
- Treating `untrusted_data` as malice
- Treating OBSERVE as ALLOW
- Treating ATTACK overlay ALLOW as a server grant
- Calling RETEST “clean” because DET-MCP-001 returned 0 rows
- Equating missing `mcp.started` with blocked
- Hunting AGENT MEMORY NOTE as a production IOC
- Collapsing write and recall into one run.id

## What telemetry should exist?

Already indexed: memory id, hash, provenance, `source_run_id`, OBSERVE, hop-1 decision, mcp.*. **Not** indexed: `allowed_tools`, `gen_ai.tool.call.id`, tenant, writer≠reader.

## How will Splunk show it?

Ten GRID tabs. COMPARE shows the same malicious hash on ATTACK and RETEST. DETECT titles **DETECTION ANALYZED — NO NEW MEMORY DETECTOR**.

## What control could change the result?

Defended CTRL-MCP-001 DENY (RETEST). The malicious memory stays the same.

## What test proves the logic?

Pytest proves JSON/XML contracts. Playwright proves tabs and tokens in Splunk Web. Pytest does not prove detection effectiveness.

## What I should now be able to explain

1. Why ATTACK and RETEST share the same malicious SHA-256 across two write/recall pairs.
2. Why malicious stored content is not authorization bypass.
3. Why overlay ALLOW is not automatically successful execution.
4. Why DET-MCP-001 is empty on all three LIVE recall runs, correctly.
5. Why zero DET-MCP-001 rows does not mean SAFE.
6. Why write and recall are different `run.id` values and why `source_run_id` is the link.
7. Why handler count is authoritative and Splunk start is corroboration.
8. Why instruction-like memory text is not a production detector.
9. What `allowed_tools` would add to a future detector.
10. Why ML must not grant or deny authority.
