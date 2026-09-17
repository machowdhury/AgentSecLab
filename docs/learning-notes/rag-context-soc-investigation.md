# RAG retrieved-context SOC investigation workshop

**Status:** Phase 10E Dashboard Studio workshop `ws_lab_rag_context`.

## What is it?

A ten-tab Splunk Dashboard Studio class for LAB-RAG-CONTEXT. It teaches **what a SOC can prove** from retrieved-context evidence: retrieval, trust/influence, authorization, and execution are different planes. Markdown teaches. Tables run Phase 10C-validated `Q-RAG-CONTEXT-AUTHORITY` and Q-MCP searches.

## Why does it exist?

Runtime (10B), Splunk (10C), and detection analysis (10D) already exist. Learners still need a clickable SOC path. The workshop is the teaching surface, not a new control and not a new detector.

## How does it work?

Tokens: Hunt defaults to BASELINE. BASELINE / ATTACK / RETEST bind the Phase 10C LIVE specimens. Q-RAG and Q-MCP files are unchanged except `__RUN_ID__` → `"$token$"`. DETECT right table is **SIMULATED** `makeresults`. Empty teaching is `noDataMessage`.

ATTACK and RETEST share the same malicious document hash. Authorization is the discriminator.

## Where does it sit in AgentSec?

After 10D analysis, as the learner-facing workshop. Visual sibling of `ws_lab_mcp_005` and `ws_lab_scanner_runtime_evidence`. Splunk still does not authorize. No DET-RAG. Phase 11 not started.

AgentSec is not only MCP or RAG: LAB-PI-001, MCP-001–006, catalog, scanner, then this lab.

## What is the trust boundary?

RETRIEVED CONTENT IS DATA. FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION. CTRL-RAG-CONTEXT-001 classifies; it does not grant. Hop-1 CTRL-MCP-001 is the real follow-on gate. The dashboard is observe-only.

## What could an attacker control?

Retrieved **document body** (here, a MALICIOUS fixture). Not the coded server grant. Not Splunk.

## What can go wrong?

- Treating `untrusted_data` as malice
- Treating OBSERVE as ALLOW
- Treating ATTACK overlay ALLOW as a server grant
- Calling RETEST “clean” because DET-MCP-001 returned 0 rows
- Equating missing `mcp.started` with blocked
- Hunting AGENT NOTE as a production IOC

## What telemetry should exist?

Already indexed: document id, hash, provenance, OBSERVE, hop-1 decision, mcp.*. **Not** indexed: `allowed_tools`, `gen_ai.tool.call.id`.

## How will Splunk show it?

Ten GRID tabs. COMPARE shows the same malicious hash on ATTACK and RETEST. DETECT titles **DETECTION ANALYZED — NO NEW RAG DETECTOR**.

## What control could change the result?

Defended CTRL-MCP-001 DENY (RETEST). The malicious document stays the same.

## What test proves the logic?

Pytest proves JSON/XML contracts. Playwright proves tabs and tokens in Splunk Web. Pytest does not prove detection effectiveness.

## What I should now be able to explain

1. Why ATTACK and RETEST share the same document hash.
2. Why malicious-looking content is not authorization bypass.
3. Why overlay ALLOW is not automatically successful execution.
4. Why DET-MCP-001 is empty on all three LIVE runs, correctly.
5. Why zero DET-MCP-001 rows does not mean SAFE.
6. Why handler count is authoritative and Splunk start is corroboration.
7. Why instruction-like text is not a production detector.
8. What `allowed_tools` would add to a future detector.
9. Why ML must not grant or deny authority.
10. Why AgentSec is not only MCP or RAG.
