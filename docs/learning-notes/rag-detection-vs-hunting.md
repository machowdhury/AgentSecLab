# Detect versus hunt versus context for retrieved documents

Phase 10D asked whether Splunk should grow a RAG detector now that CTRL-RAG-CONTEXT-001 is indexed. The short answer is **no**.

## What is it?

Detection engineering analysis: name the SOC question, name the evidence planes, and refuse to publish a notable that would fire because a document looked instruction-like, because it was labeled `untrusted_data`, or because the lab overlay used a distinctive reason string.

## Why does it exist?

SOCs are used to “prompt injection in RAG → ticket.” In agentic systems that shortcut hides the difference between **retrieved bytes**, **classified as data**, an agent **asking** for a tool, a control **denying or allowing**, and a handler **starting**. AgentSec already has those as separate events. A detector that OR-joins them would unteach the lab.

## How does it work?

Four planes:

1. Retrieval (document.id, content.hash, provenance)
2. Trust / influence (CTRL-RAG-CONTEXT-001 OBSERVE + follow-on REQUEST)
3. Authorization (CTRL-MCP-001 ALLOW / DENY)
4. Execution (`mcp.started` / completed / failed; runtime handler count)

LIVE 10C: ATTACK and RETEST share Plane 1 and Plane 2 (same malicious document, same OBSERVE, same REQUEST). Only Plane 3 differs; Plane 4 follows.

**ATTACK:** retrieve → OBSERVE → REQUEST → ALLOW → START → COMPLETE  
**RETEST:** retrieve → OBSERVE → REQUEST → DENY → no START

## Where does it sit in AgentSec?

After 10C hunts, before any workshop (Phase 10E not started). DET-MCP-001 stays the only packaged detector, and only for execution-after-DENY.

## What is the trust boundary?

Retrieved content is untrusted **data**. Coded policy is the grant. Splunk is investigation. The LLM is not the invariant.

## What could an attacker control?

Document body (and, in other systems, embeddings, indexes, or remote RAG). Not the server-owned allow-list, unless a labeled fail-open overlay is in force.

## What can go wrong?

Treating `untrusted_data` as malice. Detecting “AGENT NOTE” or overlay `vulnerable_profile_fail_open:retrieved_context_derived_authority` in production. Calling RETEST “clean” because DET-MCP-001 returned 0 rows. Equating missing `mcp.started` with blocked. Equating ALLOW with execution. Equating a known malicious hash with a current compromise.

## What telemetry should exist?

Already indexed: document id, hash, provenance, OBSERVE, hop-1 decision, mcp.*. **Not** indexed: `allowed_tools` grant snapshot, `gen_ai.tool.call.id`, tenant id. That gap blocks a defensible “unauthorized execution after untrusted retrieval” detector.

## How will Splunk show it?

Use existing hunts (`Q-RAG-CONTEXT-AUTHORITY`, Q-MCP-*). Do not add DET-RAG.

## What control could change the result?

Defended CTRL-MCP-001 DENY (RETEST). The malicious document and OBSERVE stay the same either way.

## What test proves the logic?

Logic is DOCUMENTED from 10B/10C LIVE contracts. Pytest only preserves “no new detector files.” Pytest does not prove detection effectiveness.

## What I should now be able to explain

1. Why ATTACK and RETEST share the same malicious document and hash.
2. Why malicious retrieved content is not authorization bypass.
3. Why an overlay ALLOW is not automatically successful execution.
4. Why DET-MCP-001 is silent on BASELINE, ATTACK, and RETEST, correctly.
5. Why zero DET-MCP-001 rows does not mean SAFE.
6. Why prompt-injection-like language has weak production specificity.
7. Why `untrusted_data` is classification, not a verdict of malice.
8. What TELEMETRY GAP — QUERY NOT DEFENSIBLE means for a RAG notable.
9. Where later ML / MLTK / Cisco Time Series Model could rank hunts without granting authority.
10. When a hunt is allowed to become a detector (the full gate — unmet).
