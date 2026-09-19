# Detect versus hunt versus context for persisted memory

Phase 11D asked whether Splunk should grow a memory detector now that CTRL-MEMORY-CONTEXT-001 is indexed and a cross-run hunt exists. The short answer is **no**.

## What is it?

Detection engineering analysis: name the SOC question, name five evidence planes, and refuse to publish a notable that would fire because memory was written, because it was labeled `untrusted_data`, because a later run recalled it, or because the lab overlay used a distinctive reason string.

## Why does it exist?

SOCs are used to “memory poisoning → ticket.” In agentic systems that shortcut hides the difference between **persisted bytes**, **later recall**, **classified as data**, an agent **asking** for a tool, a control **denying or allowing**, and a handler **starting**. AgentSec already has those as separate events across **two `run.id` values**. A detector that OR-joins them would unteach the lab.

## How does it work?

Five planes:

1. Persistence (write run, memory.id, SHA-256, provenance)
2. Recall / trust (destination run, `source_run_id`, CTRL-MEMORY-CONTEXT-001 OBSERVE)
3. Influence / request (follow-on tool / scope)
4. Authorization (CTRL-MCP-001 ALLOW / DENY)
5. Execution (`mcp.started` / completed / failed; runtime handler count)

LIVE 11C: ATTACK and RETEST share Planes 1–3 (same malicious SHA-256, same OBSERVE, same REQUEST). Only Plane 4 differs; Plane 5 follows.

**ATTACK:** write → later recall → OBSERVE → REQUEST → ALLOW → START → COMPLETE  
**RETEST:** write → later recall → OBSERVE → REQUEST → DENY → no START

## Where does it sit in AgentSec?

After 11C hunts, before any workshop (Phase 11E not started). DET-MCP-001 stays the only packaged detector, and only for execution-after-DENY.

## What is the trust boundary?

Persisted memory is untrusted **data**. Coded policy is the grant. Splunk is investigation. The LLM is not the invariant.

## What could an attacker control?

Memory body written in the write run (and, in other systems, vector stores or peer writes). Not the server-owned allow-list, unless a labeled fail-open overlay is in force.

## What can go wrong?

Treating `untrusted_data` as malice. Detecting “AGENT MEMORY NOTE” or overlay `vulnerable_profile_fail_open:memory_derived_authority` in production. Calling RETEST “clean” because DET-MCP-001 returned 0 rows. Equating missing `mcp.started` with blocked. Equating ALLOW with execution. Equating a known malicious hash with a current compromise. Inventing `session.id` to fake multi-agent correlation.

## What telemetry should exist?

Already indexed: memory id, hash, provenance, `source_run_id`, OBSERVE, hop-1 decision, mcp.*. **Not** indexed: `allowed_tools` grant snapshot, `gen_ai.tool.call.id`, tenant id, writer≠reader. That gap blocks a defensible “unauthorized execution after untrusted recall” detector.

## How will Splunk show it?

Use existing hunts (`Q-MEMORY-CONTEXT-AUTHORITY`, Q-MCP-* on the recall run). Do not add DET-MEMORY.

## What control could change the result?

Defended CTRL-MCP-001 DENY (RETEST). The malicious memory and OBSERVE stay the same either way.

## What test proves the logic?

Logic is DOCUMENTED from 11B/11C LIVE contracts. Pytest only preserves “no new detector files.” Pytest does not prove detection effectiveness.

## What I should now be able to explain

1. Why ATTACK and RETEST share the same malicious SHA-256 across two write/recall pairs.
2. Why malicious stored content is not authorization bypass.
3. Why an overlay ALLOW is not automatically successful execution.
4. Why DET-MCP-001 is silent on BASELINE, ATTACK, and RETEST, correctly.
5. Why zero DET-MCP-001 rows does not mean SAFE.
6. Why write and recall are different `run.id` values and why `source_run_id` is the link.
7. Why `untrusted_data` is classification, not a verdict of malice.
8. What TELEMETRY GAP — QUERY NOT DEFENSIBLE means for a memory notable.
9. Where later ML / MLTK / Cisco Time Series Model could rank hunts without granting authority.
10. When a hunt is allowed to become a detector (the full gate — unmet).
