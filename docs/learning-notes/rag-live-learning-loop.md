# RAG LIVE purple-team learning loop

**Status:** Phase 15B. Schema 1.9.0. No DET-RAG.

## What is it?

The existing RAG / retrieved-context lab, taught as a learner-driven LIVE loop: predict, launch a controlled experiment, copy a fresh `run.id`, hunt in Splunk Search, defend by changing **authorization configuration**, retest the **same document bytes**, compare, and state what the evidence does and does not prove.

## Why does it exist?

Phase 10E already had a validated REPLAY workshop. Phase 14 proved the LIVE loop on prompt injection and tool authorization. RAG has different security semantics (INV-002, observation control + tool PDP). The loop had to move without inventing a second authorization engine.

## How does it work?

Attack Service picks a predefined ExperimentContext. AcmeBank retrieves a fixture document, emits CTRL-RAG-CONTEXT-001 OBSERVE, may form a follow-on tool request, and asks CTRL-MCP-001. Splunk stores a copy. Splunk does not ALLOW or DENY.

## Where does it sit in AgentSec?

After PI-001 and MCP-001 LIVE reference labs, on the existing `LAB-RAG-CONTEXT` / `ws_lab_rag_context` surface. Memory, goal integrity, and identity are later labs and are not this migration.

## What is the trust boundary?

Retrieved bytes enter agent context as `untrusted_data`. Provenance is source identity. Classification is not a grant.

## What could an attacker control?

The retrieved document body (here, a closed malicious fixture). Not coded grants. Not the browser-chosen profile (the browser cannot choose a profile).

## What can go wrong?

Treating OBSERVE as ALLOW; treating influence as authority; treating Splunk silence as prevention; sanitizing text instead of keeping authorization server-owned.

## What telemetry should exist?

`document.id`, `content.hash`, provenance, CONTEXT-001 OBSERVE, follow-on tool/scope, CTRL-MCP-001 decision, `mcp.started` / completed when the handler begins, handler count.

## How will Splunk show it?

Path A in Search. Path B copyable `Q-RAG-CONTEXT-AUTHORITY` / Q-MCP hunts on canonical REPLAY tables. Fresh LIVE ids stay in Search.

## What control could change the result?

Defended CTRL-MCP-001 (`tool_not_granted`) on the RETEST ExperimentContext. Not a document sanitizer. Not Splunk.

## What test proves the logic?

Pytest MEASURED: same `content.hash`, distinct `run.id`s, ATTACK handler 1 / RETEST handler 0, unknown fields ERROR, concurrent launches do not leak profile, coded_policy unchanged. Live Splunk is a separate MEASURED report.

## What I should now be able to explain

1. Why retrieved content is data even when it looks like an instruction.
2. Why CTRL-RAG-CONTEXT-001 OBSERVE is not a tool grant.
3. Why ATTACK and RETEST must share `document.id` and `content.hash`.
4. Why the hop-1 MCP request hash is the wrong fingerprint for this lab.
5. Why the vulnerable overlay is labeled fail-open and is not coded_policy.
6. Why RETEST DENY is not automatically SAFE and not universal RAG resistance.
7. Why handler count is authoritative and missing `mcp.started` is corroboration.
8. Why DET-MCP-001 is empty on ATTACK (ALLOW path) and RETEST (no start after DENY).
9. Why the learner cannot send profile, grants, or document body to Attack Service.
10. Why Splunk is the notebook and AcmeBank is the enforcement point.
