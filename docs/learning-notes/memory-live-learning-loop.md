# Persistent memory LIVE purple-team learning loop

**Status:** Phase 15C. Schema 1.9.0. No DET-MEMORY.

## What is it?

The existing Memory lab, taught as a learner-driven LIVE loop with **two related runs**: WRITE then later RECALL. Predict, launch, copy both `run.id` values, hunt in Splunk Search, defend by changing **authorization configuration**, retest the **same malicious memory bytes**, compare, and state what the evidence does and does not prove.

## Why does it exist?

Phase 11E already had a validated REPLAY workshop. Phase 14/15B proved the LIVE loop on PI, MCP, and RAG. Memory has different security semantics (INV-003, persistence across runs). Collapsing it into RAG would hide the cross-run relationship.

## How does it work?

Attack Service picks a predefined ExperimentContext. AcmeBank writes a fixture into in-process memory, then recalls it on a later run. CTRL-MEMORY-CONTEXT-001 OBSERVE. A follow-on tool request may be formed. CTRL-MCP-001 ALLOW or DENY. Splunk stores a copy. Splunk does not ALLOW or DENY.

## Where does it sit in AgentSec?

After PI-001, MCP-001, and RAG-CONTEXT LIVE reference labs, on the existing `LAB-MEMORY-001` / `ws_lab_memory_security` surface. Identity and goal integrity are later labs and are not this migration.

## What is the trust boundary?

Persisted bytes enter a later run as `untrusted_data`. Provenance is source identity. Classification is not a grant. The check/use snapshot is frozen.

## What could an attacker control?

The stored memory body (here, a closed malicious fixture). Not coded grants. Not the browser-chosen profile.

## What can go wrong?

Treating STORED as TRUSTED; treating RECALLED as AUTHORIZED; treating OBSERVE as ALLOW; treating influence as authority; treating Splunk silence as prevention; sanitizing memory instead of keeping authorization server-owned.

## What telemetry should exist?

`agentsec.memory.written`, `agentsec.memory.recalled`, memory.id, content.hash, source_run_id, CONTEXT-001 OBSERVE, follow-on tool/scope, CTRL-MCP-001 decision, `mcp.started` / completed when the handler begins, handler count.

## How will Splunk show it?

Path A in Search using **both** run.ids. Path B copyable `Q-MEMORY-CONTEXT-AUTHORITY` / Q-MCP hunts on canonical REPLAY tables. Fresh LIVE ids stay in Search.

## What control could change the result?

Server-owned ExperimentContext profile on the **recall** run. Not Splunk. Not a memory sanitizer. Overlay is not stored in the record.

## What test proves the logic?

`tests/unit/test_phase15c_memory_learning_loop.py`: same fingerprint, two write ids, two recall ids, ATTACK ALLOW/handler 1, RETEST DENY/handler 0, overlay non-persistence, authority-field rejection, auto-mode duplicate still ERROR.

## What I should now be able to explain

1. Why WRITE run.id and RECALL run.id must both be copied.
2. Why `source_run_id` is not the recall run.id.
3. Why Memory is not RAG.
4. Why CTRL-MEMORY-CONTEXT-001 stays OBSERVE.
5. Why CTRL-MCP-001 is the tool PDP.
6. Why ATTACK ALLOW is a labeled overlay, not a grant stored in memory.
7. Why RETEST uses the same malicious bytes.
8. Why missing `mcp.started` is corroboration only.
9. Why one RETEST is not universal memory-poisoning resistance.
10. Why Splunk reconstructed the experiment and did not enforce it.
