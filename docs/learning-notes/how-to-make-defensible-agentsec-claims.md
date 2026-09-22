# How to make defensible AgentSec claims

**Audience:** learners who will repeat AgentSec lessons to a security engineer, SOC lead, architect, or CISO.  
**Status:** Phase 17C teaching note. Not policy. Not a launcher spec. Schema **1.9.0**.  
**Not a certificate.**

## WHAT IS IT?

A claim is defensible when the **component that actually decided or executed** can be named, the **telemetry** that records it can be named, and the **evidence class** is not upgraded.

## WHY DOES IT EXIST?

Agentic systems mix influence with authority. Strong verbs (“blocked,” “authenticated,” “safe,” “proved”) are easy to say and hard to support. AgentSec is a learning range. Over-claiming teaches the wrong security model.

## HOW DOES IT WORK?

Use this ladder:

1. **Name the security question.**  
2. **Name the authoritative component** (runtime handler count, a specific CTRL-*, not Splunk).  
3. **Name the supporting telemetry** (event.name, control.id, run.id).  
4. **Name the hunt** (existing Q-*).  
5. **Classify the evidence** (MEASURED / OBSERVED / CORROBORATED / REPLAYED / NOT PROVEN / NOT MODELED).  
6. **Say what it does not establish.**

## WHERE DOES IT SIT IN AGENTSEC?

Home CHECK, every PROVE tab, Mastery Path B “What is not proven,” and this note. Assessments are learning-only. They are not coded_policy().

## WHAT IS THE TRUST BOUNDARY?

Whatever the lab names: HTTP loan input, tool request, retrieved document, recalled memory, untrusted instruction, identity claim. The attacker does not own grants, profile, or ExperimentContext via the browser.

## WHAT COULD AN ATTACKER CONTROL?

Only the closed specimen bytes for that lab. Not `allowed_tools`. Not the schema.

## WHAT CAN GO WRONG?

Upgrading empty Search to DENY. Upgrading OBSERVE to ALLOW. Upgrading a claim string to authentication. Upgrading one RETEST to universal resistance. Upgrading DET-MCP-001 silence to SAFE. Upgrading a REPLAY UUID to a fresh LIVE launch.

## WHAT TELEMETRY SHOULD EXIST?

Enough to reconstruct: `run.id`, control id, decision, reason, requested vs granted, whether execution started. Memory also needs write vs recall ids and `source_run_id`. Capstone needs three ids and hash equality (no retrieve-to-write field).

## HOW WILL SPLUNK SHOW IT?

A copy. Completeness is local count vs `dc(_raw)`. HEC 200 is not EVIDENCE READY.

## WHAT CONTROL COULD CHANGE THE RESULT?

The runtime PDP for that boundary: CTRL-INPUT-001, CTRL-MCP-001, or CTRL-GOAL-INTEGRITY-001 for task expansion. OBSERVE classifiers do not grant.

## WHAT TEST PROVES THE LOGIC?

A named `run.id` (or pair/triple), a fingerprint of the right object, a control decision, a runtime execution count, and an explicit limitation. Pytest passing is not purple-team proof.

## Claim pattern

```text
On run.id R, CTRL-X decided D for reason N.
Runtime handler count was C.
Indexed mcp.started was present/absent on a copy with dc(_raw)=local.
This SUPPORTS … CORROBORATES … and does NOT PROVE …
```

## What I should now be able to explain

1. Why Splunk reconstructing a DENY is not Splunk preventing the action.  
2. Why runtime handler count outranks missing `mcp.started`.  
3. Why CTRL-RAG-CONTEXT-001 OBSERVE is not the tool PDP.  
4. Why Goal RETEST can DENY the expanded task while MCP still ALLOWs `lookup_policy`.  
5. Why IDENTITY OBSERVE does not mean the caller authenticated.  
6. Why DET-MCP-001 returning 0 rows is correct on a preferred ATTACK ALLOW path.  
7. Why WRITE `run.id` is not RECALL `run.id`.  
8. Why a matching SHA-256 proves hashed bytes of that object, not “the same lab” in the abstract.  
9. Why official 16B capstone UUIDs are historical copies unless you just launched.  
10. Why one defended RETEST is not a product security certification.
