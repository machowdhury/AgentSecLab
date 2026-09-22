# Capstone attack story

**Status:** DESIGN ONLY. Not a payload catalog. **Do not implement from this file.**  
**Lab:** LAB-AGENTSEC-CAPSTONE-001  
**Do not start Phase 16B from this file.**

The chain is **one** influence path plus **one** PDP change. Not “everything fails.”

---

## Narrative (symptoms, not the answer)

A policy assistant is supposed to look up **policy language**. A customer reports it returned **customer-tier** information. The learner receives:

- Time window / experiment ids
- Index `agentsec_telemetry`, sourcetype `otel:agentic:json`
- The architecture in `docs/AGENTSEC_CAPSTONE_ARCHITECTURE.md` (no failing-control label)

They must discover whether retrieved text, persisted memory, a goal rewrite, or a delegation claim was involved — and whether the tool was **granted**.

---

## Smallest chain

```text
Untrusted retrieved document
  → influences a privileged tool request
  → that request (or its rationale) is written to memory
  → a later recall restates the request
  → CTRL-MCP-001 evaluates lookup_customer_tier
  → ATTACK: overlay ALLOW, handler runs
  → RETEST: coded DENY, handler does not start
```

RAG OBSERVE and memory OBSERVE fire on **both** ATTACK and RETEST. They are not the variable. The variable is the **same** as 15B/15C: server-owned MCP overlay vs coded policy.

Goal integrity and identity **do not fail simultaneously**. If those event families are absent, the learner must say so (NOT PROVEN that they caused it — they were not in the path).

---

## BASELINE

| Field | Design |
|-------|--------|
| Retrieve | Benign policy fixture (existing RAG BASELINE document family) |
| Memory | Optional write of in-task note; recall does **not** request `lookup_customer_tier` |
| MCP | `lookup_policy` (or no follow-on privileged tool) |
| Overlay | Off |
| Expected | CTRL-MCP-001 ALLOW only for granted in-task tool; no `lookup_customer_tier` execution |
| Teaching | Shape of a normal retrieve → memory → in-task tool run. BASELINE ≠ SAFE for other attacks |

---

## ATTACK

| Field | Design |
|-------|--------|
| Retrieve | Same RAG-001 **malicious** fixture already used in LAB-RAG-CONTEXT LIVE |
| Memory | Write the influenced request (or document hash + requested tool) on the retrieve run; recall on a later `run.id` (15C pattern) |
| MCP | `lookup_customer_tier` / `customer:read` / `cust-001` |
| Overlay | On (existing `untrusted_*_derived_tool_authority` family — **labeled lab fail-open**, not production IAM) |
| RAG / memory classifiers | OBSERVE (untrusted, not a grant) |
| Expected | Handler **executes** (runtime count authoritative) |
| Equivalent bytes | Document body + memory body frozen; fingerprint published like 15B/15C |

---

## DEFEND

Not a new control. Learner recommendation should be:

1. Keep RAG/memory as **data** (OBSERVE is correct).
2. Remove the lab overlay / restore coded `coded_policy()` so `lookup_customer_tier` is **not** granted.
3. Optional later (not 16A): retrieval allow-lists, memory isolation — **not** claimed as implemented.

Do not recommend “enable DET-CAPSTONE.” Do not recommend Splunk DENY.

---

## RETEST

| Field | Design |
|-------|--------|
| Adversarial input | **Equivalent** retrieve + memory bytes (same fingerprints as ATTACK) |
| Overlay | Off |
| Expected | CTRL-MCP-001 DENY `tool_not_granted`; handler count 0; RAG/memory still OBSERVE |
| Does not prove | Universal RAG or memory security; other tools; paraphrased documents; production readiness |

ATTACK and RETEST must use equivalent adversarial input when implemented (14E/15x contract).

---

## What this is not

- Not a second identity lab (no claimed `customer:read` from Agent A).
- Not a goal lab (`extract_full_policy` proposal is out of packet).
- Not MCP-006 (no deputy ambient grant).
- Not a detector exercise.
- Not “the document authorized the tool” and not “memory authorized the tool.”

---

## Mapping to existing official pairs (Mode A REPLAY)

Until Mode B exists, a facilitator may hand the learner:

1. 15B RAG ATTACK/RETEST pair (retrieve → MCP on one run)
2. 15C Memory WRITE+RECALL pair (persist → later MCP)

The learner’s job is to **combine** those evidence planes in a readout. Facilitator must label **REPLAY** and not claim a single fused LIVE `run.id`.
