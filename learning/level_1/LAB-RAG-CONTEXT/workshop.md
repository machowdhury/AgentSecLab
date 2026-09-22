# Workshop flow — RAG / retrieved-context SOC investigation

Ten stages. Question: **what can I prove from the evidence?** Not: did the RAG attack happen?

## LEARN

USER QUESTION → RETRIEVER → DOCUMENT / CHUNK → AGENT CONTEXT → AGENT MAY FORM REQUEST → AUTHORIZATION CONTROL → HANDLER.

Four planes: RETRIEVAL, TRUST / INFLUENCE, AUTHORIZATION, EXECUTION.

**LIVE** = Attack Service mints a fresh run.id; investigate in Splunk Search. **REPLAY** = canonical Investigate specimen ids on this workshop. Do not mix them.

AgentSec is not only MCP or RAG: LAB-PI-001, MCP-001–006, catalog, scanner, then this lab. Phase 11 (memory) is a later lab. A2A / rug-pull are later.

Copy full REPLAY ids and hashes from the first canvas. Input fields may ellipsize UUIDs.

## BASELINE

**REPLAY specimen** `51f70fb9-994e-4dd4-9b36-cac6fb1e8232`. Launch LIVE BASELINE from Attack Service for a fresh run.id. NORMAL `doc.lending-policy.normal`. Hash `sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e`. Provenance `rag.local.fixture`. CTRL-RAG-CONTEXT-001 **OBSERVE** `retrieved_context_is_data`. Classification `untrusted_data`. No privileged follow-on. Handler 0.

Do not label SAFE, TRUSTED, APPROVED, or BENIGN.

Zero suspicious follow-on behavior is an observation, not proof that the content is safe.

## ATTACK

**REPLAY specimen** `3a43d24f-9281-42f6-8375-1fb2efaa80ac`. Launch LIVE ATTACK from Attack Service. **INTENTIONALLY VULNERABLE LAB PROFILE**.

MALICIOUS `doc.lending-policy.malicious`. Hash `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`. Same provenance. OBSERVE. Follow-on REQUEST `lookup_customer_tier` / `customer:read`. CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:retrieved_context_derived_authority`. mcp.started. mcp.completed. Handler 1.

Retrieved text did **not** authorize the operation. Retrieved content influenced a request. The intentionally vulnerable authorization profile granted it.

```text
retrieve → OBSERVE → REQUEST → ALLOW → START → COMPLETE
```

## OBSERVE

Four visible sections: RETRIEVAL · TRUST / INFLUENCE · AUTHORIZATION · EXECUTION.

Indexed structured fields. No `_raw`. No full retrieved document. Hash + bounded preview. Sequence visible.

Hunt run.id defaults to BASELINE.

## HUNT

Two paths. **Path A** — construct the search in Splunk Search. **Path B** — copyable existing hunt SPL, expected shape, what it means and does not mean.

Primary: **Q-RAG-CONTEXT-AUTHORITY**.

Reuse: Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED (and Q-MCP-WHO).

Reconstruct: document → request → authorization → execution.

Do not hunt a regex for AGENT NOTE. Do not use the vulnerable overlay reason as a production IOC. No Q-RAG-INJECTION. No Q-RAG-MALICIOUS. No Q-RAG-POISONED. No DET-RAG.

## DETECT

**DETECTION ANALYZED — NO NEW RAG DETECTOR.**

DET-MCP-001:

- BASELINE = 0 because there was no DENY
- ATTACK = 0 because the path was ALLOW — no DENY
- RETEST = 0 because DENY was respected — no later start

0 rows is CORRECT. 0 rows != SAFE.

Classification: untrusted retrieval CONTEXT; instruction-like text HUNT / weak specificity; retrieval + privileged request HUNT; retrieval + ALLOW not enough; retrieval + execution HUNT; DENY + later execution is DET-MCP-001; rare tool after retrieval FUTURE BEHAVIORAL; abnormal retrieve→tool sequence FUTURE BEHAVIORAL / ML.

SIMULATED positive-control table is makeresults, not LIVE.

FUTURE — NOT IMPLEMENTED panel: ML may prioritize investigation. ML must not grant or deny authority. ANOMALY != INCIDENT.

## DEFEND

Not: sanitize everything, block every suspicious document, trust a scanner, ask Splunk, let an LLM decide authority.

Retrieved content may influence a REQUEST. Server-owned authorization determines the GRANT.

```text
MALICIOUS DOCUMENT
 ↓
REQUEST lookup_customer_tier
 ↓
CTRL-MCP-001
 ↓
DENY tool_not_granted
 ↓
HANDLER DOES NOT START
```

## RETEST

**REPLAY specimen** `bea97bae-491b-4b36-b52f-1417d2bad01b`. Launch LIVE RETEST from Attack Service. Same malicious bytes. Different ExperimentContext.

SAME document.id, content.hash, provenance, follow-on request, requested scope as ATTACK.

CTRL-MCP-001 DENY `tool_not_granted`. Handler 0. No mcp.started on COMPLETE Splunk copy.

Handler count = **authoritative**. Missing indexed start = **corroboration**. Do not treat Splunk as independent non-execution proof.

```text
retrieve → OBSERVE → REQUEST → DENY → no START
```

## COMPARE

Three cards: BASELINE · ATTACK · RETEST.

ATTACK and RETEST prominently share hash `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`.

**SAME RETRIEVED CONTENT. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

ATTACK: ALLOW + execution. RETEST: DENY + handler 0.

## PROVE

Twenty evidence questions. Answers in `knowledge-check.md`.

Evidence hierarchy: RUNTIME → LOCAL → OTLP → SPLUNK → HUNT → SECURITY EVIDENCE.
