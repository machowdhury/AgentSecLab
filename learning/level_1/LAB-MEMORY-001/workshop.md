# Workshop flow — persistent-memory SOC investigation

Ten stages. Question: **what can I prove from the evidence?** Not: was malicious memory detected?

## LEARN

WRITE RUN → MEMORY STORE → LATER RECALL RUN → CTRL-MEMORY-CONTEXT-001 → REQUEST → CTRL-MCP-001 → HANDLER.

Five planes: PERSISTENCE, RECALL / TRUST, INFLUENCE / REQUEST, AUTHORIZATION, EXECUTION.

RAG = retrieved external/contextual information in one run. MEMORY = persisted state surviving into a later run. AgentSec is not only MCP, RAG, or memory.

Copy full LIVE ids and hashes from the first canvas. Input fields may ellipsize UUIDs.

## BASELINE

LIVE WRITE `a8407246-7992-4ad8-bd02-cb701e150f30` / RECALL `914c41ce-5123-49eb-892c-c948295dbc46`. NORMAL `mem.lending-preference.normal`. Hash `sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b`. Provenance `agentsec.memory.fixture`. CTRL-MEMORY-CONTEXT-001 **OBSERVE** `memory_context_is_data`. Classification `untrusted_data`. No unauthorized follow-on. Handler 0.

Do not label SAFE, TRUSTED, APPROVED, or BENIGN.

No privileged follow-on was observed in this specimen. That is an observation, not proof that the stored content is safe.

## ATTACK

LIVE WRITE `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` / RECALL `b8737cd9-9b6b-48f2-acfa-178ae1446ddc`. **INTENTIONALLY VULNERABLE LAB PROFILE**.

MALICIOUS `mem.lending-preference.malicious`. Hash `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9`. Same provenance. OBSERVE. Follow-on REQUEST `lookup_customer_tier` / `customer:read`. CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:memory_derived_authority` (**LAB-ONLY VULNERABLE PROFILE MECHANISM**, not a production IOC). mcp.started. mcp.completed. Handler 1.

The recalled memory influenced a request. The vulnerable authorization profile granted the request. The memory itself did not grant the tool.

```text
write → later recall → OBSERVE → REQUEST → ALLOW → START → COMPLETE
```

## OBSERVE

Five visible sections: PERSISTENCE · RECALL / TRUST · INFLUENCE / REQUEST · AUTHORIZATION · EXECUTION.

Indexed structured fields. No `_raw`. No full memory body. Hash + bounded preview. Write-run sequence and recall-run sequence are both shown.

Hunt write + Hunt recall default to BASELINE.

## HUNT

Primary: **Q-MEMORY-CONTEXT-AUTHORITY**.

Reuse: Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-WHO against the **recall** run.

Reconstruct: WRITE → RECALL → REQUEST → AUTHORIZATION → EXECUTION.

Correlation: memory.id + content.hash + source_run_id + destination run.id + agent id + sequence.

Do not invent session.id / invocation.id / tenant.id / tool.call.id. Do not hunt AGENT MEMORY NOTE. Do not use the overlay reason as a production IOC. No DET-MEMORY.

## DETECT

**DETECTION ANALYZED — NO NEW MEMORY DETECTOR.**

DET-MCP-001:

- BASELINE = 0 because there was no DENY
- ATTACK = 0 because the path was ALLOW — no DENY
- RETEST = 0 because DENY was respected — no later start

0 rows is CORRECT. 0 rows != SAFE.

DET-MCP-001 detects execution-after-DENY. It is not a memory-poisoning detector.

SIMULATED positive-control table is makeresults, not LIVE.

FUTURE — NOT IMPLEMENTED panel: ML may prioritize investigation. ML must not grant or deny authority. ANOMALY != INCIDENT.

WHAT WE CANNOT PROVE YET: grant snapshot, tool.call.id, writer≠reader, tenant, cross-agent, vector memory.

## DEFEND

Not: sanitize all memory, block every suspicious string, trust a scanner, ask Splunk, let an LLM decide authority.

Memory may influence a REQUEST. Server-owned authorization determines the GRANT.

```text
MALICIOUS MEMORY
 ↓
RECALL
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

LIVE WRITE `060a0a72-ceb5-4b99-8330-98de81d8ae5e` / RECALL `5d5b9d1b-092d-4ddb-8422-4092d289cd49`.

SAME memory.id, content.hash, provenance, follow-on request, requested scope as ATTACK.

CTRL-MCP-001 DENY `tool_not_granted`. Handler 0. No mcp.started on COMPLETE Splunk copy.

Runtime handler count is authoritative for non-execution. Missing indexed execution is corroboration.

```text
write → later recall → OBSERVE → REQUEST → DENY → no START
```

## COMPARE

Three cards: BASELINE · ATTACK · RETEST.

ATTACK and RETEST prominently share hash `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9`.

**SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

ATTACK: ALLOW + execution. RETEST: DENY + handler 0.

## PROVE

Thirty evidence questions. Answers in `knowledge-check.md`.

Evidence hierarchy: RUNTIME → LOCAL → OTLP → SPLUNK → HUNT → SECURITY EVIDENCE.
