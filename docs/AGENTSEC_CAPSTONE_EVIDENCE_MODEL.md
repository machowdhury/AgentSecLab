# Capstone evidence model

**Status:** DESIGN ONLY.  
**Do not start Phase 16B from this file.**  
Do not collapse everything into “agent logs.”

The 15A/16A security chain ends in Splunk reconstruction and proof classes. The planes below are how a SOC should **label** evidence, not new schema fields.

---

## Planes

| # | Plane | Authoritative for | Corroborative for | Observational only |
|---|-------|-------------------|-------------------|--------------------|
| 1 | INPUT / SOURCE | What bytes the closed experiment injected (Attack Service frozen fixture) | — | Browser form text (rejected if it disagrees with the catalog) |
| 2 | CONTEXT (RAG) | That retrieve happened; document.id; content.hash; CTRL-RAG-CONTEXT-001 OBSERVE label | That the document *could* have influenced a later request | Malice; “the document granted the tool” |
| 3 | MEMORY | That write/recall happened; memory.id; source_run_id; CTRL-MEMORY-CONTEXT-001 OBSERVE | Cross-run influence hypothesis | That memory is trusted instruction |
| 4 | TASK / GOAL | Server-owned task **when goal events exist** | — | In capstone Mode B: typically **absent** → cannot prove a goal attack |
| 5 | IDENTITY / DELEGATION | Claim fields **when identity events exist** | Attribution of caller_agent_id as an identifier | Authentication; grants |
| 6 | AUTHORIZATION | CTRL-MCP-001 decision, reason, coded grants (runtime) | Splunk copy of `control.decision` | Studio Path B text |
| 7 | EXECUTION | Runtime handler / LLM invocation counts | `mcp.started` / `llm.started` in a **complete** Splunk copy | Empty Splunk = prevention |
| 8 | TELEMETRY | What the runtime emitted (`events.jsonl`) | HEC accepted count | Searchability; completeness of the index |
| 9 | SPLUNK RECONSTRUCTION | What the index contains for this `run.id` | Sequence vs local jsonl | Enforcement |
| 10 | EVIDENCE / PROOF | The learner’s classification: SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT | — | Marketing “safe” |

---

## Proof classes (learner must use these words)

| Class | Meaning |
|-------|---------|
| SUPPORTED | Runtime + complete Splunk copy agree |
| CORROBORATED | Splunk agrees with runtime, or two independent event families agree |
| NOT PROVEN | Missing events, HEC lag, absent plane (goal/identity/auth), incomplete copy |
| INCORRECT | Contradicted (e.g. “Splunk DENY’d the tool”; “document authorized MCP”) |

---

## Inequalities mapped to planes

| Inequality | Planes |
|------------|--------|
| PROVENANCE ≠ TRUST | 2, 3 vs 6 |
| TRUST ≠ AUTHORITY | OBSERVE on 2–3 vs PDP on 6 |
| RETRIEVED CONTENT ≠ AUTHORITY | 2 vs 6 |
| STORED MEMORY ≠ TRUSTED INSTRUCTION | 3 vs 6 |
| REQUEST ≠ GRANT | 6 |
| OBSERVE ≠ ALLOW | 2, 3 vs 6 |
| ALLOW ≠ EXECUTION | 6 vs 7 |
| DENY ≠ PROOF OF NON-EXECUTION | 6 vs 7 |
| MISSING EVENT ≠ PREVENTION | 8 vs 9 vs 7 |
| HEC ACCEPTANCE ≠ SEARCHABLE EVIDENCE | 8 vs 9 |
| SPLUNK ≠ ENFORCEMENT | 9 vs 6 |
| IDENTITY CLAIM ≠ AUTHENTICATION | 5 |
| CALLER ID ≠ GRANT | 5 vs 6 |
| AUTHORIZED TOOL ≠ AUTHORIZED GOAL | 4 vs 6 (if goal present) |
| BASELINE ≠ SAFE | 1 + 10 |
| RETEST ≠ UNIVERSAL SECURITY | 10 |
| ANOMALY ≠ INCIDENT | 9 (DET-MCP-001 0 rows) |

---

## Is the eight-plane model sufficient?

Yes, with planes 9–10 explicit. Do not add a “business API” plane until a distinct handler exists. Do not add an “orchestrator” plane until a distinct process exists.

HITL / authentication remain **NOT PROVEN** absences, not planes with events.
