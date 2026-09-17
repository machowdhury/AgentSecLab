# RAG retrieved-context search contract (LAB-RAG-001)

**Status:** Phase 10C **VALIDATED** against live Splunk (2026-09-16).  
**Not:** Dashboard Studio, DET-RAG, embeddings, scanners.  
**Runtime remains authoritative.** Splunk is the analytical/evidence surface.

Stored SPL: `learning/level_1/LAB-RAG-CONTEXT/searches/`. Token: `__RUN_ID__`.

Index: `agentsec_telemetry`. Sourcetype: `otel:agentic:json`.

Parents: `docs/MCP_SEARCH_CONTRACT.md`, `docs/RAG_SPLUNK_FIELD_CONTRACT.md`, `docs/PHASE10C_RAG_SPLUNK_VALIDATION.md`.

---

## Query catalog

| Query ID | Security question | Zero results means |
|----------|-------------------|--------------------|
| **Q-RAG-CONTEXT-AUTHORITY** | What retrieved context was observed, how classified, and how was any follow-on authorized? | No indexed CONTEXT-001 for that `run.id`. Not “safe.” Not DENY. |
| Reused **Q-MCP-WHO** | Which principal/agent/tool? | Extra CONTEXT-001 row with empty method |
| Reused **Q-MCP-AUTHZ** | What decisions were indexed? | Extra OBSERVE row; hop-1 ALLOW/DENY |
| Reused **Q-MCP-TOOL** | Which `mcp.started` events exist? | No indexed start. Not automatically DENY |
| Reused **Q-MCP-EXECUTED** | Did a governed operation begin (per tool)? | Extra empty-tool OBSERVE row |
| Reused **Q-MCP-AFTER-DENY** | MCP event after DENY same run/tool? | **0 = no indexed violation found** |

---

## Candidates not published

| ID | Decision |
|----|----------|
| Q-RAG-CONTEXT | **REDUNDANT** — columns on Q-RAG-CONTEXT-AUTHORITY |
| Q-RAG-TRUST | **REDUNDANT** — same |
| Q-RAG-FINGERPRINT | **SUPPORTED** by indexed hash; **REDUNDANT** as a join hunt. Compare two `context_hash` values in CLI |
| Q-RAG-FOLLOWON | **SUPPORTED BY EXISTING Q-MCP** |
| Q-RAG-AUTHZ | **SUPPORTED BY EXISTING Q-MCP** |

---

## Required output columns (validated)

Q-RAG-CONTEXT-AUTHORITY: `run_id`, `profile`, `mode`, `context_trust`, `context_provenance`, `context_document_id`, `context_hash`, `context_preview`, `context_decision`, `context_reason`, `derived_authority`, `followon_tool`, `followon_requested_scope`, `followon_coded_allowed_scope`, `followon_decision`, `followon_reason`, `followon_execution_observation`

`derived_authority` is a display helper (`present` only when follow-on reason contains `retrieved_context_derived_authority`). It is not a detector.

---

## Semantics

- OBSERVE ≠ ALLOW ≠ DENY
- ALLOW ≠ execution
- `mcp.started` ≠ success
- DENY + no indexed start ≠ independent proof of non-execution
- 0 rows ≠ safe
- provenance ≠ trust
- request ≠ grant
- Hash is the fingerprint; do not correlate by preview
- Do not invent `gen_ai.tool.call.id`
- NORMAL is not SAFE
- INTENTIONALLY VULNERABLE LAB PROFILE is not “the document authorized the tool”

---

## SPL quality

Prefer: index, sourcetype, `run.id`, event/control types, `stats` / `eventstats` / `where` / `eval` / `fields` / `table`, `mvindex(mvdedup(…),0)`.

`Q-RAG-CONTEXT-AUTHORITY` uses none of: `join`, `transaction`, `map`, `append`, subsearch fan-out.

`earliest=0` is lab-only.

---

## Detection

DET-MCP-001 reused unchanged. Expected live A/B/C = 0. RAG ATTACK is an ALLOW-path lab fail-open.

**DETECTION ANALYZED — NO NEW DETECTOR.** Overlay reason and AGENT NOTE regex are **REJECT** as production detectors. No DET-RAG file.
