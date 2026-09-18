# Agent memory search contract (LAB-MEMORY-001)

**Status:** Phase 11C **VALIDATED** against live Splunk (2026-09-17).  
**Not:** Dashboard Studio, DET-MEMORY, vector DB, LangChain, A2A.  
**Runtime remains authoritative.** Splunk is the analytical/evidence surface.

Stored SPL: `learning/level_1/LAB-MEMORY-001/searches/`. Tokens: `__WRITE_RUN_ID__` + `__RECALL_RUN_ID__`. Reused Q-MCP queries bind the **recall** `run.id` as `__RUN_ID__`.

Index: `agentsec_telemetry`. Sourcetype: `otel:agentic:json`.

Parents: `docs/MCP_SEARCH_CONTRACT.md`, `docs/MEMORY_SPLUNK_FIELD_CONTRACT.md`, `docs/PHASE11C_MEMORY_SPLUNK_VALIDATION.md`.

---

## Query catalog

| Query ID | Security question | Zero results means |
|----------|-------------------|--------------------|
| **Q-MEMORY-CONTEXT-AUTHORITY** | Which write persisted this memory, which later recall loaded it, how classified, and how was any follow-on authorized? | No indexed write+recall pair for those tokens. Not “safe.” Not DENY. |
| Reused **Q-MCP-WHO** | Which principal/agent/tool? | Extra CONTEXT-001 row with empty method on recall. **0 rows on write runs.** |
| Reused **Q-MCP-AUTHZ** | What decisions were indexed? | Extra OBSERVE row; hop-1 ALLOW/DENY on recall. **0 rows on write runs.** |
| Reused **Q-MCP-TOOL** | Which `mcp.started` events exist? | No indexed start. Not automatically DENY |
| Reused **Q-MCP-EXECUTED** | Did a governed operation begin (per tool)? | Extra empty-tool OBSERVE row on recall |
| Reused **Q-MCP-AFTER-DENY** | MCP event after DENY same run/tool? | **0 = no indexed violation found** |

---

## Candidates not published

| ID | Decision |
|----|----------|
| Q-MEMORY-WRITE | **REDUNDANT** — columns on Q-MEMORY-CONTEXT-AUTHORITY |
| Q-MEMORY-TRUST | **REDUNDANT** — same |
| Q-MEMORY-FINGERPRINT | **SUPPORTED** by indexed hash; **REDUNDANT** as a join hunt. Compare two `recall_hash` values in CLI |
| Q-MEMORY-FOLLOWON | **SUPPORTED BY EXISTING Q-MCP** on the recall run |
| Q-MEMORY-AUTHZ | **SUPPORTED BY EXISTING Q-MCP** on the recall run |

---

## Required output columns (validated)

Q-MEMORY-CONTEXT-AUTHORITY: `write_run_id`, `recall_run_id`, `recall_source_run_id`, `write_recall_linked`, `write_agent`, `recall_agent`, `write_profile`, `recall_profile`, `write_mode`, `recall_mode`, `memory_id`, `write_hash`, `recall_hash`, `fingerprint_survived`, `write_provenance`, `recall_provenance`, `write_preview`, `recall_preview`, `memory_trust`, `memory_decision`, `memory_reason`, `derived_authority`, `followon_tool`, `followon_requested_scope`, `followon_coded_allowed_scope`, `followon_decision`, `followon_reason`, `followon_execution_observation`

`derived_authority` is a display helper (`present` only when follow-on reason contains `memory_derived_authority`). It is not a detector.

`write_recall_linked=linked` only when `recall_source_run_id = write_run_id` and SHA-256 and memory id match.

---

## Semantics

- OBSERVE ≠ ALLOW ≠ DENY
- ALLOW ≠ execution
- `mcp.started` ≠ success
- DENY + no indexed start ≠ independent proof of non-execution
- 0 rows ≠ safe
- provenance ≠ trust
- request ≠ grant
- stored ≠ trusted
- recalled ≠ malicious
- `untrusted_data` ≠ malicious
- Hash is the fingerprint; do not correlate by preview
- Do not invent `session.id` / `invocation.id`
- NORMAL is not SAFE
- INTENTIONALLY VULNERABLE LAB PROFILE is not “memory authorized the tool”
- Writer `run.id` is `write_run_id`. Destination `run.id` is `recall_run_id`. `source_run_id` on recall points at the writer.

---

## SPL quality

Prefer: index, sourcetype, two `run.id` values, event/control types, `stats` / `where` / `eval` / `fields` / `table`, `mvindex(mvdedup(…),0)`.

`Q-MEMORY-CONTEXT-AUTHORITY` uses none of: `join`, `transaction`, `map`, `append`, subsearch fan-out.

`earliest=0` is lab-only.

---

## Detection

DET-MCP-001 reused unchanged. Expected live A/B/C recall = 0. Memory ATTACK is an ALLOW-path lab fail-open.

**DETECTION ANALYZED — NO NEW DETECTOR.** Overlay reason and AGENT MEMORY NOTE regex are **REJECT** as production detectors. No DET-MEMORY file. Suspicious memory evidence is **CONTEXT / HUNT**, not a published detector.
