# Splunk KO review — LAB-MEMORY-001 Phase 11C

**Date:** 2026-09-17  
**Purpose:** Knowledge-object review for Phase 11C live Splunk validation.  
**Live Splunk:** RUN (field discovery, completeness, Q-MCP reuse, `Q-MEMORY-CONTEXT-AUTHORITY`, DET-MCP-001).  
**This review does not redesign historical Q-MCP files, DET-MCP-001, or `props.conf`.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search, Search Performance Optimizer (notes only), Field Extraction and CIM Mapping, Knowledge Object Governance. `/spl-validate` headings live in `Q-MEMORY-CONTEXT-AUTHORITY.md`.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MEMORY-CONTEXT-AUTHORITY

TYPE: HUNT

PURPOSE: Learner/SOC reconstruction of persisted-memory write → later recall → trust classification → follow-on authorization for one specimen (two `run.id` values). Persistent as a reusable lab hunt file (not a scheduled saved search). Persistence justified: existing Q-MCP cannot collapse write-run identity with recall CONTEXT-001 and hop-1 CTRL-MCP-001 (Q-MCP is 0 on write runs; Q-MCP-AUTHZ omits `agentsec.memory.*`). Q-RAG-CONTEXT-AUTHORITY is one-run retrieved context and does not answer the unique cross-run question.

SECURITY / OPERATIONAL QUESTION: Which write run persisted this memory, which later recall run loaded it, how was it classified, and did a follow-on tool request after that observation get authorized?

EVIDENCE REQUIRED: Indexed `memory.written` and `memory.recalled` (memory id, SHA-256, provenance, `source_run_id`); CTRL-MEMORY-CONTEXT-001 (`memory_context_trust`, `untrusted_data`, OBSERVE `memory_context_is_data`); optional hop-1 CTRL-MCP-001; optional hop-1 `mcp.started`/`mcp.completed`.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json` (OTLP → collector → HEC).

INDEXED FIELDS VERIFIED:
YES (Phase 11C fieldsummary + collapsed values on fresh A/B/C write+recall)

FIELD CONTRACT:
PASS (`docs/MEMORY_SPLUNK_FIELD_CONTRACT.md`)

CORRELATION CONTRACT:
PASS (`__WRITE_RUN_ID__` + `__RECALL_RUN_ID__`; `source_run_id`; SHA-256 not preview; no `session.id` / `invocation.id`)

SPL CORRECTNESS:
PASS (index+sourcetype+two run.ids+event names; `mvindex(mvdedup(...),0)`; `stats` not join/transaction/map/append; `/spl-validate` headings present)

NO-DATA SEMANTICS:
PASS (zero rows = no indexed write+recall pair; not DENY; not safe; execution observation is corroboration)

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded on 11–16 events per specimen. `earliest=0` is lab-only.

CIM:
NOT APPLICABLE (`agentsec.memory.*` is AgentSec-specific; no honest CIM authorization mapping)

KO DUPLICATION:
NONE among published memory hunts. Five candidate IDs were classified REDUNDANT / REUSED and not published.

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (`docs/PHASE11C_MEMORY_SPLUNK_VALIDATION.md`)

DASHBOARD CONSUMER:
NO (Phase 11D not started)

LIMITATIONS: `derived_authority` is a display helper from a lab reason string. No `allowed_tools` field. Preview is bounded. Handler count remains authoritative for non-execution. `memory.id` is not a unique specimen key.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-WHO / Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED / Q-MCP-AFTER-DENY (reuse, unmodified)

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Existing canonical MCP reconstruction. Not rewritten for memory.

SECURITY / OPERATIONAL QUESTION: Who/agent/tool; what decision; did execution begin; execution after DENY.

EVIDENCE REQUIRED: Indexed control.decision and mcp.* rows.

TELEMETRY SOURCE: same index/sourcetype.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for original MCP questions. Memory trust/id/source_run_id are **not** in these columns.

CORRELATION CONTRACT:
PASS with documented extra CONTEXT-001 rows (empty tool) on **recall** runs. Write runs return 0 rows.

SPL CORRECTNESS:
PASS (unchanged)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE (reuse)

DETECTION READINESS:
NOT APPLICABLE (investigation). Q-MCP-AFTER-DENY remains the hunt form of DET-MCP-001.

LIVE SPLUNK VALIDATION:
PASS on memory A/B/C (recall) and documented 0 on write runs

DASHBOARD CONSUMER:
YES (existing MCP workshops only; no memory Studio)

LIMITATIONS: Extra OBSERVE row; Q-MCP does not reconstruct the write run.

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001

TYPE: DETECTION

PURPOSE: Execution after authorization DENY. Unchanged.

SECURITY / OPERATIONAL QUESTION: After DENY, did `mcp.started` occur for the same run.id + tool?

EVIDENCE REQUIRED: control.decision DENY and later mcp.started.

TELEMETRY SOURCE: same.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for its predicate. Does not answer INV-003.

CORRELATION CONTRACT:
PASS (`run.id` + tool + sequence)

SPL CORRECTNESS:
PASS (unchanged)

NO-DATA SEMANTICS:
PASS (0 rows ≠ safe; 0 rows on ATTACK is correct ALLOW-path silence)

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
READY for its original predicate only. Not a memory detector.

LIVE SPLUNK VALIDATION:
PASS (0 rows A/B/C recall)

DASHBOARD CONSUMER:
NO (disabled saved search)

LIMITATIONS: Silent on overlay ALLOW.

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MEMORY / extra Q-MEMORY-* / Dashboard Studio / props.conf change / CIM mapping / saved search

TYPE: DETECTION / HUNT / DASHBOARD / FIELD EXTRACTION / DATA MODEL / SAVED SEARCH

PURPOSE: Not in Phase 11C scope except as explicit rejects.

SECURITY / OPERATIONAL QUESTION: n/a

EVIDENCE REQUIRED: n/a

TELEMETRY SOURCE: n/a

INDEXED FIELDS VERIFIED:
NO for invented fields (`trusted_memory`, `memory_authorized`, `session.id`)

FIELD CONTRACT:
FAIL if those fields were queried

CORRELATION CONTRACT:
NOT APPLICABLE

SPL CORRECTNESS:
NOT APPLICABLE

NO-DATA SEMANTICS:
NOT APPLICABLE

PERFORMANCE:
NOT APPLICABLE

CIM:
NOT APPLICABLE

KO DUPLICATION:
Would duplicate Q-MEMORY-CONTEXT-AUTHORITY or DET-MCP-001

DETECTION READINESS:
NOT APPLICABLE / BLOCKED (overlay reason REJECT)

LIVE SPLUNK VALIDATION:
NOT RUN (not created)

DASHBOARD CONSUMER:
NO

LIMITATIONS: Overlay reason and AGENT MEMORY NOTE regex are teaching signals.

VERDICT:
REJECT (DET-MEMORY, extra Q-MEMORY files, CIM force-map, scheduled saved search, props.conf change) / DEFER (Studio / Phase 11D)

---

## Recommendation classes

| Item | Class |
|------|-------|
| Publish Q-MEMORY-CONTEXT-AUTHORITY as a token hunt | REQUIRED |
| Reuse Q-MCP and DET-MCP-001 unchanged | REQUIRED |
| Keep `mvindex(mvdedup(...),0)`; do not change props.conf | REQUIRED |
| Do not create DET-MEMORY | REQUIRED |
| Do not create extra Q-MEMORY-* files | REQUIRED |
| Document write-run Q-MCP 0-row limitation | REQUIRED |
| Bind recall `run.id` when reusing Q-MCP | RECOMMENDED |
| Compare ATTACK/RETEST hashes in CLI rather than a join hunt | RECOMMENDED |
| Package as a scheduled saved search | REJECTED |
| Force CIM Malware/IDS/Auth/Web/Change | REJECTED |
| Dashboard Studio `ws_lab_memory_*` | DEFERRED |
| Widen `agentsec_index` macro | REJECTED (not required; hunts hardcode index/sourcetype) |
| Invent `session.id` / `invocation.id` | REJECTED |
