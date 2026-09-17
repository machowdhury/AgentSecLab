# Splunk KO review — LAB-RAG-001 Phase 10C

**Date:** 2026-09-16  
**Purpose:** Knowledge-object review for Phase 10C live Splunk validation.  
**Live Splunk:** RUN (field discovery, completeness, Q-MCP reuse, `Q-RAG-CONTEXT-AUTHORITY`, DET-MCP-001).  
**This review does not redesign historical Q-MCP files or `props.conf`.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search, Search Performance Optimizer (notes only), Field Extraction and CIM Mapping, Knowledge Object Governance. `/spl-validate` headings live in `Q-RAG-CONTEXT-AUTHORITY.md`.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-RAG-CONTEXT-AUTHORITY

TYPE: HUNT

PURPOSE: Learner/SOC reconstruction of retrieved-context classification plus follow-on authorization for one `run.id`. Persistent as a reusable lab hunt file (not a scheduled saved search). Persistence justified: existing Q-MCP cannot collapse CONTEXT-001 trust/hash/document.id with hop-1 CTRL-MCP-001 without mislabeling (Q-MCP-PARAMS) or missing fields (Q-MCP-AUTHZ). Q-MCP-CATALOG-AUTHORITY and Q-MCP-RESULT-AUTHORITY return 0 rows on these specimens.

SECURITY / OPERATIONAL QUESTION: What retrieved context did this run observe, how was it classified, and did a follow-on tool request after that observation get authorized?

EVIDENCE REQUIRED: Indexed CONTEXT-001 (`rag_context_trust`, `untrusted_data`, `rag.local.fixture`, document id, content hash/preview, OBSERVE `retrieved_context_is_data`); optional hop-1 CTRL-MCP-001; optional hop-1 `mcp.started`/`mcp.completed`.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json` (OTLP → collector → HEC).

INDEXED FIELDS VERIFIED:
YES (Phase 10C fieldsummary + collapsed values on fresh A/B/C)

FIELD CONTRACT:
PASS (`docs/RAG_SPLUNK_FIELD_CONTRACT.md`)

CORRELATION CONTRACT:
PASS (`agentsec.run.id` token; `hop.index` + `sequence`; hash not preview; no `gen_ai.tool.call.id`)

SPL CORRECTNESS:
PASS (index+sourcetype+run.id+event names; `mvindex(mvdedup(...),0)`; no join/transaction/map/append; `/spl-validate` headings present)

NO-DATA SEMANTICS:
PASS (zero rows = no indexed CONTEXT-001; not DENY; not safe; execution observation is corroboration)

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded on 5–10 events. `earliest=0` is lab-only.

CIM:
NOT APPLICABLE (`agentsec.rag.context.*` is AgentSec-specific; no honest CIM authorization mapping)

KO DUPLICATION:
NONE among published RAG hunts. Five candidate IDs were classified REDUNDANT / REUSED and not published.

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (`docs/PHASE10C_RAG_SPLUNK_VALIDATION.md`)

DASHBOARD CONSUMER:
NO (Phase 10D not started)

LIMITATIONS: `derived_authority` is a display helper from a lab reason string. No `allowed_tools` field. Preview is bounded. Handler count remains authoritative for non-execution.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-WHO / Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED / Q-MCP-AFTER-DENY (reuse, unmodified)

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Existing canonical MCP reconstruction. Not rewritten for RAG.

SECURITY / OPERATIONAL QUESTION: Who/agent/tool; what decision; did execution begin; execution after DENY.

EVIDENCE REQUIRED: Indexed control.decision and mcp.* rows.

TELEMETRY SOURCE: same index/sourcetype.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for original MCP questions. RAG trust/provenance/document.id are **not** in these columns.

CORRELATION CONTRACT:
PASS with documented extra CONTEXT-001 rows (empty tool).

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
PASS on RAG A/B/C

DASHBOARD CONSUMER:
YES (existing MCP workshops only; no RAG Studio)

LIMITATIONS: Extra OBSERVE row; Q-MCP-PARAMS mislabels document hash as arguments.

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
PASS for its predicate. Does not answer INV-002.

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
READY for its original predicate only. Not a RAG detector.

LIVE SPLUNK VALIDATION:
PASS (0 rows A/B/C)

DASHBOARD CONSUMER:
NO (disabled saved search)

LIMITATIONS: Silent on overlay ALLOW.

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-RAG / extra Q-RAG-* / Dashboard Studio / props.conf change / CIM mapping

TYPE: DETECTION / HUNT / DASHBOARD / FIELD EXTRACTION / DATA MODEL

PURPOSE: Not in Phase 10C scope except as explicit rejects.

SECURITY / OPERATIONAL QUESTION: n/a

EVIDENCE REQUIRED: n/a

TELEMETRY SOURCE: n/a

INDEXED FIELDS VERIFIED:
NO for invented fields (`trusted_document`, `rag_allowed_tools`)

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
Would duplicate Q-RAG-CONTEXT-AUTHORITY or DET-MCP-001

DETECTION READINESS:
NOT APPLICABLE / BLOCKED (overlay reason REJECT)

LIVE SPLUNK VALIDATION:
NOT RUN (not created)

DASHBOARD CONSUMER:
NO

LIMITATIONS: Overlay reason and AGENT NOTE regex are teaching signals.

VERDICT:
REJECT (DET-RAG, extra Q-RAG files, CIM force-map) / DEFER (Studio / Phase 10D)
