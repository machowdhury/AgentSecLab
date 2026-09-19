# Splunk KO review — LAB-AGENT-DELEGATION-001 Phase 12C

**Date:** 2026-09-18  
**Purpose:** Knowledge-object review for Phase 12C live Splunk validation.  
**Live Splunk:** RUN (field discovery, completeness, Q-MCP reuse, `Q-AGENT-DELEGATION-AUTHORITY`, DET-MCP-001).  
**This review does not redesign historical Q-MCP files, DET-MCP-001, Q-MCP-DELEGATION, or `props.conf`.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search, Search Performance Optimizer (notes only), Field Extraction and CIM Mapping, Knowledge Object Governance. `/spl-validate` headings live in `Q-AGENT-DELEGATION-AUTHORITY.md`.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-AGENT-DELEGATION-AUTHORITY

TYPE: HUNT

PURPOSE: Learner/SOC reconstruction of an A2A-shaped identity claim → CTRL-IDENTITY-001 OBSERVE → hop-1 CTRL-MCP-001 → indexed execution for one `run.id`. Persistent as a reusable lab hunt file (not a scheduled saved search). Persistence justified: existing Q-MCP cannot table caller vs callee, `claim.trust`, `claimed_scope`, or IDENTITY claim hash. Q-MCP-DELEGATION requires CTRL-DELEGATION-001 and is MCP-006-only.

SECURITY / OPERATIONAL QUESTION: For this run: who called whom, what authority was claimed, what privileged operation was requested, what did CTRL-MCP-001 decide, and was execution observed?

EVIDENCE REQUIRED: Indexed CTRL-IDENTITY-001 (caller, callee, principal, `untrusted_claim`, claimed scope, OBSERVE, content.hash); hop-1 CTRL-MCP-001 (tool, requested vs coded allowed scope, decision, reason); optional hop-1 `mcp.started`/`mcp.completed`/`mcp.failed`.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json` (OTLP → collector → HEC).

INDEXED FIELDS VERIFIED:
YES (Phase 12C field discovery on fresh A/B/C)

FIELD CONTRACT:
PASS (`docs/AGENT_DELEGATION_SPLUNK_FIELD_CONTRACT.md`)

CORRELATION CONTRACT:
PASS (`__RUN_ID__`; IDENTITY `content.hash` for ATTACK/RETEST; no `session.id` / `invocation.id` / `delegation.id`)

SPL CORRECTNESS:
PASS (index+sourcetype+run.id+event names; `mvindex(mvdedup(...),0)`; `eventstats` not join/transaction/map/append; `/spl-validate` headings present)

NO-DATA SEMANTICS:
PASS (zero rows = no indexed CTRL-IDENTITY-001; not DENY; not safe; execution observation is corroboration)

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded on 9–10 events per specimen. `earliest=0` is lab-only. **LAB MEASURED ONLY.**

CIM:
NOT APPLICABLE (agentic identity-claim fields; no honest CIM Authentication mapping)

KO DUPLICATION:
NONE among published identity hunts. Candidate Q-A2A-* IDs were classified REDUNDANT / REUSED and not published. Does not duplicate Q-MCP-DELEGATION (different control).

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (`docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`)

DASHBOARD CONSUMER:
NO (Phase 12E not started)

LIMITATIONS: Privileged hop may lack first-class `agentsec.mcp.resource.id`. No `allowed_tools`. Overlay reason is a lab teaching string. Handler count remains authoritative for non-execution. OBSERVE is not authentication.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-WHO / Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED / Q-MCP-AFTER-DENY (reuse, unmodified)

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Existing canonical MCP reconstruction. Not rewritten for identity.

SECURITY / OPERATIONAL QUESTION: Who/agent/tool; what decision; did execution begin; execution after DENY.

EVIDENCE REQUIRED: Indexed control.decision and mcp.* rows.

TELEMETRY SOURCE: same index/sourcetype.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for original MCP questions. Caller/callee/`claim.trust` are **not** in these columns.

CORRELATION CONTRACT:
PASS with documented extra IDENTITY-001 rows (empty method on WHO; extra OBSERVE on AUTHZ/EXECUTED).

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
PASS on identity A/B/C

DASHBOARD CONSUMER:
YES (existing MCP workshops only; no identity Studio)

LIMITATIONS: Extra OBSERVE row; Q-MCP-WHO agent is callee; Q-MCP-EXECUTED groups by tool.

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-DELEGATION

TYPE: HUNT

PURPOSE: MCP-006 ambient confused-deputy reconstruction. Unchanged.

SECURITY / OPERATIONAL QUESTION: Who requested, who executed with ambient authority, what did CTRL-DELEGATION-001 vs CTRL-MCP-001 decide?

EVIDENCE REQUIRED: CTRL-DELEGATION-001 rows.

TELEMETRY SOURCE: same.

INDEXED FIELDS VERIFIED:
YES (fields exist; this lab does not emit CTRL-DELEGATION-001)

FIELD CONTRACT:
PASS for MCP-006. NOT APPLICABLE to A2A-001.

CORRELATION CONTRACT:
NOT APPLICABLE here

SPL CORRECTNESS:
PASS (unchanged)

NO-DATA SEMANTICS:
PASS (0 rows on A2A-001 ATTACK is correct, not a defect)

PERFORMANCE:
NOT APPLICABLE

CIM:
NOT APPLICABLE

KO DUPLICATION:
Would be semantic corruption if rewritten for CTRL-IDENTITY-001

DETECTION READINESS:
NOT APPLICABLE

LIVE SPLUNK VALIDATION:
PASS as 0 rows (NOT APPLICABLE)

DASHBOARD CONSUMER:
YES (`ws_lab_mcp_006` only)

LIMITATIONS: Must not be overloaded for amplification.

VERDICT:
REUSE (do not rewrite)

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
PASS for its predicate. Does not answer INV-001 amplification.

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
READY for its original predicate only. Not an identity detector.

LIVE SPLUNK VALIDATION:
PASS (0 rows A/B/C)

DASHBOARD CONSUMER:
NO (disabled saved search)

LIMITATIONS: Silent on overlay ALLOW. Does not detect identity claims.

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: props.conf / macros.conf / savedsearches.conf / Studio / CIM mapping / DET-A2A / extra Q-A2A-*

TYPE: FIELD EXTRACTION / MACRO / SAVED SEARCH / DASHBOARD / DATA MODEL / DETECTION / HUNT

PURPOSE: Not in Phase 12C scope except as explicit rejects / reuse.

SECURITY / OPERATIONAL QUESTION: n/a

EVIDENCE REQUIRED: n/a

TELEMETRY SOURCE: n/a

INDEXED FIELDS VERIFIED:
NO for invented fields (`authenticated`, `trusted_identity`, `session.id`, `allowed_tools`)

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
Would duplicate Q-AGENT-DELEGATION-AUTHORITY or DET-MCP-001

DETECTION READINESS:
NOT APPLICABLE / BLOCKED (overlay reason REJECT as IOC; grant snapshot TELEMETRY GAP)

LIVE SPLUNK VALIDATION:
NOT RUN (not created)

DASHBOARD CONSUMER:
NO

LIMITATIONS: Overlay reason is teaching vocabulary. `agentsec_index` macro was not required; hunts hardcode index/sourcetype. Multivalue class B does not require a props change.

VERDICT:
REJECT (DET-A2A, DET-DELEGATION, extra Q-A2A files, CIM force-map, scheduled saved search, props.conf change, widen `agentsec_index`) / DEFER (Studio / Phase 12E) / OPTIONAL none

---

## Recommendation classes

| Item | Class |
|------|-------|
| Publish Q-AGENT-DELEGATION-AUTHORITY as a token hunt | REQUIRED |
| Reuse Q-MCP and DET-MCP-001 unchanged | REQUIRED |
| Keep `mvindex(mvdedup(...),0)`; do not change props.conf | REQUIRED |
| Do not create DET-A2A / DET-DELEGATION | REQUIRED |
| Do not rewrite Q-MCP-DELEGATION | REQUIRED |
| Do not create extra Q-A2A-* files | REQUIRED |
| Document TELEMETRY GAP `allowed_tools` | REQUIRED |
| Document privileged-hop missing `mcp.resource.id` | REQUIRED |
| Compare ATTACK/RETEST IDENTITY hashes in CLI rather than a join hunt | RECOMMENDED |
| Package as a scheduled saved search | REJECTED |
| Force CIM Authentication/Change/Web/IDS/Endpoint | REJECTED |
| Overlay reason as production IOC | REJECTED |
| Dashboard Studio `ws_lab_agent_delegation` | DEFERRED (12E) |
| Widen `agentsec_index` macro | REJECTED |
| Invent `session.id` / `authenticated=true` / `allowed_tools` | REJECTED |
| Schema bump for dashboard convenience | REJECTED |
