# Splunk KO review — governance baseline (process validation)

**Date:** 2026-09-15  
**Purpose:** Validate `.cursor/skills/splunk-ko-review/SKILL.md` against representative existing objects.  
**This review does not redesign the artifacts.** Live Splunk was **NOT RUN** in this governance pass. Prior live status is cited from existing validation docs.

Official skills consulted (read-only mapping): Splunk Search, Search Performance Optimizer, Search and Dashboard Troubleshooter, Field Extraction and CIM Mapping, Knowledge Object Governance, Dashboard / Report / Alert Performance Advisor, Alerting and Notable Workflows.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-AUTHZ

TYPE: INVESTIGATION SEARCH

PURPOSE: Learner/SOC reconstruction of control.decision rows for one `run.id`. Persistent as a reusable lab hunt file (not a scheduled saved search). Persistence justified: reused across MCP-001/003/004/005/006 workshops.

SECURITY / OPERATIONAL QUESTION: What authorization decision was made?

EVIDENCE REQUIRED: Indexed `agentsec.control.decision` with control id, tool, scopes, attempted/executed/outcome.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json` control.decision events.

INDEXED FIELDS VERIFIED:
YES (Phase 3C field contract; revalidated through 7C)

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (`agentsec.run.id` token; one run per search)

SPL CORRECTNESS:
PASS (index+sourcetype+run.id+event.name; `mvindex(mvdedup(...),0)`; no join/transaction/map/append)

NO-DATA SEMANTICS:
PASS (zero rows = no indexed control.decision; not DENY; ERROR is not DENY)

PERFORMANCE:
NOT MEASURED (this pass). Prior live CLI on lab-sized copies: documented VALIDATED.

CIM:
NOT APPLICABLE (`agentsec.control.*` is AgentSec-specific; no honest CIM authorization mapping)

KO DUPLICATION:
NONE (single canonical file; dashboards bind tokens rather than copy SPL)

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
NOT RUN (this pass). Prior: PASS (`docs/PHASE3C_MCP_SPLUNK_VALIDATION.md` and later reuse docs)

DASHBOARD CONSUMER:
YES

LIMITATIONS: Control `executed=false` on ALLOW is expected and is not handler non-execution. MCP-006 emits two control rows (CTRL-DELEGATION-001 then CTRL-MCP-001). Do not collapse them.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-AFTER-DENY

TYPE: HUNT

PURPOSE: Investigation query for DENY then later MCP execution event same run/tool. Persistent hunt file. Not automatically a detection (DET-MCP-001 is the scheduled form).

SECURITY / OPERATIONAL QUESTION: Did an MCP execution event occur after a DENY for the same run/tool?

EVIDENCE REQUIRED: DENY control.decision sequence and later `agentsec.mcp.*` with higher sequence, same run_id and tool.

TELEMETRY SOURCE: Same index/sourcetype; control.decision or mcp.started/completed/failed.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (`run_id` + `tool` + `sequence`)

SPL CORRECTNESS:
PASS (`eventstats` by run_id,tool; `sequence>deny_seq`; no join)

NO-DATA SEMANTICS:
PASS (0 = no indexed violation found; does not independently prove the handler never ran)

PERFORMANCE:
NOT MEASURED (this pass). Prior live: PASS on lab copies.

CIM:
NOT APPLICABLE

KO DUPLICATION:
FOUND (same invariant as DET-MCP-001; hunt vs detection is intentional — hunt is tokenized `__RUN_ID__`, detection is untokenized scheduled window)

DETECTION READINESS:
HUNT ONLY (detector already exists as DET-MCP-001; do not create a second detector)

LIVE SPLUNK VALIDATION:
NOT RUN (this pass). Prior: PASS

DASHBOARD CONSUMER:
YES (DETECT tabs)

LIMITATIONS: Silent on vulnerable ALLOW→execute paths (MCP-005/006 preferred ATTACKs). That silence is correct for this predicate.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001 (`AgentSec - MCP Execution After Authorization Deny`)

TYPE: DETECTION

PURPOSE: Disabled saved search for DENY then later `mcp.started` same run/tool. Persistence justified: one operational detector for that invariant. Not an ES notable.

SECURITY / OPERATIONAL QUESTION: After authorization DENY, did tool execution begin for the same run and tool?

EVIDENCE REQUIRED: Same as Q-MCP-AFTER-DENY but start-only (`mcp.started`).

TELEMETRY SOURCE: `agentsec_telemetry` / `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (`run_id`,`tool`,`sequence>deny_sequence`)

SPL CORRECTNESS:
PASS (matches hunt invariant; scheduled `-24h` to `now`; no `__RUN_ID__` by design)

NO-DATA SEMANTICS:
PASS (0 hits ≠ system is secure; 0 hits ≠ no MCP-005/006 attack)

PERFORMANCE:
NOT MEASURED (this pass). Lab-sized live: 0 rows on preferred specimens MEASURED in 3E–7C.

CIM:
NOT APPLICABLE

KO DUPLICATION:
FOUND (intentional pair with Q-MCP-AFTER-DENY). Placeholders Q-RUN/Q-DENY in the same conf file are unrelated and unvalidated.

DETECTION READINESS:
READY (narrow predicate only). Packaged disabled, `enableSched=0`. Throttle: none (lab). Severity HIGH documented. Positive control: SIMULATED makeresults. Negative specimens: ALLOW paths, ERROR, RETEST DENY with no start.

LIVE SPLUNK VALIDATION:
NOT RUN (this pass). Prior: PASS (`docs/PHASE3E_MCP_DETECTION.md`; 0 rows on MCP-006 A/B/C)

DASHBOARD CONSUMER:
NO (Studio must not enable this saved search; DETECT uses hunt + SIMULATED fixture)

LIMITATIONS: Not a general MCP bypass detector. Not confused-deputy detection. Not result-trust detection.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: `ds_q_delegation` (LAB-MCP-006 Dashboard Studio data source)

TYPE: DASHBOARD DATA SOURCE

PURPOSE: Bind validated Q-MCP-DELEGATION to Hunt token `run_id` for OBSERVE/HUNT/PROVE. Persistence is inside `dashboard.definition.json` / `ws_lab_mcp_006.xml` generated by `scripts/build_lab_mcp_006_dashboard.py`.

SECURITY / OPERATIONAL QUESTION: Same as Q-MCP-DELEGATION (reconstruction for the Hunt run.id).

EVIDENCE REQUIRED: Same as Q-MCP-DELEGATION.

TELEMETRY SOURCE: Same as Q-MCP-DELEGATION; token bind only (`__RUN_ID__` → `"$run_id$"`).

INDEXED FIELDS VERIFIED:
YES (Phase 7C)

FIELD CONTRACT:
PASS (does not invent fields; bind-only)

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS (must remain byte-equal to the hunt file after token substitution)

NO-DATA SEMANTICS:
PASS (Studio `noDataMessage`; empty ≠ DENY / blocked / no attack)

PERFORMANCE:
NOT MEASURED (this pass)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE as a second hunt file; multiple Studio ds.* may bind the same hunt to different tokens (justified).

DETECTION READINESS:
NOT APPLICABLE

LIVE SPLUNK VALIDATION:
NOT RUN (this pass). Prior workshop: OBSERVED populated rows on Phase 7C specimens (`docs/PHASE7D_MCP006_WORKSHOP.md`)

DASHBOARD CONSUMER:
YES

LIMITATIONS: Wide 18-column hunt wraps in Studio. Do not rewrite SPL for display. COMPARE uses markdown cards instead.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-DELEGATION

TYPE: HUNT

PURPOSE: Phase 7C reconstruction of CTRL-DELEGATION-001 vs downstream MCP vs indexed execution. Persistent lab hunt. Not a detector.

SECURITY / OPERATIONAL QUESTION: What did CTRL-DELEGATION-001 decide, for which caller/deputy/tool, which authority source was used, and what downstream MCP / execution were indexed?

EVIDENCE REQUIRED: Hop-0 CTRL-DELEGATION-001, indexed `agentsec.delegation.authority.source`, hop-1 CTRL-MCP-001 when present, mcp.* when present. Grant lists are **not** indexed.

TELEMETRY SOURCE: `agentsec_telemetry` / `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (Phase 7C). `allowed_tools` verified **absent**.

FIELD CONTRACT:
PASS (uses indexed `authority.source`; labels `deputy_not_on_indexed_hop1` rather than inventing hop-1)

CORRELATION CONTRACT:
PASS (`run_id`; one operation per lab run). No `gen_ai.tool.call.id`.

SPL CORRECTNESS:
PASS (`eventstats` by run_id; no join/transaction/map/append)

NO-DATA SEMANTICS:
PASS (`no_indexed_mcp_execution_event` is not independent prevention proof)

PERFORMANCE:
NOT MEASURED (this pass). Prior live CLI: PASS on A/B/C copies.

CIM:
NOT APPLICABLE (delegated vs ambient authority has no honest CIM field)

KO DUPLICATION:
NONE among published hunts. Rejected duplicates documented in catalog.

DETECTION READINESS:
HUNT ONLY (Phase 7C: DETECTION ANALYZED — NO NEW DETECTOR). ATTACK is vulnerable ALLOW→execute, so DET-MCP-001 is correctly silent.

LIVE SPLUNK VALIDATION:
NOT RUN (this pass). Prior: PASS (`docs/MCP006_SPLUNK_VALIDATION.md`)

DASHBOARD CONSUMER:
YES (`ws_lab_mcp_006`)

LIMITATIONS: No indexed `allowed_tools`. RETEST deputy not first-class on hop 1. Runtime handler count remains authoritative for non-execution.

VERDICT:
PUBLISH

---

## Process findings (not artifact redesigns)

| Finding | Class | Disposition |
|---------|-------|-------------|
| Q-RUN / Q-DENY placeholders in `savedsearches.conf` | MEDIUM | Documented unvalidated. Do not use as learner hunts. Do not silently enable. Later review may remove or replace. |
| `` `agentsec_index` `` macro unused by validated Q-* | LOW | Style/governance. Do not rewrite validated SPL to use the macro without revalidation. |
| Duplicate JSON extraction (`mvcount>1`) | HIGH if used for completeness counts | Already mitigated by `dc(_raw)` + `mvdedup`. Do not change `props.conf` in this task. |
| CIM unmapped for `agentsec.*` | CIM NOT APPLICABLE | Honest. Do not force CIM. |
| No data models / lookups / event types | NOT APPLICABLE | Do not invent them to look complete. |
| DET-MCP-001 not bound as `ds.savedsearch` on workshops | NONE (intentional) | Dashboards must not enable the detector. |

No BLOCKER correctness defect found that requires changing validated SPL in this governance pass.
