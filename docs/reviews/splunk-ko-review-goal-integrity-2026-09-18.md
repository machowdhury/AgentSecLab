# Splunk KO review — LAB-AGENT-GOAL-INTEGRITY-001 Phase 13C

**Date:** 2026-09-18  
**Purpose:** Knowledge-object review for Phase 13C live Splunk validation.  
**Live Splunk:** RUN (field discovery, completeness, Q-MCP reuse, `Q-GOAL-INTEGRITY-AUTHORITY`, DET-MCP-001).  
**This review does not redesign historical Q-MCP files, DET-MCP-001, Q-MCP-DELEGATION, or `props.conf`.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search, Search Performance Optimizer (notes only), Field Extraction and CIM Mapping, Knowledge Object Governance. `/spl-validate` headings live in `Q-GOAL-INTEGRITY-AUTHORITY.md`. Dashboard Studio skills were consulted only for future compatibility; **no dashboard was built**.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-GOAL-INTEGRITY-AUTHORITY

TYPE: HUNT

PURPOSE: Learner/SOC reconstruction of authoritative task → untrusted instruction → proposed action → CTRL-GOAL-INTEGRITY-001 → effective action (bounded MCP preview) → hop-1 CTRL-MCP-001 → indexed execution for one `run.id`. Persistent as a reusable lab hunt file (not a scheduled saved search). Persistence justified: existing Q-MCP cannot table `task.hash`, `instruction.trust`, `goal.proposed`, or bounded instruction/effective-action previews in one row.

SECURITY / OPERATIONAL QUESTION: For this run: what authoritative task was assigned, what untrusted instruction was observed, what task change was proposed, what did CTRL-GOAL-INTEGRITY-001 decide, what became the effective action, what did CTRL-MCP-001 decide, and was execution observed?

EVIDENCE REQUIRED: Indexed CTRL-GOAL-INTEGRITY-001 (task id/hash/provenance, `untrusted_instruction`, proposed action, OBSERVE/DENY, content.hash/preview); hop-1 CTRL-MCP-001 (`lookup_policy`, requested vs coded allowed scope, decision, reason, content.preview); optional hop-1 `mcp.started`/`mcp.completed`/`mcp.failed`.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json` (OTLP → collector → HEC).

INDEXED FIELDS VERIFIED:
YES (Phase 13C field discovery on fresh A/B/C)

FIELD CONTRACT:
PASS (`docs/GOAL_INTEGRITY_SPLUNK_FIELD_CONTRACT.md`)

CORRELATION CONTRACT:
PASS (`__RUN_ID__`; GOAL `task.hash` + GOAL `content.hash` for ATTACK/RETEST; no `session.id` / `gen_ai.tool.call.id`)

SPL CORRECTNESS:
PASS (index+sourcetype+run.id+event names; `mvindex(mvdedup(...),0)`; `eventstats` not join/transaction/map/append/rex; `/spl-validate` headings present)

NO-DATA SEMANTICS:
PASS (zero rows = no indexed CTRL-GOAL-INTEGRITY-001; not DENY; not safe; execution observation is corroboration)

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded on 10 events per specimen. `earliest=0` is lab-only. **LAB MEASURED ONLY.** **LAB VOLUME != PRODUCTION SCALE.**

CIM:
NOT APPLICABLE (agentic task-contract / untrusted-instruction fields; no honest CIM Authentication/Change/IDS mapping)

KO DUPLICATION:
NONE among published goal hunts. Candidate Q-GOAL-TASK / INSTRUCTION / EXECUTED classified REDUNDANT and not published. Does not duplicate Q-MCP-AUTHZ (different columns).

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (`docs/PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md`)

DASHBOARD CONSUMER:
NO (Phase 13D/workshop not started)

LIMITATIONS: Instruction hash / effective action / proposed-change fingerprint are bounded preview, not first-class. Overlay reason is a lab teaching string. Handler count remains authoritative for wrong-goal non-execution. OBSERVE is not ALLOW. MCP ALLOW is not goal authorization.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-WHO / Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED / Q-MCP-AFTER-DENY (reuse, unmodified)

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Existing canonical MCP reconstruction. Not rewritten for goal integrity.

SECURITY / OPERATIONAL QUESTION: Who/agent/tool; what decision; did execution begin; execution after DENY.

EVIDENCE REQUIRED: Indexed control.decision and mcp.* rows.

TELEMETRY SOURCE: same index/sourcetype.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for original MCP questions. `task.hash` / `instruction.trust` / `goal.proposed` are **not** in these columns. Extra GOAL rows with empty MCP fields are expected.

CORRELATION CONTRACT:
PASS with documented extra GOAL-001 rows (WHO tool = proposed action id; extra OBSERVE/DENY on AUTHZ/EXECUTED).

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
PASS on goal A/B/C

DASHBOARD CONSUMER:
YES (existing MCP workshops only; no goal Studio)

LIMITATIONS: Extra GOAL row; Q-MCP-EXECUTED groups by `gen_ai.tool.name` so RETEST DENY and `lookup_policy` start are different tools.

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
PASS for MCP-006. NOT APPLICABLE to GOAL-001.

CORRELATION CONTRACT:
NOT APPLICABLE here

SPL CORRECTNESS:
PASS (unchanged)

NO-DATA SEMANTICS:
PASS (0 rows expected)

PERFORMANCE:
NOT APPLICABLE

CIM:
NOT APPLICABLE

KO DUPLICATION:
Would be semantic corruption if rewritten for CTRL-GOAL-INTEGRITY-001

DETECTION READINESS:
NOT APPLICABLE

LIVE SPLUNK VALIDATION:
NOT APPLICABLE (predicate requires CTRL-DELEGATION-001)

DASHBOARD CONSUMER:
YES (`ws_lab_mcp_006` only)

LIMITATIONS: Must not be overloaded for goal integrity.

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
PASS for its predicate. Does not answer unauthorized-goal / authorized-tool.

CORRELATION CONTRACT:
PASS (`run.id` + tool + sequence). RETEST GOAL DENY tool (`extract_full_policy`) ≠ hop-1 start tool (`lookup_policy`), so 0 rows is correct.

SPL CORRECTNESS:
PASS (unchanged)

NO-DATA SEMANTICS:
PASS (0 rows ≠ safe; 0 rows on ATTACK is correct ALLOW-path silence; 0 rows on RETEST must not be taught as goal DENY then start)

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
READY for its original predicate only. Not a goal detector.

LIVE SPLUNK VALIDATION:
PASS (0 rows A/B/C)

DASHBOARD CONSUMER:
NO (disabled saved search)

LIMITATIONS: Silent on overlay ALLOW. Must not be weakened if someone wants it to fire on goal DENY.

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: props.conf / macros.conf / savedsearches.conf / Studio / CIM mapping / DET-GOAL / extra Q-GOAL-*

TYPE: FIELD EXTRACTION / MACRO / SAVED SEARCH / DASHBOARD / DATA MODEL / DETECTION / HUNT

PURPOSE: Not in Phase 13C scope except as explicit rejects / reuse.

SECURITY / OPERATIONAL QUESTION: n/a

EVIDENCE REQUIRED: n/a

TELEMETRY SOURCE: n/a

INDEXED FIELDS VERIFIED:
NO for invented fields (`session.id`, `trusted_instruction`, `task_authorized`, `goal_authorized`, `allowed_tools`, `agentsec.instruction.hash`)

FIELD CONTRACT:
FAIL if those fields were queried as first-class

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
Would duplicate Q-GOAL-INTEGRITY-AUTHORITY or DET-MCP-001

DETECTION READINESS:
NOT APPLICABLE / BLOCKED (overlay reason REJECT as IOC; AGENT NOTE REJECT as IOC)

LIVE SPLUNK VALIDATION:
NOT RUN (not created)

DASHBOARD CONSUMER:
NO

LIMITATIONS: Overlay reason is teaching vocabulary. `agentsec_index` macro was not required; hunts hardcode index/sourcetype. Multivalue class B does not require a props change.

VERDICT:
REJECT (DET-GOAL, extra Q-GOAL files, CIM force-map, scheduled saved search, props.conf change, widen `agentsec_index`, rex fake first-class hashes) / DEFER (Studio / workshop) / OPTIONAL none

---

## Recommendation classes

| Item | Class |
|------|-------|
| Publish Q-GOAL-INTEGRITY-AUTHORITY as a token hunt | REQUIRED |
| Reuse Q-MCP and DET-MCP-001 unchanged | REQUIRED |
| Keep `mvindex(mvdedup(...),0)`; do not change props.conf | REQUIRED |
| Do not create DET-GOAL | REQUIRED |
| Do not rewrite Q-MCP-DELEGATION | REQUIRED |
| Do not create extra Q-GOAL-* files | REQUIRED |
| Document preview-bounded instruction hash / effective action / proposed fingerprint | REQUIRED |
| Document DET-MCP-001 0/0/0 including RETEST | REQUIRED |
| Compare ATTACK/RETEST hashes in CLI rather than a join hunt | RECOMMENDED |
| Package as a scheduled saved search | REJECTED |
| Force CIM Authentication/Change/Web/IDS/Endpoint | REJECTED |
| Overlay reason as production IOC | REJECTED |
| `AGENT NOTE` as production IOC | REJECTED |
| Dashboard Studio `ws_lab_agent_goal_integrity` | DEFERRED (workshop / later phase) |
| Widen `agentsec_index` macro | REJECTED |
| Invent `session.id` / `trusted_instruction` / `task_authorized` / `allowed_tools` | REJECTED |
| Schema bump for hunt convenience | REJECTED |
| `rex` aliases pretending first-class `agentsec.instruction.hash` | REJECTED |
