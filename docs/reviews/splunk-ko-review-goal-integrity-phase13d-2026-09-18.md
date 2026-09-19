# Splunk KO review — goal integrity Phase 13D (detection analysis + workshop design)

**Date:** 2026-09-18  
**Purpose:** Knowledge-object review for Phase 13D **analysis/design**. No new ingest. Relies on Phase 13C LIVE field contracts and hunts.  
**This review does not modify validated Q-GOAL, Q-MCP, DET-MCP-001, or `props.conf`.** No Studio XML.

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Knowledge Object Governance, Field Extraction and CIM Mapping, Alerting and Notable Workflows (to **refuse** a notable), Splunk Search (read-only of existing hunts), Search Performance Optimizer (notes only; no rewrite), Dashboard Studio compatibility (design contract only; **not built**). `/spl-validate` headings remain on the 13C hunt file. `/ui-review` is **DEFERRED** to 13E (no view to review). `/build-workshop` checklist used for the design document only.

No lookups, macros, field extractions, tags, event types, data models, alerts, or Studio views were added.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Proposed DET-GOAL / DET-GOAL-001

TYPE: DETECTION

PURPOSE: Evaluated, not created. Persistence is **not** justified. Collapsing planes 1–5 into “goal hijack detected” would unteach TOOL AUTHORITY != TASK AUTHORITY.

SECURITY / OPERATIONAL QUESTION: “Was the goal hijacked?” is rejected as underspecified. Named planes 1–5 are required.

EVIDENCE REQUIRED: Unauthorized-use claim needs first-class effective action + permitted-action taxonomy. Overlay reason and `AGENT NOTE` are not sufficient.

TELEMETRY SOURCE: `otel:agentic:json` (schema 1.9.0).

INDEXED FIELDS VERIFIED:
YES for 13C hunt fields; NO for `agentsec.goal.effective` / `agentsec.task.action` / `allowed_tools` as first-class names

FIELD CONTRACT:
FAIL as a detector (`TELEMETRY GAP — QUERY NOT DEFENSIBLE` for general “authorized tool used for unauthorized goal”)

CORRELATION CONTRACT:
FAIL for production “unauthorized use.” PASS for the lab hunt already published (`run.id` + task.hash + goal.proposed).

SPL CORRECTNESS:
NOT APPLICABLE (no new SPL)

NO-DATA SEMANTICS:
Would fail if zero DET-MCP-001 rows were treated as safe, or if goal DENY were treated as tool DENY.

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
Would duplicate `Q-GOAL-INTEGRITY-AUTHORITY` + Q-MCP-* if published as a notable

DETECTION READINESS:
BLOCKED

LIVE SPLUNK VALIDATION:
NOT RUN (no detector to validate)

DASHBOARD CONSUMER:
NO (13E not started)

LIMITATIONS: Overlay is lab-only. ATTACK vs RETEST share proposal. Preview-bounded effective action. Three specimens ≠ production population.

VERDICT:
DO NOT PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-GOAL-INTEGRITY-AUTHORITY (reuse)

TYPE: HUNT

PURPOSE: One-row reconstruction for 13E HUNT tab. Already VALIDATED in 13C.

SECURITY / OPERATIONAL QUESTION: Task → instruction → proposed → goal decision → effective action (preview) → MCP → execution.

EVIDENCE REQUIRED: Indexed GOAL + MCP control hops + optional mcp.*

TELEMETRY SOURCE: same

INDEXED FIELDS VERIFIED:
YES (13C)

FIELD CONTRACT:
PASS for the hunt; PARTIAL for first-class effective action

CORRELATION CONTRACT:
PASS (`__RUN_ID__`)

SPL CORRECTNESS:
PASS (unchanged; no join/transaction/map/append/rex)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED (production). Lab MEASURED on ~10 events. **LAB VOLUME != PRODUCTION SCALE.**

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE. Extra Q-GOAL-* REJECTED.

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (13C; not re-run in 13D)

DASHBOARD CONSUMER:
DESIGNED for 13E; **NO** view yet

LIMITATIONS: Preview-bounded hashes. Handler counts runtime.

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-WHO / AUTHZ / TOOL / EXECUTED / AFTER-DENY (reuse)

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Unchanged. 13E may bind them with documented GOAL extra-row limitations.

VERDICT:
REUSE (do not rewrite)

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001 (reuse)

TYPE: DETECTION

PURPOSE: Execution after tool DENY. Do not broaden into a goal detector.

SECURITY / OPERATIONAL QUESTION: After CTRL-MCP-001 DENY, did `mcp.started` occur for the same run.id + tool?

EVIDENCE REQUIRED: control.decision DENY then later mcp.started.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for its predicate. Does not answer unauthorized-goal.

CORRELATION CONTRACT:
PASS (`run.id` + tool). RETEST GOAL DENY tool ≠ hop-1 start tool.

SPL CORRECTNESS:
PASS (unchanged)

NO-DATA SEMANTICS:
PASS (0/0/0 is CORRECT, not SAFE)

DETECTION READINESS:
READY for original predicate only

LIVE SPLUNK VALIDATION:
PASS (13C 0/0/0)

DASHBOARD CONSUMER:
DESIGNED (DETECT tab); SIMULATED MCP positive control must stay labeled SIMULATED

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Proposed `ws_lab_agent_goal_integrity` / extra Q-GOAL-* / CIM map / props.conf / scheduled saved search

TYPE: DASHBOARD / HUNT / DATA MODEL / FIELD EXTRACTION / SAVED SEARCH

PURPOSE: Studio is the 13E consumer. 13D designs only.

INDEXED FIELDS VERIFIED:
N/A for unimplemented view

DETECTION READINESS:
NOT APPLICABLE

DASHBOARD CONSUMER:
DEFERRED (13E)

VERDICT:
DEFER (Studio) / REJECT (DET-GOAL, extra Q-GOAL files, CIM force-map, props change, overlay/`AGENT NOTE` IOC, scheduled hunt)

---

## Recommendation classes

| Item | Class |
|------|-------|
| Keep DETECTION ANALYZED — NO NEW DETECTOR | REQUIRED |
| Reuse Q-GOAL-INTEGRITY-AUTHORITY in 13E | REQUIRED |
| Reuse Q-MCP + DET-MCP-001 unchanged | REQUIRED |
| Do not create DET-GOAL | REQUIRED |
| Do not rewrite Q-MCP for extra GOAL rows | REQUIRED |
| Teach 0/0/0 as correct, not SAFE | REQUIRED |
| Document preview-bounded effective action | REQUIRED |
| Five-plane OBSERVE layout in 13E | REQUIRED |
| First-canvas five statements | REQUIRED |
| SIMULATED MCP positive control labeled SIMULATED | REQUIRED |
| Implement Studio in 13D | REJECTED |
| Extra Q-GOAL-TASK/INSTRUCTION/EXECUTED/DENY | REJECTED |
| Overlay / AGENT NOTE as IOC | REJECTED |
| CIM force-map | REJECTED |
| Production performance claim | REJECTED |
| ML/MLTK in 13D/13E DETECT as authority | REJECTED |
| Behavioral analytics panel | DEFERRED (FUTURE copy only in 13E) |
| `/ui-review` of a live view | DEFERRED (13E) |
