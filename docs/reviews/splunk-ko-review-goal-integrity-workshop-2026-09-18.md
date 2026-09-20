# Splunk KO review — goal-integrity workshop Phase 13E

**Date:** 2026-09-18  
**Purpose:** Knowledge-object review for Phase 13E Dashboard Studio workshop `ws_lab_agent_goal_integrity`.  
**Live Splunk:** bind-only reuse of Phase 13C hunts. No new hunt file. No DET-GOAL.  
**This review does not modify validated Q-GOAL or Q-MCP files.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`):

| Skill / rule | Concrete effect |
|--------------|-----------------|
| `.cursor/rules/33-splunk-agent-skills.mdc` + `splunk-ko-review` | Classify dashboard vs hunt vs detection; persist the Studio view only; keep Q-GOAL-INTEGRITY-AUTHORITY as the published hunt |
| Knowledge Object Governance | Reuse Q-GOAL + Q-MCP; do not persist extra Q-GOAL-* files |
| Field Extraction and CIM Mapping | CIM NOT APPLICABLE; no `trusted_instruction`; no invented session.id |
| Alerting and Notable Workflows | Refuse a notable / DET-GOAL |
| Splunk Search + `spl-validate` | Bind `__RUN_ID__` only; no join / transaction / map / rex aliases |
| Search Performance Optimizer | `earliest=0` remains lab-only; one run.id per hunt token |
| Dashboard Studio | GRID 1440 / 12; markdown + tables; no extra charts |
| `dashboard-studio-review` | Four tokens (Hunt + A/B/C); noDataMessage not SAFE |
| UI Design System + `ui-review` | Palette, large font, empty tables visible, severity in TEXT; two-pass review |
| `build-workshop` | Ten-stage LEARN→PROVE sequence unchanged |
| App packaging (`splunk_app_init.sh`) | Require `ws_lab_agent_goal_integrity.xml` before staging |
| CodeGuard hardcoded-credentials | No secrets in Studio JSON/XML; Splunk auth remains `.env` |

No lookups, macros, field extractions, tags, event types, data models, or alerts were added. `savedsearches.conf` was not changed. `props.conf` was not changed. DET-MCP-001.spl was not changed.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: ws_lab_agent_goal_integrity

TYPE: DASHBOARD

PURPOSE: Learner-facing ten-tab SOC workshop for authorized-tool + unauthorized-goal investigation. Persistence justified: 13C hunts exist; 13D forbade a detector; learners need a visual reconstruction of five evidence planes.

SECURITY / OPERATIONAL QUESTION: What can I prove from the evidence? Not: did Splunk block lookup_policy?

EVIDENCE REQUIRED: Indexed CTRL-GOAL-INTEGRITY-001 + hop-1 CTRL-MCP-001 + optional mcp.*; LIVE 13C A/B/C ids; runtime handler counts taught as runtime-authoritative markdown.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (Phase 13C). OBSERVE sequence is a Studio view of the same indexed fields; not a new hunt file.

FIELD CONTRACT:
PASS for bound hunts. FAIL as a detector for out-of-task use (no first-class effective_action / allowed_tools).

CORRELATION CONTRACT:
PASS (one run.id token; ATTACK/RETEST task hash taught in markdown, not a join)

SPL CORRECTNESS:
PASS (bind tokens only). No join/transaction/map/append/rex on reused hunts.

NO-DATA SEMANTICS:
PASS (“No indexed event matched this evidence question.” Not SAFE / blocked / prevented.)

PERFORMANCE:
NOT MEASURED (production). Lab `earliest=0`. One run.id per hunt.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE among published goal hunts. OBSERVE sequence is a dashboard visualization, not Q-GOAL-SEQUENCE.spl.

DETECTION READINESS:
HUNT / WORKSHOP ONLY. No DET-GOAL.

LIVE SPLUNK VALIDATION:
Hunts PASS (13C). Dashboard rendering: Playwright (`docs/screenshots/lab-agent-goal-integrity/`). Pass-2 OBSERVE/HUNT tables returned the LIVE BASELINE row.

DASHBOARD CONSUMER:
YES (`ws_lab_agent_goal_integrity`)

LIMITATIONS: Token boxes may ellipsize UUIDs; full ids/hashes are on LEARN, COMPARE, and PROVE. Handler count remains authoritative. Studio empty graphic may override noDataMessage (not interpreted as SAFE). Instruction hash / proposed fingerprint remain PARTIALLY SUPPORTED in Splunk.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-GOAL-INTEGRITY-AUTHORITY

TYPE: HUNT

PURPOSE: One-row reconstruction for the 13E HUNT tab. Already VALIDATED in 13C. 13E binds `__RUN_ID__` → Studio tokens only.

SECURITY / OPERATIONAL QUESTION: For this run: what task, instruction trust, proposed goal, goal-integrity decision, MCP grant, and indexed execution were observed?

EVIDENCE REQUIRED: CTRL-GOAL-INTEGRITY-001 + CTRL-MCP-001 + hop-1 mcp.*

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (13C)

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS (unchanged file)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED (production). Lab `earliest=0`.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (13C). 13E Playwright showed the BASELINE bound row.

DASHBOARD CONSUMER:
YES (`ws_lab_agent_goal_integrity`)

LIMITATIONS: Effective action and instruction hash remain preview-bounded. Q-MCP extra GOAL rows are documented, not “fixed” by rewriting Q-MCP.

VERDICT:
PUBLISH / REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-WHO / Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED / Q-MCP-AFTER-DENY

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Reused tool-authorization and execution questions. 13E binds tokens only.

SECURITY / OPERATIONAL QUESTION: Was lookup_policy requested, granted, started, completed? Was there DENY-then-start?

EVIDENCE REQUIRED: Indexed MCP control + mcp.* fields already contracted in LAB-MCP-001.

TELEMETRY SOURCE: same index/sourcetype

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS (MCP). Does not prove task/goal authorization.

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS (files unchanged)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE. Extra GOAL rows when gen_ai.tool.name equals proposed action id are a documented limitation.

DETECTION READINESS:
NOT APPLICABLE (investigation)

LIVE SPLUNK VALIDATION:
PASS (13C reuse). 13E DETECT 0/0/0 tables empty as expected.

DASHBOARD CONSUMER:
YES (`ws_lab_agent_goal_integrity`)

LIMITATIONS: Q-MCP answers tool questions only.

VERDICT:
REUSE WITH DOCUMENTED LIMITATIONS

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001

TYPE: DETECTION

PURPOSE: Unchanged. Execution after authorization DENY for the same run.id + tool.

SECURITY / OPERATIONAL QUESTION: After tool DENY, did mcp.started occur for that tool?

EVIDENCE REQUIRED: DENY then later mcp.started, same run_id + tool

TELEMETRY SOURCE: same

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for its own predicate. NOT a goal-integrity detector.

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS (file unchanged; 13E did not rewrite it)

NO-DATA SEMANTICS:
PASS. LIVE A/B/C = 0/0/0 is CORRECT. 0 rows != SAFE.

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
READY for its own invariant. Not a goal detector.

LIVE SPLUNK VALIDATION:
PASS (13C 0/0/0). 13E DETECT tables empty; SIMULATED makeresults labeled SIMULATED.

DASHBOARD CONSUMER:
YES (hunt form Q-MCP-AFTER-DENY + SIMULATED fixture). Saved search remains disabled.

LIMITATIONS: RETEST goal DENY uses a different gen_ai.tool.name than hop-1 lookup_policy start.

VERDICT:
UNCHANGED

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-GOAL / Q-GOAL-TASK / Q-GOAL-INSTRUCTION / Q-GOAL-EXECUTED / Q-GOAL-DENY / CIM map / props.conf / scheduled saved search

TYPE: DETECTION / HUNT / FIELD EXTRACTION / APP CONFIGURATION (proposed, rejected)

PURPOSE: 13D already rejected these. 13E must not create them.

SECURITY / OPERATIONAL QUESTION: n/a — not created

EVIDENCE REQUIRED: n/a

TELEMETRY SOURCE: n/a

INDEXED FIELDS VERIFIED:
NO for a production out-of-task-use notable (first-class effective_action absent)

FIELD CONTRACT:
FAIL as a detector (13D)

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
FOUND if created (columns already on Q-GOAL-INTEGRITY-AUTHORITY)

DETECTION READINESS:
BLOCKED / HUNT ONLY

LIVE SPLUNK VALIDATION:
NOT RUN (objects not created)

DASHBOARD CONSUMER:
NO

LIMITATIONS: Overlay reason and AGENT NOTE remain REJECT as production signals.

VERDICT:
DO NOT PUBLISH

---

| Decision | Outcome |
|----------|---------|
| Q-GOAL-INTEGRITY-AUTHORITY | PUBLISH / REUSE |
| Q-MCP-* | REUSE WITH DOCUMENTED LIMITATIONS |
| DET-MCP-001 | UNCHANGED |
| DET-GOAL | DO NOT CREATE |
| CIM | NOT APPLICABLE |
| props.conf | NO CHANGE |
| savedsearches.conf | NO NEW DET-GOAL |
| ws_lab_agent_goal_integrity | PUBLISH |
