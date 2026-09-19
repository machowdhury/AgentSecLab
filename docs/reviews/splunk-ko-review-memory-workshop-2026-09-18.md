# Splunk KO review — memory workshop Phase 11E

**Date:** 2026-09-18  
**Purpose:** Knowledge-object review for Phase 11E Dashboard Studio workshop `ws_lab_memory_security`.  
**Live Splunk:** bind-only reuse of Phase 11C hunts. No new hunt file. No DET-MEMORY.  
**This review does not modify validated Q-MEMORY or Q-MCP files.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`):

| Skill / rule | Concrete effect |
|--------------|-----------------|
| `.cursor/rules/33-splunk-agent-skills.mdc` + `splunk-ko-review` | Classify dashboard vs hunt vs detection; persist the Studio view only; keep Q-MEMORY as the published hunt |
| Knowledge Object Governance | Reuse Q-MEMORY + Q-MCP; do not persist extra Q-MEMORY-* files |
| Field Extraction and CIM Mapping | CIM NOT APPLICABLE; no `trusted_memory`; no invented session.id |
| Alerting and Notable Workflows | Refuse a notable / DET-MEMORY |
| Splunk Search + `spl-validate` | Bind `__WRITE_RUN_ID__` / `__RECALL_RUN_ID__` / `__RUN_ID__` only; no join / transaction / map |
| Search Performance Optimizer | `earliest=0` remains lab-only; one write+recall pair per hunt token |
| Dashboard Studio (`30-splunk-dashboard-studio.mdc`) | GRID 1440 / 12; markdown + tables; no extra charts |
| `dashboard-studio-review` | Eight tokens (write+recall hunt pair plus six specimens); noDataMessage not SAFE |
| UI Design System (`32-ui-design-system.mdc`) + `ui-review` | Palette, large font, empty tables visible, severity in TEXT; two-pass review written before HIGH fixes |
| `build-workshop` | Ten-stage LEARN→PROVE sequence unchanged; memory PATH distinct from RAG |
| App packaging (`splunk_app_init.sh`) | Require `ws_lab_memory_security.xml` before staging |
| CodeGuard hardcoded-credentials | No secrets in Studio JSON/XML; Splunk auth remains `.env` |

No lookups, macros, field extractions, tags, event types, data models, or alerts were added. `savedsearches.conf` was not changed. `props.conf` was not changed.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: ws_lab_memory_security

TYPE: DASHBOARD

PURPOSE: Learner-facing ten-tab SOC workshop for persistent-memory investigation. Persistence justified: 11C hunts exist; 11D forbade a detector; learners need a visual reconstruction of five evidence planes across two runs.

SECURITY / OPERATIONAL QUESTION: What can I prove from the evidence? Not: was malicious memory detected?

EVIDENCE REQUIRED: Indexed memory.written + memory.recalled + CONTEXT-001 + hop-1 CTRL-MCP-001 + optional mcp.*; LIVE 11C write+recall ids.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (Phase 11C). OBSERVE sequences are Studio views of the same indexed fields; not new hunt files.

FIELD CONTRACT:
PASS for bound hunts. FAIL as a detector for unauthorized execution (no `allowed_tools`).

CORRELATION CONTRACT:
PASS (write + recall tokens; `source_run_id`; ATTACK/RETEST hash taught in markdown, not a join)

SPL CORRECTNESS:
PASS (bind tokens only). No join/transaction/map/append on reused hunts.

NO-DATA SEMANTICS:
PASS (“No indexed event matched this evidence question.” Not SAFE / blocked / prevented.)

PERFORMANCE:
NOT MEASURED (production). Lab `earliest=0`. One write+recall pair per hunt.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE among published memory hunts. OBSERVE sequences are dashboard visualizations, not Q-MEMORY-SEQUENCE.spl.

DETECTION READINESS:
HUNT / WORKSHOP ONLY. No DET-MEMORY.

LIVE SPLUNK VALIDATION:
Hunts PASS (11C). Dashboard rendering: Playwright (`docs/screenshots/lab-memory-security/`).

DASHBOARD CONSUMER:
YES (`ws_lab_memory_security`)

LIMITATIONS: Eight token controls (Hunt is a write+recall pair). Token boxes may ellipsize UUIDs; full ids/hashes are on LEARN, COMPARE, and PROVE. Handler count remains authoritative. Studio empty graphic may override noDataMessage (not interpreted as SAFE).

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MEMORY-CONTEXT-AUTHORITY (reuse)

TYPE: HUNT

PURPOSE: Primary memory reconstruction. Unchanged from 11C. KEEP AS-IS.

SECURITY / OPERATIONAL QUESTION: Which write persisted this memory, which later recall loaded it, how classified, and was the follow-on authorized / observed to execute?

EVIDENCE REQUIRED: Indexed write+recall pair.

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (11C)

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (`__WRITE_RUN_ID__` + `__RECALL_RUN_ID__`)

SPL CORRECTNESS:
PASS (no 11E edits)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (11C)

DASHBOARD CONSUMER:
YES (`ws_lab_memory_security`)

LIMITATIONS: `derived_authority` lab helper. Missing start ≠ handler proof.

VERDICT:
REUSE — KEEP AS-IS

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-* / DET-MCP-001 (reuse)

TYPE: INVESTIGATION SEARCH / DETECTION

PURPOSE: Authorization and execution on the **recall** run. DET-MCP-001 unchanged and disabled.

SECURITY / OPERATIONAL QUESTION: Unchanged from MCP-001.

EVIDENCE REQUIRED: control.decision / mcp.* on recall `run.id`

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for original questions

CORRELATION CONTRACT:
PASS (`run.id` on recall)

SPL CORRECTNESS:
PASS (no 11E edits)

NO-DATA SEMANTICS:
PASS (0 DET-MCP-001 rows is CORRECT BEHAVIOR)

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
DET-MCP-001 READY for DENY-then-start only. Packaged disabled.

LIVE SPLUNK VALIDATION:
PASS historically (11C 0/0/0)

DASHBOARD CONSUMER:
YES (recall tokens). SIMULATED positive-control is makeresults.

LIMITATIONS: Bind recall, not write. Silence ≠ SAFE. No DET-MEMORY.

VERDICT:
REUSE — DO NOT REWRITE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Proposed DET-MEMORY / extra Q-MEMORY-* / CIM / savedsearch

TYPE: DETECTION / HUNT / FIELD EXTRACTION / SAVED SEARCH

PURPOSE: Explicitly rejected in 11D; 11E does not create them for presentation convenience.

SECURITY / OPERATIONAL QUESTION: n/a

EVIDENCE REQUIRED: n/a

TELEMETRY SOURCE: n/a

INDEXED FIELDS VERIFIED:
NO for invented fields

FIELD CONTRACT:
FAIL if queried

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
Would duplicate the published hunt

DETECTION READINESS:
BLOCKED (11D)

LIVE SPLUNK VALIDATION:
NOT RUN

DASHBOARD CONSUMER:
NO

LIMITATIONS: Overlay reason and AGENT MEMORY NOTE remain REJECT.

VERDICT:
DO NOT PUBLISH / REJECT

---

## Governance

| Class | Item |
|-------|------|
| REQUIRED | None beyond publishing the Studio view |
| RECOMMENDED | Bind Q-MCP to recall `run.id`; keep DET-MCP-001 disabled |
| OPTIONAL | SIMULATED DET-MCP-001 positive-control table |
| DEFERRED | ES finding, grant snapshot, identity/tenant, ML, Studio extras |
| REJECT | DET-MEMORY, extra Q-MEMORY files, CIM force-map, scheduled saved search, props.conf change |
