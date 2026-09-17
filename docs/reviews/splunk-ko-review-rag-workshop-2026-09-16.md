# Splunk KO review — RAG workshop Phase 10E

**Date:** 2026-09-16  
**Purpose:** Knowledge-object review for Phase 10E Dashboard Studio workshop `ws_lab_rag_context`.  
**Live Splunk:** bind-only reuse of Phase 10C hunts. No new hunt file. No DET-RAG.  
**This review does not modify validated Q-RAG or Q-MCP files.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Knowledge Object Governance, Field Extraction and CIM Mapping, Alerting and Notable Workflows (to refuse a notable), Splunk Search (bind-only), Dashboard (Studio GRID consumer).

No lookups, macros, field extractions, tags, event types, data models, or alerts were added. `savedsearches.conf` was not changed.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: ws_lab_rag_context

TYPE: DASHBOARD

PURPOSE: Learner-facing ten-tab SOC workshop for retrieved-context investigation. Persistence justified: 10C hunts exist; 10D forbade a detector; learners need a visual reconstruction of four evidence planes.

SECURITY / OPERATIONAL QUESTION: What can I prove from the evidence? Not: did the RAG attack happen?

EVIDENCE REQUIRED: Indexed CONTEXT-001 + hop-1 CTRL-MCP-001 + optional mcp.* ; LIVE 10C run ids.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (Phase 10C). OBSERVE sequence Studio query uses the same indexed fields; it is not a new hunt file.

FIELD CONTRACT:
PASS for bound hunts. FAIL as a detector for unauthorized execution (no `allowed_tools`).

CORRELATION CONTRACT:
PASS (`run.id` tokens; ATTACK/RETEST hash taught in markdown, not a join)

SPL CORRECTNESS:
PASS (bind `__RUN_ID__` only). No join/transaction/map/append on reused hunts.

NO-DATA SEMANTICS:
PASS (“No indexed event matched this evidence question.” Not SAFE / blocked / prevented.)

PERFORMANCE:
NOT MEASURED (production). Lab `earliest=0`. One run.id per token.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE among published RAG hunts. OBSERVE sequence is a dashboard visualization of indexed fields, not Q-RAG-SEQUENCE.spl.

DETECTION READINESS:
HUNT / WORKSHOP ONLY. No DET-RAG.

LIVE SPLUNK VALIDATION:
Hunts PASS (10C). Dashboard rendering PASS (Playwright 10/10 tabs, 4/4 LIVE tokens, 2026-09-16).

DASHBOARD CONSUMER:
YES (`ws_lab_rag_context`)

LIMITATIONS: Token boxes may ellipsize UUIDs; full ids/hashes are on LEARN, ATTACK, RETEST, COMPARE, and PROVE. Handler count remains authoritative. Studio empty graphic may override noDataMessage (not interpreted as SAFE).

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-RAG-CONTEXT-AUTHORITY (reuse)

TYPE: HUNT

PURPOSE: Primary RAG reconstruction. Unchanged.

SECURITY / OPERATIONAL QUESTION: What retrieved context did this run observe, and was the follow-on authorized?

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS (no 10E edits)

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (10C)

DASHBOARD CONSUMER:
YES

VERDICT:
PUBLISH / REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-WHO / Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED / Q-MCP-AFTER-DENY

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Reuse. Not rewritten.

VERDICT:
REUSE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001

TYPE: DETECTION

PURPOSE: Unchanged. Packaged disabled. Workshop binds hunt + SIMULATED positive-control only.

VERDICT:
UNCHANGED

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-RAG / Q-RAG-INJECTION / Q-RAG-MALICIOUS / Q-RAG-POISONED

TYPE: DETECTION / HUNT

PURPOSE: Evaluated in 10D. Not created.

VERDICT:
DO NOT CREATE

---

## Governance

| Class | Item |
|-------|------|
| REQUIRED | None |
| RECOMMENDED | Keep DET-MCP-001 disabled and narrow; keep Q-RAG as hunt |
| OPTIONAL | SIMULATED DET-MCP-001 positive-control (already bound) |
| DEFERRED | ES notable, grant-snapshot field, MLTK/CDTSM |
| REJECT | DET-RAG, overlay-reason detector, instruction-regex detector, extra Q-RAG files, CIM force-map |
