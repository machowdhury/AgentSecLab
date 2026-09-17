# Splunk KO review — RAG detection analysis Phase 10D

**Date:** 2026-09-16  
**Purpose:** Knowledge-object review for Phase 10D detection engineering **analysis**.  
**Live Splunk:** NOT RUN as a new ingest. Relies on Phase 10C LIVE field contracts and hunts.  
**This review does not modify validated Q-RAG or Q-MCP files.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Knowledge Object Governance, Field Extraction and CIM Mapping, Alerting and Notable Workflows (to **refuse** a notable), Splunk Search (read-only of existing hunts), Detection engineering gate (unmet for any new detector → do not publish). `/spl-validate` headings remain on the 10C hunt file; SPL was not rewritten.

No lookups, macros, field extractions, tags, event types, data models, alerts, or Studio views were added.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Proposed DET-RAG / DET-RAG-001 / DET-MCP-RAG

TYPE: DETECTION

PURPOSE: Evaluated, not created. Persistence is **not** justified. Collapsing planes 1–4 into “RAG poisoned” would unteach INV-002.

SECURITY / OPERATIONAL QUESTION: “Was RAG poisoned?” is rejected. Named states A–J and planes 1–4 are required.

EVIDENCE REQUIRED: Depends on candidate. Unauthorized-execution claim requires a server-owned **grant snapshot**. Instruction-like preview is not sufficient.

TELEMETRY SOURCE: `otel:agentic:json` (schema 1.6.0).

INDEXED FIELDS VERIFIED:
YES for 10C hunt fields; NO for `allowed_tools` / `gen_ai.tool.call.id` / tenant

FIELD CONTRACT:
FAIL as a detector (`TELEMETRY GAP — QUERY NOT DEFENSIBLE` for “ungranted tool executed after untrusted retrieval”)

CORRELATION CONTRACT:
FAIL for production “unauthorized” (no grant snapshot). PASS for lab hunt already published (`run.id` + hop + sequence).

SPL CORRECTNESS:
NOT APPLICABLE (no new SPL)

NO-DATA SEMANTICS:
Would fail if zero DET-MCP-001 rows were treated as safe, or if missing `mcp.started` were treated as blocked.

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
Would duplicate `Q-RAG-CONTEXT-AUTHORITY` + Q-MCP-* if published as a notable

DETECTION READINESS:
BLOCKED

LIVE SPLUNK VALIDATION:
NOT RUN (no detector to validate)

DASHBOARD CONSUMER:
NO

LIMITATIONS: Overlay reason is lab-only. ATTACK vs RETEST not distinguished by Plane 1 or 2. Preview is bounded. Hash of a fixture is not current compromise.

VERDICT:
DO NOT PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001 (reuse)

TYPE: DETECTION

PURPOSE: Execution after DENY. Do not broaden into a RAG detector.

SECURITY / OPERATIONAL QUESTION: After CTRL-MCP-001 DENY, did `mcp.started` occur for the same `run.id` + tool?

EVIDENCE REQUIRED: control.decision DENY then later mcp.started (`sequence>deny_sequence`).

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (3E–10C)

FIELD CONTRACT:
PASS for its invariant

CORRELATION CONTRACT:
PASS (`run.id` + tool + sequence)

SPL CORRECTNESS:
PASS (unchanged file; `eventstats` by `run_id, tool`; `where has_deny=1 AND is_started=1 AND sequence>deny_sequence`)

NO-DATA SEMANTICS:
PASS (0 rows on BASELINE / ATTACK / RETEST is correct, not a miss of “RAG poisoning”)

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
READY for DENY-then-start only. Packaged disabled.

LIVE SPLUNK VALIDATION:
PASS historically (10C 0/0/0). Not re-run in 10D.

DASHBOARD CONSUMER:
Existing workshops only. No RAG Studio.

LIMITATIONS: Does not fire on ALLOW overlay. Does not see document.hash. Silence ≠ SAFE.

VERDICT:
REUSE — DO NOT REWRITE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-RAG-CONTEXT-AUTHORITY

TYPE: HUNT

PURPOSE: Reconstruct retrieval, trust classification, follow-on request, authorization, indexed execution observation for one `run.id`. Persistence already justified in 10C. 10D finds **no demonstrated correctness or security defect**.

SECURITY / OPERATIONAL QUESTION: What was retrieved, how classified, and was the follow-on request authorized / observed to execute?

EVIDENCE REQUIRED: Indexed CONTEXT-001 + optional hop-1 CTRL-MCP-001 + optional hop-1 mcp.*.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (Phase 10C)

FIELD CONTRACT:
PASS (`docs/RAG_SPLUNK_FIELD_CONTRACT.md`)

CORRELATION CONTRACT:
PASS (`run.id`; hop `"1"` for follow-on; document hash from CONTEXT-001 only)

SPL CORRECTNESS:
PASS (no 10D edits). Limitations documented, not rewritten: `derived_authority` lab helper; hop-1 hash ≠ document hash; missing start ≠ handler proof.

NO-DATA SEMANTICS:
PASS (zero rows = no indexed CONTEXT-001; not DENY; not safe)

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded in 10C.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE among published RAG hunts

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (10C). Not re-run in 10D.

DASHBOARD CONSUMER:
NO (Phase 10E not started)

LIMITATIONS: No `allowed_tools`. `derived_authority` is display-only. Keep-as-is classification: **KEEP AS-IS** + **DOCUMENT LIMITATION**.

VERDICT:
PUBLISH (already). REQUIRED changes: none.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-AUTHZ (reuse, unmodified)

TYPE: INVESTIGATION SEARCH

PURPOSE: Plane 3 reconstruction. Extra CONTEXT-001 OBSERVE row is documented, not a defect requiring rewrite.

SECURITY / OPERATIONAL QUESTION: What coded decision was made for each control event?

EVIDENCE REQUIRED: Indexed `agentsec.control.decision`.

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for MCP authorization columns. Does not expose `rag.context.*`.

CORRELATION CONTRACT:
PASS (`run.id`)

SPL CORRECTNESS:
PASS (no 10D edits)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE (Q-RAG adds RAG columns rather than replacing this search)

DETECTION READINESS:
HUNT / INVESTIGATION ONLY

LIVE SPLUNK VALIDATION:
PASS (10C)

DASHBOARD CONSUMER:
Existing MCP workshops. No RAG Studio.

LIMITATIONS: CONTEXT-001 appears as an extra OBSERVE row. Use Q-RAG for document fingerprint.

VERDICT:
PUBLISH (already). KEEP AS-IS.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-TOOL (reuse, unmodified)

TYPE: INVESTIGATION SEARCH

PURPOSE: Tool-name reconstruction. Empty-tool OBSERVE row is documented.

SECURITY / OPERATIONAL QUESTION: Which tool names appear on this run?

EVIDENCE REQUIRED: Indexed `gen_ai.tool.name` where present.

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS (no 10D edits)

NO-DATA SEMANTICS:
PASS (empty tool on CONTEXT-001 is observation, not `lookup_policy`)

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
NOT APPLICABLE (investigation)

LIVE SPLUNK VALIDATION:
PASS (10C)

DASHBOARD CONSUMER:
Existing workshops

LIMITATIONS: Do not treat hop 0 empty tool as a retrieve tool name.

VERDICT:
PUBLISH (already). KEEP AS-IS.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-EXECUTED (reuse, unmodified)

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Plane 4 indexed execution observation.

SECURITY / OPERATIONAL QUESTION: Did `mcp.started` / completed / failed appear for this run?

EVIDENCE REQUIRED: Indexed mcp.* events.

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS as corroboration. Handler counts remain authoritative.

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS (no 10D edits)

NO-DATA SEMANTICS:
PASS (missing start ≠ independent blocked proof)

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (10C)

DASHBOARD CONSUMER:
Existing workshops

LIMITATIONS: `mcp.started` ≠ success. `mcp.failed` ≠ prevention.

VERDICT:
PUBLISH (already). KEEP AS-IS.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-AFTER-DENY (reuse, unmodified)

TYPE: HUNT

PURPOSE: Hunt form of DET-MCP-001’s invariant.

SECURITY / OPERATIONAL QUESTION: After DENY, did execution start?

EVIDENCE REQUIRED: DENY then later mcp.started.

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS (no 10D edits)

NO-DATA SEMANTICS:
PASS (0 rows on A/B/C is correct)

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
FOUND vs DET-MCP-001 (intentional: hunt vs disabled detector)

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (10C 0 rows)

DASHBOARD CONSUMER:
Existing workshops

LIMITATIONS: Same as DET-MCP-001. Do not retarget to RAG documents.

VERDICT:
PUBLISH (already). KEEP AS-IS.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Future ES finding / notable / risk / correlation search for RAG

TYPE: DETECTION / ALERT (proposed)

PURPOSE: Design-only. Would represent a high-confidence RAG-related **authorization** incident only after the production detection bar is met.

SECURITY / OPERATIONAL QUESTION: Unauthorized execution (or DENY-then-start) with retrieval provenance attached — not “prompt injection language.”

EVIDENCE REQUIRED: Retrieval provenance, document fingerprint, agent identity, requested tool, authorization evidence, execution evidence, control ids, run correlation. Grant snapshot still missing.

TELEMETRY SOURCE: would remain `otel:agentic:json`

INDEXED FIELDS VERIFIED:
NO for grant snapshot / tool-call id / tenant

FIELD CONTRACT:
FAIL today (`TELEMETRY GAP — QUERY NOT DEFENSIBLE`)

CORRELATION CONTRACT:
NOT APPLICABLE (not designed as SPL)

SPL CORRECTNESS:
NOT APPLICABLE (no SPL created)

NO-DATA SEMANTICS:
Would need explicit “missing start ≠ blocked”

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
Would duplicate hunts if created now

DETECTION READINESS:
BLOCKED / DEFERRED

LIVE SPLUNK VALIDATION:
NOT RUN

DASHBOARD CONSUMER:
NO

LIMITATIONS: Design only. No savedsearch, notable, risk event, finding, ES detection, or correlation search in Phase 10D.

VERDICT:
DO NOT PUBLISH

---

## Future objects (no SPL)

| Class | Object | Classification |
|-------|--------|----------------|
| Overlay-reason notable | `vulnerable_profile_fail_open:retrieved_context_derived_authority` | **REJECT** |
| AGENT NOTE / instruction regex detector | preview match | **REJECT** |
| Known-hash detector | fixture SHA-256 | **REJECT** as incident; **OPTIONAL** lab CONTEXT |
| Ungranted tool after untrusted retrieval | DET-RAG future | **DEFERRED** until `allowed_tools` indexed |
| Behavioral rare-tool / sequence / burst models | statistical SPL, MLTK, CDTSM | **DEFERRED** |
| ES notable / risk | Finding with planes preserved | **DEFERRED** |
| Dashboard Studio RAG workshop | 10E | **DEFERRED** |
| Extra Q-RAG-TRUST / FINGERPRINT / FOLLOWON files | hunts | **REJECT** (redundant with Q-RAG-CONTEXT-AUTHORITY) |
| Lookups / macros / CIM force-map / data models | packaging | **REJECT** / **DEFERRED** |

---

## Governance

No new saved search, alert, lookup, event type, tag, data model, or Studio view. `agentsec_index` remains runtime-only. CIM remains NOT APPLICABLE.

Recommendations:

| Class | Item |
|-------|------|
| REQUIRED | None |
| RECOMMENDED | Keep `Q-RAG-CONTEXT-AUTHORITY` as hunt; keep DET-MCP-001 disabled and narrow |
| OPTIONAL | Teaching overlay positive-control (SIMULATED), not indexed |
| DEFERRED | ES finding/risk, grant-snapshot field, `gen_ai.tool.call.id`, behavioral models, Studio (Phase 10E) |
| REJECT | DET-RAG, overlay-reason detector, instruction-regex detector, extra Q-RAG files, CIM force-map |
