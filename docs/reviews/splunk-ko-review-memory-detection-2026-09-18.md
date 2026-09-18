# Splunk KO review — memory detection analysis Phase 11D

**Date:** 2026-09-18  
**Purpose:** Knowledge-object review for Phase 11D detection engineering **analysis**.  
**Live Splunk:** NOT RUN as a new ingest. Relies on Phase 11C LIVE field contracts and hunts.  
**This review does not modify validated Q-MEMORY, Q-MCP, DET-MCP-001, or `props.conf`.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Knowledge Object Governance, Field Extraction and CIM Mapping, Alerting and Notable Workflows (to **refuse** a notable), Splunk Search (read-only of existing hunts), Detection engineering gate (unmet for any new detector → do not publish). `/spl-validate` headings remain on the 11C hunt file; SPL was not rewritten.

No lookups, macros, field extractions, tags, event types, data models, alerts, or Studio views were added.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Proposed DET-MEMORY / DET-MEMORY-001

TYPE: DETECTION

PURPOSE: Evaluated, not created. Persistence is **not** justified. Collapsing planes 1–5 into “memory poisoning detected” would unteach INV-003.

SECURITY / OPERATIONAL QUESTION: “Was malicious memory detected?” is rejected. Named states A–H and planes 1–5 are required.

EVIDENCE REQUIRED: Depends on candidate. Unauthorized-execution claim requires a server-owned **grant snapshot**. Instruction-like preview and overlay reason are not sufficient.

TELEMETRY SOURCE: `otel:agentic:json` (schema 1.7.0).

INDEXED FIELDS VERIFIED:
YES for 11C hunt fields; NO for `allowed_tools` / `gen_ai.tool.call.id` / tenant / writer≠reader

FIELD CONTRACT:
FAIL as a detector (`TELEMETRY GAP — QUERY NOT DEFENSIBLE` for “ungranted tool executed after untrusted recall”)

CORRELATION CONTRACT:
FAIL for production “unauthorized” (no grant snapshot). PASS for lab hunt already published (write+recall tokens + `source_run_id` + SHA-256).

SPL CORRECTNESS:
NOT APPLICABLE (no new SPL)

NO-DATA SEMANTICS:
Would fail if zero DET-MCP-001 rows were treated as safe, or if missing `mcp.started` were treated as blocked.

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
Would duplicate `Q-MEMORY-CONTEXT-AUTHORITY` + Q-MCP-* if published as a notable

DETECTION READINESS:
BLOCKED

LIVE SPLUNK VALIDATION:
NOT RUN (no detector to validate)

DASHBOARD CONSUMER:
NO

LIMITATIONS: Overlay reason is lab-only. ATTACK vs RETEST not distinguished by Planes 1–3. Preview is bounded. Hash of a fixture is not current compromise.

VERDICT:
DO NOT PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001 (reuse)

TYPE: DETECTION

PURPOSE: Execution after DENY. Do not broaden into a memory detector.

SECURITY / OPERATIONAL QUESTION: After CTRL-MCP-001 DENY, did `mcp.started` occur for the same run.id + tool?

EVIDENCE REQUIRED: control.decision DENY then later mcp.started (`sequence>deny_sequence`).

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (3E–11C)

FIELD CONTRACT:
PASS for its invariant

CORRELATION CONTRACT:
PASS (`run.id` + tool + sequence)

SPL CORRECTNESS:
PASS (unchanged file; `eventstats` by `run_id, tool`; `where has_deny=1 AND is_started=1 AND sequence>deny_sequence`)

NO-DATA SEMANTICS:
PASS (0 rows on BASELINE / ATTACK / RETEST is correct, not a miss of “memory poisoning”)

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
READY for DENY-then-start only. Packaged disabled.

LIVE SPLUNK VALIDATION:
PASS historically (11C 0/0/0 on recall run IDs). Not re-run in 11D.

DASHBOARD CONSUMER:
Existing workshops only. No memory Studio.

LIMITATIONS: Does not fire on ALLOW overlay. Does not see memory.hash. Silence ≠ SAFE.

VERDICT:
REUSE — DO NOT REWRITE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MEMORY-CONTEXT-AUTHORITY

TYPE: HUNT

PURPOSE: Reconstruct write → later recall → trust classification → follow-on request → authorization → indexed execution observation for one specimen (two `run.id` values). Persistence already justified in 11C. 11D finds **no demonstrated correctness or security defect**.

SECURITY / OPERATIONAL QUESTION: Which write persisted this memory, which later recall loaded it, how classified, and was the follow-on request authorized / observed to execute?

EVIDENCE REQUIRED: Indexed `memory.written` + `memory.recalled` + CONTEXT-001 + optional hop-1 CTRL-MCP-001 + optional hop-1 mcp.*.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (Phase 11C)

FIELD CONTRACT:
PASS (`docs/MEMORY_SPLUNK_FIELD_CONTRACT.md`)

CORRELATION CONTRACT:
PASS (`__WRITE_RUN_ID__` + `__RECALL_RUN_ID__`; `source_run_id`; SHA-256 not preview)

SPL CORRECTNESS:
PASS (no 11D edits). Limitations documented, not rewritten: `derived_authority` lab helper; hop-1 hash ≠ memory hash; missing start ≠ handler proof.

NO-DATA SEMANTICS:
PASS (zero rows = no indexed write+recall pair; not DENY; not safe)

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded in 11C. No join/transaction/map.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE among published memory hunts

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (11C). Not re-run in 11D.

DASHBOARD CONSUMER:
NO (Phase 11E not started)

LIMITATIONS: No `allowed_tools`. `derived_authority` is display-only. Keep-as-is classification: **KEEP AS-IS** + **DOCUMENT LIMITATION**.

VERDICT:
PUBLISH (already). REQUIRED changes: none.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-WHO / Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED / Q-MCP-AFTER-DENY (reuse, unmodified)

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Generic authorization and execution reconstruction on the **recall** run. Extra CONTEXT-001 OBSERVE row is documented, not a defect requiring rewrite. Write runs return 0 Q-MCP rows.

SECURITY / OPERATIONAL QUESTION: Who/agent/tool; what decision; did execution begin; execution after DENY.

EVIDENCE REQUIRED: Indexed control.decision and mcp.* rows.

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS for original MCP questions. Memory trust/id/source_run_id are **not** in these columns.

CORRELATION CONTRACT:
PASS (`run.id` on recall)

SPL CORRECTNESS:
PASS (no 11D edits)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE (Q-MEMORY adds cross-run columns rather than replacing these searches)

DETECTION READINESS:
HUNT / INVESTIGATION ONLY. Q-MCP-AFTER-DENY remains the hunt form of DET-MCP-001.

LIVE SPLUNK VALIDATION:
PASS (11C)

DASHBOARD CONSUMER:
Existing MCP workshops. No memory Studio.

LIMITATIONS: CONTEXT-001 appears as an extra OBSERVE row. Bind recall `run.id`, not write `run.id`.

VERDICT:
REUSE — KEEP AS-IS

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Future ES finding / notable / risk / correlation search for memory

TYPE: DETECTION / ALERT (proposed)

PURPOSE: Design-only. Would represent a high-confidence memory-related **authorization** incident only after the production detection bar is met. Must preserve separate provenance for persistence, recall/trust, authorization, and execution.

SECURITY / OPERATIONAL QUESTION: Unauthorized execution (or DENY-then-start) with write→recall provenance attached — not “memory poisoning language.”

EVIDENCE REQUIRED: Writer run, destination run, SHA-256, OBSERVE, agent identity, requested tool, authorization evidence, execution evidence, control ids. Grant snapshot still missing.

TELEMETRY SOURCE: would remain `otel:agentic:json`

INDEXED FIELDS VERIFIED:
NO for grant snapshot / tool-call id / tenant / writer≠reader

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

LIMITATIONS: Design only. No savedsearch, notable, risk event, finding, investigation, or playbook in Phase 11D. No invented risk score.

VERDICT:
DO NOT PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Macros / CIM / props.conf / extra Q-MEMORY-* / Dashboard Studio / saved search for Q-MEMORY

TYPE: MACRO / FIELD EXTRACTION / HUNT / DASHBOARD / SAVED SEARCH

PURPOSE: Not in Phase 11D scope except as explicit rejects / deferrals.

SECURITY / OPERATIONAL QUESTION: n/a

EVIDENCE REQUIRED: n/a

TELEMETRY SOURCE: n/a

INDEXED FIELDS VERIFIED:
NO for invented fields (`trusted_memory`, `session.id`)

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
NOT APPLICABLE (`agentsec.memory.*` remains AgentSec-specific)

KO DUPLICATION:
Extra Q-MEMORY-* files would duplicate the published hunt

DETECTION READINESS:
NOT APPLICABLE

LIVE SPLUNK VALIDATION:
NOT RUN

DASHBOARD CONSUMER:
NO

LIMITATIONS: `agentsec_index` remains runtime-only. `earliest=0` is lab-only.

VERDICT:
REJECT (extra hunts, CIM force-map, scheduled saved search, props.conf change) / DEFER (Studio / Phase 11E)

---

## Governance

No new saved search, alert, lookup, event type, tag, data model, or Studio view. `agentsec_index` remains runtime-only. CIM remains NOT APPLICABLE.

Recommendations:

| Class | Item |
|-------|------|
| REQUIRED | None |
| RECOMMENDED | Keep `Q-MEMORY-CONTEXT-AUTHORITY` as hunt; keep DET-MCP-001 disabled and narrow; bind Q-MCP to the **recall** `run.id` |
| OPTIONAL | Teaching overlay positive-control (SIMULATED), not indexed |
| DEFERRED | ES finding/risk, grant-snapshot field, `gen_ai.tool.call.id`, identity/tenant fields, behavioral models, Studio (Phase 11E) |
| REJECT | DET-MEMORY, overlay-reason detector, instruction-regex detector, extra Q-MEMORY files, CIM force-map, `session.id` / `invocation.id` |
