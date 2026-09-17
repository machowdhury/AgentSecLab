# Splunk KO review — scanner detection analysis Phase 9D

**Date:** 2026-09-16  
**Purpose:** Knowledge-object review for Phase 9D detection engineering **analysis**.  
**Live Splunk:** NOT RUN as a new ingest. Relies on Phase 9C LIVE field contracts and hunts.  
**This review does not modify validated Q-SCANNER or Q-MCP files.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Knowledge Object Governance, Field Extraction and CIM Mapping, Alerting and Notable Workflows (to **refuse** a notable), Splunk Search (read-only of existing hunts). Detection engineering gate: unmet for any new detector → do not publish.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Proposed DET-SCANNER-* / DET-MCP-CATALOG

TYPE: DETECTION

PURPOSE: Evaluated, not created. Persistence is **not** justified.

SECURITY / OPERATIONAL QUESTION: Collapsed “poisoning” vs named planes 1–3.

EVIDENCE REQUIRED: Depends on candidate; grant snapshot **not indexed**.

TELEMETRY SOURCE: scanner sourcetype + `otel:agentic:json`.

INDEXED FIELDS VERIFIED:
YES for 9C hunt fields; NO for `allowed_tools` / scan-vs-call pin / `gen_ai.tool.call.id`

FIELD CONTRACT:
FAIL as a detector (TELEMETRY GAP — QUERY NOT DEFENSIBLE for unauthorized-execution+scanner)

CORRELATION CONTRACT:
FAIL for production (description hash only). PASS for lab hunt already published.

SPL CORRECTNESS:
NOT APPLICABLE (no new SPL)

NO-DATA SEMANTICS:
Would fail if zero findings were treated as safe

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
Would duplicate Q-SCANNER-FINDINGS + Q-MCP-CATALOG-AUTHORITY if published as a notable

DETECTION READINESS:
BLOCKED

LIVE SPLUNK VALIDATION:
NOT RUN (no detector to validate)

DASHBOARD CONSUMER:
NO

LIMITATIONS: Scanner HIGH ≠ incident. Overlay reason is lab-only. ATTACK vs RETEST not distinguished by Plane 1.

VERDICT:
DO NOT PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001 (reuse)

TYPE: DETECTION

PURPOSE: Execution after DENY. Do not broaden.

SECURITY / OPERATIONAL QUESTION: After CTRL-MCP-001 DENY, did `mcp.started` occur for same run.id + tool?

EVIDENCE REQUIRED: control.decision DENY then later mcp.started.

TELEMETRY SOURCE: `otel:agentic:json`

INDEXED FIELDS VERIFIED:
YES (3E–8D)

FIELD CONTRACT:
PASS for its invariant

CORRELATION CONTRACT:
PASS (`run.id` + tool + sequence)

SPL CORRECTNESS:
PASS (unchanged file)

NO-DATA SEMANTICS:
PASS (0 rows on ATTACK B is correct, not a miss of “poisoning”)

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
READY for DENY-then-start only. Packaged disabled.

LIVE SPLUNK VALIDATION:
PASS historically (8D 0/0/0). Not re-run in 9D.

DASHBOARD CONSUMER:
Existing workshops only

LIMITATIONS: Does not see scanner sourcetype. Does not fire on ALLOW overlay.

VERDICT:
REUSE — DO NOT REWRITE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-SCANNER-* and Q-MCP-CATALOG-AUTHORITY / Q-MCP-AUTHZ / Q-MCP-EXECUTED

TYPE: HUNT / INVESTIGATION SEARCH

PURPOSE: Sufficient for 9D analysis. No cosmetic rewrites.

SECURITY / OPERATIONAL QUESTION: Planes 1–3 reconstruction (already published).

INDEXED FIELDS VERIFIED:
YES (9C / 8D)

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS for lab description hash

SPL CORRECTNESS:
PASS (no 9D edits)

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (9C / 8D)

DASHBOARD CONSUMER:
Catalog workshop for Q-MCP only. No scanner Studio in 9D.

VERDICT:
PUBLISH (already). REQUIRED changes: none. RECOMMENDED: none. OPTIONAL: later scanner workshop. DEFERRED: ES notable, risk, lookups, data models, mixing sourcetypes into Q-MCP-AUTHZ.

---

## Governance

No new saved search, alert, lookup, event type, tag, data model, or Studio view. `agentsec_index` remains runtime-only. CIM remains NOT APPLICABLE.

Recommendations:

| Class | Item |
|-------|------|
| REQUIRED | None |
| RECOMMENDED | Keep scanner evidence as hunts; keep DET-MCP-001 disabled and narrow |
| OPTIONAL | Teaching positive-control for overlay string (SIMULATED), not indexed |
| DEFERRED | ES finding/risk, rug-pull pin, grant-snapshot field, other scanners |
