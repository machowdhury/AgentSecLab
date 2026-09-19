# Splunk KO review — LAB-MCP-CATALOG Phase 8D

**Date:** 2026-09-16  
**Purpose:** Knowledge-object review for Phase 8D live Splunk validation.  
**Live Splunk:** RUN (field discovery, completeness, Q-MCP reuse, `Q-MCP-CATALOG-AUTHORITY`, DET-MCP-001).  
**This review does not redesign historical Q-MCP files or `props.conf`.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search, Search Performance Optimizer (notes only), Field Extraction and CIM Mapping, Knowledge Object Governance. `/spl-validate` headings live in `Q-MCP-CATALOG-AUTHORITY.md`.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-CATALOG-AUTHORITY

TYPE: HUNT

PURPOSE: Learner/SOC reconstruction of catalog metadata classification plus follow-on authorization for one `run.id`. Persistent as a reusable lab hunt file (not a scheduled saved search). Persistence justified: existing Q-MCP cannot collapse METADATA-001 trust/hash with hop-1 CTRL-MCP-001 without mislabeling (Q-MCP-PARAMS) or missing fields (Q-MCP-AUTHZ). Q-MCP-RESULT-AUTHORITY returns 0 rows on these specimens.

SECURITY / OPERATIONAL QUESTION: What catalog metadata did this run observe, how was it classified, and did a follow-on tool request after that observation get authorized?

EVIDENCE REQUIRED: Indexed METADATA-001 (`mcp_metadata_trust`, `untrusted_data`, `mcp.catalog.snapshot`, content hash/preview, OBSERVE `metadata_is_data`); hop-0 CTRL-MCP-001; optional hop-1 CTRL-MCP-001; optional hop-1 `mcp.started`/`mcp.completed`.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=otel:agentic:json` (OTLP → collector → HEC).

INDEXED FIELDS VERIFIED:
YES (Phase 8D fieldsummary + collapsed values on fresh A/B/C)

FIELD CONTRACT:
PASS (`docs/MCP_CATALOG_SPLUNK_FIELD_CONTRACT.md`)

CORRELATION CONTRACT:
PASS (`agentsec.run.id` token; `hop.index` + `sequence`; hash not preview; no `gen_ai.tool.call.id`)

SPL CORRECTNESS:
PASS (index+sourcetype+run.id+event names; `mvindex(mvdedup(...),0)`; no join/transaction/map/append; `/spl-validate` headings present)

NO-DATA SEMANTICS:
PASS (zero rows = no indexed METADATA-001; not DENY; not safe; execution observation is corroboration)

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded on 8–13 events. `earliest=0` is lab-only.

CIM:
NOT APPLICABLE (`agentsec.mcp.metadata.*` is AgentSec-specific; no honest CIM authorization mapping)

KO DUPLICATION:
NONE among published catalog hunts. Five candidate IDs were classified REDUNDANT / REUSED / BLOCKED and not published.

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (`docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md`)

DASHBOARD CONSUMER:
NO (Phase 8E not started)

LIMITATIONS: `derived_authority` is a display helper from a lab reason string. No `allowed_tools` field. Preview is bounded. Handler count remains authoritative for non-execution.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-AUTHZ (reuse, unmodified)

TYPE: INVESTIGATION SEARCH

PURPOSE: Existing canonical control.decision reconstruction. Not rewritten for catalog.

SECURITY / OPERATIONAL QUESTION: What authorization decision was made?

EVIDENCE REQUIRED: Indexed control.decision rows.

TELEMETRY SOURCE: same index/sourcetype.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS (historical)

CORRELATION CONTRACT:
PASS

SPL CORRECTNESS:
PASS

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED (this pass)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (revalidated 8D; extra METADATA-001 OBSERVE row documented)

DASHBOARD CONSUMER:
YES (prior labs). Not bound for LAB-MCP-CATALOG yet.

LIMITATIONS: Extra catalog row has empty requested/allowed scope. Do not treat OBSERVE as ALLOW. Do not rewrite this file merely because MCP-CATALOG adds events.

VERDICT:
PUBLISH (no change)

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001 (reuse, unmodified)

TYPE: DETECTION

PURPOSE: Execution after DENY. Packaged disabled. Not a catalog-poisoning detector.

SECURITY / OPERATIONAL QUESTION: After authorization DENY, did `mcp.started` occur for the same run.id + tool?

EVIDENCE REQUIRED: DENY then later mcp.started.

TELEMETRY SOURCE: same.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (`run_id`, `tool`, `sequence`)

SPL CORRECTNESS:
PASS (unchanged)

NO-DATA SEMANTICS:
PASS (0 rows ≠ safe; 0 rows ≠ attack failed)

PERFORMANCE:
NOT MEASURED (this pass)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
READY for its invariant; NOT APPLICABLE for catalog overlay ATTACK

LIVE SPLUNK VALIDATION:
PASS (A/B/C = 0/0/0 MEASURED)

DASHBOARD CONSUMER:
NO for catalog (no Studio)

LIMITATIONS: Silent on ALLOW-path catalog ATTACK. That is a detection gap, not a detector failure.

VERDICT:
PUBLISH (no change)

---

## Recommendations (not implemented in Phase 8D)

| Priority | Recommendation |
|----------|----------------|
| LOW | Future workshop should bind `Q-MCP-CATALOG-AUTHORITY` with `__RUN_ID__` → token; do not copy SPL into Studio JSON. |
| LOW | Do not add a catalog savedsearch until a detector (if any) is designed. |
| LOW | Teach Q-MCP-EXECUTED extra OBSERVE row in the workshop rather than rewriting the validated hunt. |
| LOW | Do not CIM-map `agentsec.mcp.metadata.trust` to `dest` / `action` / malware categories. |
| MEDIUM | A later lab-only teaching detector may use the fail-open reason; a general production poisoning detector must not. |

Rejected this phase: five extra Q-MCP-CATALOG-* files, DET-MCP-CATALOG, Studio, `props.conf` changes, scanner sourcetype, packaging DET into `savedsearches.conf`.
