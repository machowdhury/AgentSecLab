# MCP catalog search contract (LAB-MCP-CATALOG)

**Status:** Phase 8D **VALIDATED** against live Splunk (2026-09-16).  
**Not:** Dashboard Studio, DET-MCP-CATALOG, scanner ingestion, rug-pull.  
**Runtime remains authoritative.** Splunk is the analytical/evidence surface.

Stored SPL: `learning/level_1/LAB-MCP-CATALOG/searches/`. Token: `__RUN_ID__`.

Index: `agentsec_telemetry`. Sourcetype: `otel:agentic:json`.

Parents: `docs/MCP_SEARCH_CONTRACT.md`, `docs/MCP_CATALOG_SPLUNK_FIELD_CONTRACT.md`, `docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md`.

---

## Query catalog

| Query ID | Security question | Zero results means |
|----------|-------------------|--------------------|
| **Q-MCP-CATALOG-AUTHORITY** | What catalog metadata was observed, how classified, and how was any follow-on authorized? | No indexed METADATA-001 for that `run.id`. Not “safe.” Not DENY. |
| Reused **Q-MCP-WHO** | Which principal/agent/tool? | Extra METADATA-001 row with empty method |
| Reused **Q-MCP-AUTHZ** | What decisions were indexed? | Extra OBSERVE row; hop-1 ALLOW/DENY |
| Reused **Q-MCP-TOOL** | Which `mcp.started` events exist? | No indexed start. Not automatically DENY |
| Reused **Q-MCP-EXECUTED** | Did a governed operation begin (per tool)? | Extra OBSERVE row inherits lookup_policy execution_state |
| Reused **Q-MCP-AFTER-DENY** | MCP event after DENY same run/tool? | **0 = no indexed violation found** |
| Reused **Q-MCP-RESULT-TRUST** | How is **result** content classified? | Does not answer metadata trust |

---

## Candidates not published

| ID | Decision |
|----|----------|
| Q-MCP-CATALOG-METADATA | **REDUNDANT** — columns on Q-MCP-CATALOG-AUTHORITY |
| Q-MCP-CATALOG-TRUST | **REDUNDANT** — same |
| Q-MCP-CATALOG-FINGERPRINT | **SUPPORTED** by indexed hash; **REDUNDANT** as a join hunt. Compare two `metadata_hash` values in CLI |
| Q-MCP-CATALOG-FOLLOWON | **SUPPORTED BY EXISTING Q-MCP** |
| Q-MCP-CATALOG-AUTHZ | **SUPPORTED BY EXISTING Q-MCP** |
| Q-CATALOG-WHAT-WAS-ADVERTISED | **BLOCKED BY TELEMETRY** |
| Q-CATALOG-SCANNER-FINDINGS | **BLOCKED BY TELEMETRY** |

---

## Required output columns (validated)

Q-MCP-CATALOG-AUTHORITY: `run_id`, `profile`, `mode`, `metadata_trust`, `metadata_provenance`, `metadata_hash`, `metadata_preview`, `metadata_decision`, `metadata_reason`, `initial_tool`, `initial_decision`, `initial_reason`, `server_owned_allowed_scope`, `derived_authority`, `followon_tool`, `followon_requested_scope`, `followon_coded_allowed_scope`, `followon_decision`, `followon_reason`, `followon_execution_observation`

`derived_authority` is a display helper (`present` only when follow-on reason contains `metadata_derived_authority`). It is not a detector.

---

## Semantics

- OBSERVE ≠ ALLOW ≠ DENY
- ALLOW ≠ execution
- `mcp.started` ≠ success
- DENY + no indexed start ≠ independent proof of non-execution
- 0 rows ≠ safe
- metadata provenance ≠ metadata trust
- malicious description ≠ malicious tool
- request ≠ grant
- Hash is the fingerprint; do not correlate by preview
- Do not invent `gen_ai.tool.call.id`

---

## SPL quality

Prefer: index, sourcetype, `run.id`, event/control types, `stats` / `eventstats` / `where` / `eval` / `fields` / `table`, `mvindex(mvdedup(…),0)`.

`Q-MCP-CATALOG-AUTHORITY` uses none of: `join`, `transaction`, `map`, `append`, subsearch fan-out.

`earliest=0` is lab-only.

---

## Detection

DET-MCP-001 reused unchanged. Expected live A/B/C = 0. Catalog poisoning ATTACK is an ALLOW-path vulnerability.

**DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN** for a *lab-specific* teaching detector on the fail-open reason. General production tool-description-poisoning detection is still a gap. No DET-MCP-CATALOG file.
