# Splunk knowledge object inventory

**Date:** 2026-09-17  
**Scope:** AgentSec repository Splunk content as of Phase 11D memory detection analysis. No DET-MEMORY. No memory Studio.  
**This file is inventory, not live Splunk proof.** Validation status is copied from existing phase documents.

Governance: `docs/SPLUNK_ENGINEERING_GOVERNANCE.md`. Rule: `.cursor/rules/33-splunk-agent-skills.mdc`. Review skill: `.cursor/skills/splunk-ko-review/SKILL.md`.

Index: `agentsec_telemetry`. Sourcetypes: `otel:agentic:json` (runtime schema 1.7.0), `agentsec:scanner:finding` (scanner evidence, not security_event). App: `agentsec`.

Q-MCP investigation searches are **schema-version agnostic** (no `schema.version=` filter). Catalog `schema.version` values are documentation metadata for the lab that first published the file.

LAB-MCP-003 has **no unique hunt file**. It reuses LAB-MCP-001 searches.

No lookups, data models, event types, or tags are packaged.

---

## LAB-PI-001 searches

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-RUN-EVENTS | INVESTIGATION SEARCH | LAB-PI-001 | What happened during one AgentSec run? | `learning/level_1/LAB-PI-001/searches/Q-RUN-EVENTS.spl` | VALIDATED (Phase 2C) | YES (`ws_lab_pi_001`) | HUNT | Agnostic | Token `__RUN_ID__` |
| Q-CONTROL-DECISION | INVESTIGATION SEARCH | LAB-PI-001 | What security decisions were made, by which control, at which hop? | `learning/level_1/LAB-PI-001/searches/Q-CONTROL-DECISION.spl` | VALIDATED (Phase 2C) | YES | HUNT | Agnostic | |
| Q-LLM-EXECUTED | INVESTIGATION SEARCH | LAB-PI-001 | Which governed LLM operations began and how did they end? | `learning/level_1/LAB-PI-001/searches/Q-LLM-EXECUTED.spl` | VALIDATED (Phase 2C) | YES | HUNT | Agnostic | |
| Q-LLM-AFTER-DENY | HUNT | LAB-PI-001 | Did a governed LLM operation begin after a pre-invocation DENY? | `learning/level_1/LAB-PI-001/searches/Q-LLM-AFTER-DENY.spl` | VALIDATED (Phase 2C) | YES | HUNT | Agnostic | Zero rows ≠ prevention |
| Q-LLM-AFTER-DENY-POSITIVE-CONTROL | INVESTIGATION SEARCH | LAB-PI-001 | Can the after-DENY query fire? | `learning/level_1/LAB-PI-001/searches/Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl` | VALIDATED fixture | YES (DETECT) | HUNT fixture | N/A | SIMULATED `makeresults`; not indexed |

Field contract: `learning/level_1/LAB-PI-001/searches/catalog.json`, `docs/PHASE2C_SPL_VALIDATION.md`.

---

## LAB-MCP-001 searches (reused by MCP-003+)

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-MCP-WHO | INVESTIGATION SEARCH | LAB-MCP-001 | Which principal/agent requested which MCP tool? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-WHO.spl` | VALIDATED (3C; reused 4C–7C) | YES (MCP workshops) | HUNT | Agnostic | Does not label caller vs deputy |
| Q-MCP-AUTHZ | INVESTIGATION SEARCH | LAB-MCP-001 | What authorization decision was made? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-AUTHZ.spl` | VALIDATED | YES | HUNT | Agnostic | `executed` is control-event field |
| Q-MCP-SCOPE | INVESTIGATION SEARCH | LAB-MCP-001 | Requested vs coded allowed scope | `learning/level_1/LAB-MCP-001/searches/Q-MCP-SCOPE.spl` | VALIDATED | some workshops | HUNT | Agnostic | Equality helper, not subset |
| Q-MCP-PARAMS | INVESTIGATION SEARCH | LAB-MCP-001 | What arguments were supplied? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-PARAMS.spl` | VALIDATED | some workshops | HUNT | Agnostic | Preview/hash; not grant proof |
| Q-MCP-TOOL | INVESTIGATION SEARCH | LAB-MCP-001 | Which tool executions actually began? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-TOOL.spl` | VALIDATED | YES | HUNT | Agnostic | `mcp.started` ≠ success |
| Q-MCP-EXECUTED | INVESTIGATION SEARCH | LAB-MCP-001 | Did the governed MCP operation begin? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-EXECUTED.spl` | VALIDATED | YES | HUNT | Agnostic | May emit extra rows when two controls share a tool |
| Q-MCP-AFTER-DENY | HUNT | LAB-MCP-001 | MCP execution event after DENY same run/tool? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-AFTER-DENY.spl` | VALIDATED | YES (DETECT) | HUNT | Agnostic | Investigation form of DET-MCP-001 invariant |
| Q-MCP-RESULT | INVESTIGATION SEARCH | LAB-MCP-001 | What result metadata exists? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-RESULT.spl` | VALIDATED | MCP-005 | HUNT | Agnostic | |
| Q-MCP-RESULT-TRUST | INVESTIGATION SEARCH | LAB-MCP-001 | How is returned content classified? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-RESULT-TRUST.spl` | VALIDATED | MCP-005 | HUNT | Agnostic | Classification, not authority |
| Q-MCP-AFTER-DENY-POSITIVE-CONTROL | INVESTIGATION SEARCH | LAB-MCP-001 | Can the after-DENY hunt fire? | `learning/level_1/LAB-MCP-001/searches/Q-MCP-AFTER-DENY-POSITIVE-CONTROL.spl` | VALIDATED fixture | teaching | HUNT fixture | N/A | SIMULATED |
| DET-MCP-001-POSITIVE-CONTROL | INVESTIGATION SEARCH | LAB-MCP-001 | Can DET-MCP-001 fire? | `learning/level_1/LAB-MCP-001/searches/DET-MCP-001-POSITIVE-CONTROL.spl` | VALIDATED fixture | YES (DETECT SIMULATED) | DETECTION fixture | N/A | SIMULATED `makeresults` |
| DET-MCP-001-SCOPE-POSITIVE-CONTROL | INVESTIGATION SEARCH | LAB-MCP-003 teaching | Teaching fixture for existing DET-MCP-001 on scope | `learning/level_1/LAB-MCP-001/searches/DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl` | VALIDATED fixture | MCP-003 DETECT | DETECTION fixture | N/A | Not DET-MCP-003 |

Field contract: `docs/MCP_SEARCH_CONTRACT.md`, `docs/MCP_SPLUNK_FIELD_CONTRACT.md`.

---

## LAB-MCP-003 searches

No unique `.spl` hunt. Reuses LAB-MCP-001. Scope teaching fixture listed above. No DET-MCP-003.

---

## LAB-MCP-004 searches

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-MCP-RESOURCE-AUTHZ | HUNT | LAB-MCP-004 | Requested resource vs coded grant vs decision | `learning/level_1/LAB-MCP-004/searches/Q-MCP-RESOURCE-AUTHZ.spl` | VALIDATED (5C) | YES (`ws_lab_mcp_004`) | HUNT | Agnostic | Not the confused-deputy predicate |
| DET-MCP-001-RESOURCE-POSITIVE-CONTROL | INVESTIGATION SEARCH | LAB-MCP-004 teaching | Teaching fixture for existing DET-MCP-001 | `learning/level_1/LAB-MCP-004/searches/DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl` | VALIDATED fixture | MCP-004 DETECT | DETECTION fixture | N/A | Not DET-MCP-004 |

---

## LAB-MCP-005 searches

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-MCP-RESULT-AUTHORITY | HUNT | LAB-MCP-005 | Did result-derived data influence later authorization? | `learning/level_1/LAB-MCP-005/searches/Q-MCP-RESULT-AUTHORITY.spl` | VALIDATED (6C) | YES (`ws_lab_mcp_005`) | HUNT | Agnostic | Q-MCP-RESULT-FOLLOWON rejected / not published. No DET-MCP-005 |

---

## LAB-MCP-006 searches

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-MCP-DELEGATION | HUNT | LAB-MCP-006 | CTRL-DELEGATION-001, caller/deputy, authority.source, downstream MCP, indexed execution | `learning/level_1/LAB-MCP-006/searches/Q-MCP-DELEGATION.spl` | VALIDATED (7C) | YES (`ws_lab_mcp_006`) | HUNT | Agnostic | Rejected: Q-MCP-AMBIENT-USE, Q-MCP-DELEGATION-CHAIN, Q-MCP-DELEGATION-EXECUTED, Q-MCP-DELEGATION-AUTHORITY. No DET-MCP-006 |

---

## LAB-MCP-CATALOG searches

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-MCP-CATALOG-AUTHORITY | HUNT | LAB-MCP-CATALOG | Catalog metadata classification, description hash, follow-on authorization, indexed execution | `learning/level_1/LAB-MCP-CATALOG/searches/Q-MCP-CATALOG-AUTHORITY.spl` | VALIDATED (8D) | YES (`ws_lab_mcp_catalog`) | HUNT | Agnostic | Rejected extra Q-MCP-CATALOG-* files. No DET-MCP-CATALOG |

---

## LAB-RAG-001 searches

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-RAG-CONTEXT-AUTHORITY | HUNT | LAB-RAG-001 | Retrieved-context classification, document hash, follow-on authorization, indexed execution | `learning/level_1/LAB-RAG-CONTEXT/searches/Q-RAG-CONTEXT-AUTHORITY.spl` | VALIDATED (10C) | YES (`ws_lab_rag_context`) | HUNT | Agnostic | Rejected extra Q-RAG-* files. No DET-RAG. Rebuild: `scripts/build_lab_rag_context_dashboard.py` |

---

## LAB-MEMORY-001 searches

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-MEMORY-CONTEXT-AUTHORITY | HUNT | LAB-MEMORY-001 | Write → recall correlation, memory trust/hash, follow-on authorization, indexed execution | `learning/level_1/LAB-MEMORY-001/searches/Q-MEMORY-CONTEXT-AUTHORITY.spl` | VALIDATED (11C) | NO | HUNT | Agnostic | Tokens `__WRITE_RUN_ID__` + `__RECALL_RUN_ID__`. Rejected extra Q-MEMORY-* files. No DET-MEMORY. No Studio. |

---

## Scanner evidence searches (Phase 9C)

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-SCANNER-WHO | HUNT | LAB-MCP-CATALOG | Which scanner ran? | `learning/level_1/LAB-MCP-CATALOG/searches/Q-SCANNER-WHO.spl` | VALIDATED (9C) | YES (`ws_lab_scanner_runtime_evidence`) | HUNT | N/A (scanner sourcetype) | Token `__SCAN_ID__`. Scan-summary event. |
| Q-SCANNER-ARTIFACT | HUNT | LAB-MCP-CATALOG | What artifact was scanned? | `learning/level_1/LAB-MCP-CATALOG/searches/Q-SCANNER-ARTIFACT.spl` | VALIDATED (9C) | YES (`ws_lab_scanner_runtime_evidence`) | HUNT | N/A | File hash ≠ description hash |
| Q-SCANNER-FINDINGS | HUNT | LAB-MCP-CATALOG | Did the scan execute, and were native findings produced? | `learning/level_1/LAB-MCP-CATALOG/searches/Q-SCANNER-FINDINGS.spl` | VALIDATED (9C) | YES (`ws_lab_scanner_runtime_evidence`) | HUNT | N/A | Zero findings ≠ no scan. Native HIGH not remapped |
| Q-SCANNER-RUNTIME-CORRELATION | HUNT | LAB-MCP-CATALOG | Which METADATA-001 rows share the description hash? | `learning/level_1/LAB-MCP-CATALOG/searches/Q-SCANNER-RUNTIME-CORRELATION.spl` | VALIDATED (9C) | YES (`ws_lab_scanner_runtime_evidence`) | HUNT | N/A | Token `__DESCRIPTION_SHA256__`. No join. Does not authorize |

Field contract: `docs/SCANNER_SPLUNK_FIELD_CONTRACT.md`. Search contract: `docs/SCANNER_SEARCH_CONTRACT.md`. Catalog: `learning/level_1/LAB-MCP-CATALOG/searches/scanner_catalog.json`.

---

## DET-MCP-001

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| DET-MCP-001 | DETECTION | LAB-MCP-001 | After authorization DENY, did `mcp.started` occur for the same run.id + tool? | `learning/level_1/LAB-MCP-001/searches/DET-MCP-001.spl` | VALIDATED (3E); revalidated 4C–11C | NO (dashboards bind hunt + SIMULATED fixture; do not enable this saved search) | DETECTION | Agnostic | Packaged **disabled**, `enableSched=0`. Not a general MCP bypass detector. Not an ES notable |

Saved search name: `AgentSec - MCP Execution After Authorization Deny`.

---

## savedsearches.conf

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| Q-RUN | SAVED SEARCH | LAB-PI-001 placeholder | Did this run.id produce events? | `splunk_app/agentsec/default/savedsearches.conf` | **NOT VALIDATED** | NO | PLACEHOLDER | Unknown | disabled=1; do not treat as Q-RUN-EVENTS |
| Q-DENY | SAVED SEARCH | LAB-PI-001 placeholder | Which LIVE events have DENY and executed=false? | `splunk_app/agentsec/default/savedsearches.conf` | **NOT VALIDATED** | NO | PLACEHOLDER | Unknown | disabled=1 |
| AgentSec - MCP Execution After Authorization Deny | DETECTION | LAB-MCP-001 | Same as DET-MCP-001 | `splunk_app/agentsec/default/savedsearches.conf` | VALIDATED | NO (not enabled by Studio) | DETECTION | Agnostic | Search body matches DET-MCP-001.spl |

---

## Dashboard Studio views

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| ws_lab_pi_001 | DASHBOARD | LAB-PI-001 | Ten-step PI workshop | `splunk_app/agentsec/default/data/ui/views/ws_lab_pi_001.xml` | VALIDATED | — | consumes hunts | Agnostic | Rebuild: `scripts/build_lab_pi_001_dashboard.py` |
| ws_lab_mcp_001 | DASHBOARD | LAB-MCP-001 | Ten-step MCP tool-grant workshop | `.../ws_lab_mcp_001.xml` | VALIDATED | — | consumes Q-MCP | Agnostic | |
| ws_lab_mcp_003 | DASHBOARD | LAB-MCP-003 | Scope escalation workshop | `.../ws_lab_mcp_003.xml` | VALIDATED | — | consumes Q-MCP | Agnostic | No DET-MCP-003 |
| ws_lab_mcp_004 | DASHBOARD | LAB-MCP-004 | Resource authorization workshop | `.../ws_lab_mcp_004.xml` | VALIDATED | — | consumes Q-MCP + RESOURCE-AUTHZ | Agnostic | |
| ws_lab_mcp_005 | DASHBOARD | LAB-MCP-005 | Result-trust workshop | `.../ws_lab_mcp_005.xml` | VALIDATED | — | consumes Q-MCP + RESULT-AUTHORITY | Agnostic | No DET-MCP-005 |
| ws_lab_mcp_006 | DASHBOARD | LAB-MCP-006 | Confused-deputy workshop | `.../ws_lab_mcp_006.xml` | VALIDATED | — | consumes Q-MCP + DELEGATION | Agnostic | No DET-MCP-006 |
| ws_lab_mcp_catalog | DASHBOARD | LAB-MCP-CATALOG | Tool-description / catalog-metadata workshop | `.../ws_lab_mcp_catalog.xml` | VALIDATED (8E) | — | consumes Q-MCP + CATALOG-AUTHORITY | Agnostic | No DET-MCP-CATALOG. Rebuild: `scripts/build_lab_mcp_catalog_dashboard.py` |
| ws_lab_scanner_runtime_evidence | DASHBOARD | LAB-SCANNER-RUNTIME-EVIDENCE | Combine scanner + runtime evidence without collapsing planes | `.../ws_lab_scanner_runtime_evidence.xml` | VALIDATED (9E) | — | consumes Q-SCANNER + Q-MCP + CATALOG-AUTHORITY | Agnostic | No DET-SCANNER. No DET-MCP-CATALOG. Rebuild: `scripts/build_lab_scanner_runtime_evidence_dashboard.py` |
| ws_lab_rag_context | DASHBOARD | LAB-RAG-CONTEXT | Reconstruct retrieved-context investigation without collapsing planes | `.../ws_lab_rag_context.xml` | VALIDATED (10E) | — | consumes Q-RAG-CONTEXT-AUTHORITY + Q-MCP | Agnostic | No DET-RAG. Rebuild: `scripts/build_lab_rag_context_dashboard.py` |

Canonical JSON beside each lab: `learning/level_1/LAB-*/dashboard.definition.json`. Studio **DASHBOARD DATA SOURCE** objects are `ds.search` binds of the files above (`__RUN_ID__` → `"$token$"`), plus labeled SIMULATED fixtures and a small observe-sequence helper per workshop.

---

## Field contracts, lookups, macros, data models

| NAME | TYPE | LAB | QUESTION ANSWERED | SOURCE FILE | VALIDATION STATUS | DASHBOARD CONSUMER | DETECTION/HUNT | SCHEMA VERSION DEPENDENCY | NOTES |
|------|------|-----|-------------------|-------------|-------------------|--------------------|----------------|---------------------------|-------|
| MCP field contract | FIELD EXTRACTION / contract | MCP labs | Which indexed names are authoritative? | `docs/MCP_SPLUNK_FIELD_CONTRACT.md` | VALIDATED | docs | — | 1.1.0+ additive | Duplicate JSON extraction documented; `mvindex(mvdedup(...),0)` |
| MCP-003 field validation | FIELD EXTRACTION / contract | LAB-MCP-003 | Indexed scope fields | `docs/MCP003_SPLUNK_FIELD_VALIDATION.md` | VALIDATED | docs | — | Agnostic | |
| MCP-004 field validation | FIELD EXTRACTION / contract | LAB-MCP-004 | Indexed resource fields | `docs/MCP004_SPLUNK_FIELD_VALIDATION.md` | VALIDATED | docs | — | Agnostic | |
| MCP-005 field validation | FIELD EXTRACTION / contract | LAB-MCP-005 | Indexed result-trust fields | `docs/MCP005_SPLUNK_FIELD_VALIDATION.md` | VALIDATED | docs | — | Agnostic | No `allowed_tools` |
| MCP-006 field validation | FIELD EXTRACTION / contract | LAB-MCP-006 | Indexed delegation fields | `docs/MCP006_SPLUNK_FIELD_VALIDATION.md` | VALIDATED | docs | — | 1.4.0 additive | `agentsec.delegation.authority.source` |
| MCP-CATALOG field contract | FIELD EXTRACTION / contract | LAB-MCP-CATALOG | Indexed metadata-trust fields | `docs/MCP_CATALOG_SPLUNK_FIELD_CONTRACT.md` | VALIDATED (8D) | docs | — | 1.5.0 additive | `agentsec.mcp.metadata.trust` / provenance; no `allowed_tools` |
| RAG field contract | FIELD EXTRACTION / contract | LAB-RAG-001 | Indexed retrieved-context fields | `docs/RAG_SPLUNK_FIELD_CONTRACT.md` | VALIDATED (10C) | docs | — | 1.6.0 additive | `agentsec.rag.context.trust` / provenance / document.id; no `trusted_document` |
| Memory field contract | FIELD EXTRACTION / contract | LAB-MEMORY-001 | Indexed memory write/recall fields | `docs/MEMORY_SPLUNK_FIELD_CONTRACT.md` | VALIDATED (11C) | docs | — | 1.7.0 additive | `agentsec.memory.id` / trust / provenance / `source_run_id`; no `trusted_memory` |
| Scanner field contract | FIELD EXTRACTION / contract | scanner evidence | Indexed scanner finding/scan fields | `docs/SCANNER_SPLUNK_FIELD_CONTRACT.md` | VALIDATED (9C) | docs | — | N/A | Independent of 1.5.0; native severity preserved |
| `agentsec_index` | MACRO | app | Index+sourcetype shortcut | `splunk_app/agentsec/default/macros.conf` | Packaged | NO (validated Q-* hardcode index/sourcetype) | — | N/A | Runtime only (`otel:agentic:json`). Not widened for scanner |
| JSON props | FIELD EXTRACTION | app | INDEXED_EXTRACTIONS=json for `otel:agentic:json` | `splunk_app/agentsec/default/props.conf` | OBSERVED | runtime searches | — | N/A | Causes documented mv duplication |
| Scanner JSON props | FIELD EXTRACTION | app | INDEXED_EXTRACTIONS=json, KV_MODE=none for `agentsec:scanner:finding` | `splunk_app/agentsec/default/props.conf` | VALIDATED (9C) | Q-SCANNER-* | — | N/A | MEASURED mvcount=1 |
| `agentsec_telemetry` | APP CONFIGURATION | app | Lab index | `splunk_app/agentsec/default/indexes.conf` | Packaged | — | — | N/A | |
| Lookups | LOOKUP | — | — | none | ABSENT | — | — | — | |
| Data models | DATA MODEL | — | — | none | ABSENT | — | — | — | CIM NOT APPLICABLE for agentic authorization fields unless later mapped honestly |
| Event types / tags | EVENT TYPE / TAG | — | — | none | ABSENT | — | — | — | |

---

## Rejected / not published (do not add)

| NAME | TYPE | NOTES |
|------|------|-------|
| Q-MCP-RESULT-FOLLOWON | HUNT | Duplicate of Q-MCP-RESULT-AUTHORITY |
| Q-MCP-AMBIENT-USE | HUNT | Would look like a detector; covered by Q-MCP-DELEGATION |
| Q-MCP-DELEGATION-CHAIN | HUNT | Duplicate columns |
| Q-MCP-DELEGATION-EXECUTED | HUNT | Duplicate of execution_observation + Q-MCP-EXECUTED |
| Q-MCP-DELEGATION-AUTHORITY | HUNT | Duplicate |
| DET-MCP-003 / 004 / 005 / 006 | DETECTION | DETECTION ANALYZED — NO NEW DETECTOR |
| Q-MCP-CATALOG-METADATA / TRUST / FINGERPRINT / FOLLOWON / AUTHZ | HUNT | Duplicate or reused; not published as separate files |
| DET-MCP-CATALOG | DETECTION | DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN; not implemented |
| DET-RAG / Q-RAG-CONTEXT / TRUST / FINGERPRINT / FOLLOWON / AUTHZ | DETECTION / HUNT | 10C extra hunts redundant; 10D DET-RAG REJECT; DETECTION ANALYZED — NO NEW DETECTOR (`docs/reviews/splunk-ko-review-rag-detection-2026-09-16.md`) |
| DET-MEMORY / Q-MEMORY-WRITE / TRUST / FINGERPRINT / FOLLOWON / AUTHZ | DETECTION / HUNT | 11C extra hunts redundant; 11D DET-MEMORY REJECT; overlay reason and AGENT MEMORY NOTE regex REJECT; DETECTION ANALYZED — NO NEW DETECTOR (`docs/reviews/splunk-ko-review-memory-2026-09-17.md`, `docs/reviews/splunk-ko-review-memory-detection-2026-09-18.md`) |
| Q-SCANNER-PASS-FAIL | HUNT | Would collapse zero findings / missing scan / error |
| DET-SCANNER-* | DETECTION | Phase 9C investigation only; scanner HIGH ≠ DENY |
| Q-SCANNER-FILEHASH-TO-CONTENT-HASH | HUNT | Wrong hash semantics; live 0 rows |
