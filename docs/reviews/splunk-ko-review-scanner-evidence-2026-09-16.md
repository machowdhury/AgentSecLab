# Splunk KO review — scanner evidence Phase 9C

**Date:** 2026-09-16  
**Purpose:** Knowledge-object review for Phase 9C live scanner ingest + hunts.  
**Live Splunk:** RUN (HEC ingest, fieldsummary, `dc(_raw)`, Q-SCANNER-*, Q-MCP reuse).  
**This review does not redesign historical Q-MCP files.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search, Field Extraction and CIM Mapping, Knowledge Object Governance, Data Source Onboarding Advisor, Ingestion Pipeline Design, HEC Setup and Troubleshooting, Search Performance Optimizer (notes only). `/spl-validate` headings live in `Q-SCANNER-*.md`.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: agentsec:scanner:finding (props.conf)

TYPE: FIELD EXTRACTION / APP CONFIGURATION

PURPOSE: Index-time JSON extraction for independent scanner evidence. Persistence justified: HEC events would otherwise inherit the default `otel:agentic:json` contract.

SECURITY / OPERATIONAL QUESTION: Can scanner JSON be indexed without contaminating schema 1.5.0 or authorization telemetry?

EVIDENCE REQUIRED: Per-event HEC sourcetype, scan + finding JSON, no raw stdout.

TELEMETRY SOURCE: HEC → `index=agentsec_telemetry`. Not OTLP.

INDEXED FIELDS VERIFIED:
YES (fieldsummary 2026-09-16)

FIELD CONTRACT:
PASS (`docs/SCANNER_SPLUNK_FIELD_CONTRACT.md`)

CORRELATION CONTRACT:
PASS (`artifact.description_sha256` ↔ `agentsec.content.hash`; file hash rejected)

SPL CORRECTNESS:
N/A (extraction)

NO-DATA SEMANTICS:
PASS (scan event required for zero findings)

PERFORMANCE:
NOT MEASURED (production). Lab: 3 events.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE. `KV_MODE=none` avoided runtime JSON double extraction. MEASURED mvcount=1.

DETECTION READINESS:
NOT A DETECTOR

LIVE SPLUNK VALIDATION:
PASS

DASHBOARD CONSUMER:
NO (Phase 9C forbids Studio)

LIMITATIONS: Boolean strings `true`/`false`. Classification omitted when null.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-SCANNER-WHO

TYPE: HUNT

PURPOSE: Identify which scanner produced a scan-summary event.

SECURITY / OPERATIONAL QUESTION: Which scanner ran?

EVIDENCE REQUIRED: Indexed scan-summary with scanner identity.

TELEMETRY SOURCE: `agentsec:scanner:finding`

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (`scan_id` token)

SPL CORRECTNESS:
PASS (index+sourcetype+scan_id+event.name; no join/transaction/map/append)

NO-DATA SEMANTICS:
PASS (0 rows ≠ zero findings)

PERFORMANCE:
NOT MEASURED (production). Lab CLI succeeded.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS

DASHBOARD CONSUMER:
NO

LIMITATIONS: Does not authorize.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-SCANNER-ARTIFACT

TYPE: HUNT

PURPOSE: Show artifact identity and hash semantics for one scan.

SECURITY / OPERATIONAL QUESTION: What artifact did it scan?

EVIDENCE REQUIRED: Indexed artifact hashes, bytes, fixture, raw SHA-256 link.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (documents file hash ≠ description hash)

SPL CORRECTNESS:
PASS

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
PASS

DASHBOARD CONSUMER:
NO

LIMITATIONS: File hash is not a runtime join key.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-SCANNER-FINDINGS

TYPE: HUNT

PURPOSE: Distinguish scan-executed-zero-findings from missing scan and from finding-present. Preserve native severity.

SECURITY / OPERATIONAL QUESTION: Were findings produced, and what native rules/severities were reported?

INDEXED FIELDS VERIFIED:
YES (`finding.native_confidence` ABSENT FROM SOURCE — search does not require it)

FIELD CONTRACT:
PASS

SPL CORRECTNESS:
PASS (`finding_state` is a display helper, not PASS/FAIL)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED (production)

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE (Q3 and Q4 share one hunt)

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS

DASHBOARD CONSUMER:
NO

LIMITATIONS: Classification field missing on NORMAL is correct omit-none.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-SCANNER-RUNTIME-CORRELATION

TYPE: HUNT

PURPOSE: Honest artifact correlation across sourcetypes without join.

SECURITY / OPERATIONAL QUESTION: Which runtime catalog observations correspond to the scanned artifact?

EVIDENCE REQUIRED: Scanner `artifact.description_sha256` and METADATA-001 `agentsec.content.hash`.

TELEMETRY SOURCE: both sourcetypes, OR + stats by unified hash.

INDEXED FIELDS VERIFIED:
YES

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (wrong file-hash token 0 rows MEASURED)

SPL CORRECTNESS:
PASS (no join/transaction/map/append)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED (production). Lab hash filter is selective.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE. Does not rewrite Q-MCP-CATALOG-AUTHORITY.

DETECTION READINESS:
HUNT ONLY — does not eval ALLOW/DENY from scanner HIGH

LIVE SPLUNK VALIDATION:
PASS

DASHBOARD CONSUMER:
NO

LIMITATIONS: `values()` does not order ATTACK vs RETEST. Follow-on authorization remains Q-MCP-AUTHZ.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-AUTHZ / Q-MCP-CATALOG-AUTHORITY / Q-MCP-EXECUTED (reuse)

TYPE: INVESTIGATION SEARCH / HUNT

PURPOSE: Unmodified runtime reconstruction of ATTACK vs RETEST.

SECURITY / OPERATIONAL QUESTION: What happened in the vulnerable ATTACK vs defended RETEST?

INDEXED FIELDS VERIFIED:
YES (revalidated 2026-09-16)

SPL CORRECTNESS:
PASS (files unchanged)

DETECTION READINESS:
HUNT ONLY (DET-MCP-001 unchanged, disabled)

LIVE SPLUNK VALIDATION:
PASS

DASHBOARD CONSUMER:
Existing catalog workshop only. No new scanner tab.

VERDICT:
REUSE — DO NOT REWRITE

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: DET-MCP-001 / savedsearches.conf / macros / Studio / CIM data models / lookups

TYPE: DETECTION / SAVED SEARCH / MACRO / DASHBOARD / DATA MODEL / LOOKUP

PURPOSE: Confirm Phase 9C did not create or enable extra KOs.

EVIDENCE REQUIRED: Repository files.

INDEXED FIELDS VERIFIED:
N/A

SPL CORRECTNESS:
DET-MCP-001 body unchanged; no `scanner`. `agentsec_index` still `otel:agentic:json`. No `ws_lab_*scanner*`. No lookups. No data models. No DET-SCANNER.

CIM:
NOT APPLICABLE (unchanged)

DETECTION READINESS:
No new detector. Do not publish DET-SCANNER-HIGH.

LIVE SPLUNK VALIDATION:
N/A for non-created objects

DASHBOARD CONSUMER:
NO new dashboard

VERDICT:
DO NOT PUBLISH new objects in these classes

---

## Knowledge Object Governance notes

Naming `Q-SCANNER-*` keeps scanner hunts distinct from `Q-MCP-*`. Bind tokens follow existing `__TOKEN__` style. Hunts are files, not scheduled saved searches. Privacy: no argv, no full descriptions, no raw stdout in indexed fields.
