# Splunk KO review — scanner + runtime evidence workshop (Phase 9E)

**Date:** 2026-09-16  
**Surface:** Dashboard Studio `ws_lab_scanner_runtime_evidence` plus bind-only reuse of validated hunts.  
**Live Splunk:** NOT RUN in this review (9C/8D already validated the searches). Playwright rendering is separate.  
**This review does not rewrite Q-SCANNER-* or Q-MCP-*.**

Official skills consulted (after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search, Knowledge Object Governance, Field Extraction and CIM Mapping, Dashboard and Visualization. `/spl-validate` not re-run because no new SPL was authored.

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: ws_lab_scanner_runtime_evidence

TYPE: DASHBOARD

PURPOSE: Learner workshop that keeps scanner artifact evidence independent from runtime metadata, authorization, and execution evidence. Persistence justified: LAB-MCP-CATALOG already teaches the runtime poisoning lesson; overloading that view would collapse chapter questions.

SECURITY / OPERATIONAL QUESTION: When an external security scanner flags agent/tool metadata, what can the SOC actually conclude from that evidence?

EVIDENCE REQUIRED: Indexed scanner scan-summary/finding rows; METADATA-001 content hash; CTRL-MCP-001 ALLOW/DENY; mcp.started/completed; runtime handler counts (authoritative for non-execution).

TELEMETRY SOURCE: `agentsec:scanner:finding` (PLANE 1) and `otel:agentic:json` (PLANES 2–3). Correlation search unions both by description SHA-256.

INDEXED FIELDS VERIFIED:
YES (Phase 9C / 8D contracts; this phase binds existing tokens only)

FIELD CONTRACT:
PASS (no invented fields; description_sha256 is the join key; artifact.sha256 not used as runtime key)

CORRELATION CONTRACT:
PASS (`__SCAN_ID__` → scan tokens; `__RUN_ID__` → run tokens; `__DESCRIPTION_SHA256__` bound to validated NORMAL/MALICIOUS hashes)

SPL CORRECTNESS:
PASS (bind-only; no join/transaction/map; sourcetype boundaries preserved except the validated correlation hunt)

NO-DATA SEMANTICS:
PASS (empty copy says missing indexed rows, not SAFE/blocked/trusted)

PERFORMANCE:
NOT MEASURED (production). Lab `earliest=0` retained from validated hunts.

CIM:
NOT APPLICABLE (scanner sourcetype and agentsec.mcp.* remain AgentSec-specific; 9C classified CIM NOT APPLICABLE)

KO DUPLICATION:
NONE. No new hunt files. No DET-SCANNER. No DET-MCP-CATALOG. DET-MCP-001 unchanged and not enabled by this dashboard. SIMULATED fixture is DET-MCP-001-POSITIVE-CONTROL makeresults.

DETECTION READINESS:
HUNT ONLY (Phase 9D: DETECTION ANALYZED — NO NEW DETECTOR)

LIVE SPLUNK VALIDATION:
NOT RUN for new SPL (none created). Prior 9C/8D LIVE remains the search validation.

DASHBOARD CONSUMER:
YES (`ws_lab_scanner_runtime_evidence`)

LIMITATIONS: Pytest does not prove Splunk rendering. Seven global inputs may ellipsize UUIDs. Scanner HIGH is identical on ATTACK and RETEST.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-SCANNER-WHO / Q-SCANNER-ARTIFACT / Q-SCANNER-FINDINGS / Q-SCANNER-RUNTIME-CORRELATION (dashboard data sources)

TYPE: DASHBOARD DATA SOURCE

PURPOSE: Plane 1 (and 1+2 correlation) tables. Reused from Phase 9C. Token bind only.

SECURITY / OPERATIONAL QUESTION: Did this scan execute, what artifact/hash was scanned, and which METADATA-001 rows share the description hash?

EVIDENCE REQUIRED: Scan-summary event always; finding rows when present; METADATA-001 hash match.

TELEMETRY SOURCE: `index=agentsec_telemetry sourcetype=agentsec:scanner:finding` (correlation also `otel:agentic:json`)

INDEXED FIELDS VERIFIED:
YES (9C)

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (description SHA-256; file hash is not the runtime key)

SPL CORRECTNESS:
PASS (unchanged files)

NO-DATA SEMANTICS:
PASS

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
HUNT ONLY

LIVE SPLUNK VALIDATION:
PASS (9C)

DASHBOARD CONSUMER:
YES

LIMITATIONS: Zero findings ≠ SAFE. Native HIGH ≠ incident HIGH.

VERDICT:
PUBLISH

---

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: Q-MCP-AUTHZ / Q-MCP-TOOL / Q-MCP-EXECUTED / Q-MCP-CATALOG-AUTHORITY / Q-MCP-AFTER-DENY (dashboard data sources)

TYPE: DASHBOARD DATA SOURCE

PURPOSE: Planes 2–3 and DET-MCP-001 hunt semantics. Reused from LAB-MCP-001 / LAB-MCP-CATALOG.

SECURITY / OPERATIONAL QUESTION: Was metadata classified, was the follow-on authorized, did execution begin, and did DENY then mcp.started occur?

EVIDENCE REQUIRED: Indexed control.decision and mcp.* events for the bound run.id.

TELEMETRY SOURCE: `otel:agentic:json` only (scanner sourcetype must not appear)

INDEXED FIELDS VERIFIED:
YES (8D)

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS (`agentsec.run.id`)

SPL CORRECTNESS:
PASS (unchanged files)

NO-DATA SEMANTICS:
PASS (AFTER-DENY 0 rows on ATTACK and RETEST is expected)

PERFORMANCE:
NOT MEASURED

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE versus published hunts

DETECTION READINESS:
HUNT ONLY except DET-MCP-001 which remains the existing DENY-then-start detector and is not enabled here

LIVE SPLUNK VALIDATION:
PASS (8D)

DASHBOARD CONSUMER:
YES

LIMITATIONS: Q-MCP-EXECUTED extra OBSERVE row remains a known teaching caveat from 8E.

VERDICT:
PUBLISH

---

## Macro / saved search / detector / props

- `macros.conf` agentsec_index unchanged; scanner sourcetype stays out of the runtime macro.
- `savedsearches.conf` has no Q-SCANNER and no DET-SCANNER. DET-MCP-001 remains disabled.
- `props.conf` `[agentsec:scanner:finding]` unchanged from 9C.
- Nav includes `ws_lab_scanner_runtime_evidence` without removing `ws_lab_mcp_catalog`.
- App staging requires the new XML (`scripts/splunk_app_init.sh`).

## Security semantics

SCANNER FINDING != AUTHORIZATION DECISION. Scanner evidence does not feed CTRL-MCP-001. Splunk does not ALLOW or DENY. SIMULATED != LIVE.

## Verdict

PUBLISH the workshop dashboard. Do not create a detector. Do not start Agent Scan, rug-pull, A2A, or Phase 10.
