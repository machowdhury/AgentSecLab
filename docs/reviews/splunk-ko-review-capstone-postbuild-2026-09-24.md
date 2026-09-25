# Splunk knowledge object review — Capstone postbuild

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: `ws_lab_agentsec_capstone` and its token-bound data sources  
TYPE: DASHBOARD / DASHBOARD DATA SOURCE  
PURPOSE: Provide a reduced-guidance Capstone investigation using existing validated hunts.

SECURITY / OPERATIONAL QUESTION:

How did untrusted influence become a privileged request, which control evaluated authority, what executed, and what changed in RETEST?

EVIDENCE REQUIRED:

Three run IDs; content fingerprints; RAG and memory control evidence; memory source link; tool/scope/resource request; MCP decision/reason; ToolRegistry invocation count; completion/failure and outcome evidence; local and indexed counts.

TELEMETRY SOURCE:

Attack Service runtime events exported as `sourcetype=otel:agentic:json` in `index=agentsec_telemetry`.

INDEXED FIELDS VERIFIED:
YES — fresh ATTACK and RETEST packets reconstructed in local Splunk.

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS — distinct RETRIEVE/WRITE/RECALL IDs, WRITE→RECALL `source_run_id`, and scoped content-hash equality.

SPL CORRECTNESS:
PASS — existing Q-* searches returned the expected evidence shapes.

NO-DATA SEMANTICS:
PASS — zero rows are labeled as missing/instrumented absence, not SAFE, DENY, or prevention.

PERFORMANCE:
PASS for the local constrained specimen — searches are index/sourcetype/run bound. Production-scale performance is NOT MEASURED.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE

DETECTION READINESS:
HUNT ONLY — no Capstone detector added. Existing DET-MCP-001 semantics remain separate.

LIVE SPLUNK VALIDATION:
PASS

DASHBOARD CONSUMER:
YES

LIMITATIONS:

- fixed Studio dropdowns use validated specimens; fresh IDs go to Search
- fixed-grid tables are dense at narrow widths
- Splunk is downstream evidence, not enforcement
- the per-run ToolRegistry count supports non-invocation on the governed path; it does not prove successful completion
- hash equality covers exact document bytes only
- zero Goal/Identity rows apply only to this instrumented packet
- one RETEST is not universal effectiveness

VERDICT:
PUBLISH

## Query result

All 32 data-source IDs remain present. Every data-source query is byte-identical to the reviewed starting commit. No SPL semantics changed.

## Workshop result

- MISSION frames the incident without giving the final control answer.
- INVESTIGATE is primary Path A with six causal questions and progressive hints.
- EVIDENCE exposes the selected packet and evidence limitations.
- PATH B · ANSWERS contains validated SPL, expected shape, interpretation, and proof limits.

No `Q-CAPSTONE`, `DET-CAPSTONE`, saved search, alert, lookup, macro, extraction, CIM mapping, or data model was added.
