# SPLUNK KNOWLEDGE OBJECT REVIEW

**Evidence:** DOCUMENTED pre-build review of the existing MCP Dashboard Studio consumer and Q-MCP search files.

OBJECT: `ws_lab_mcp_001`
TYPE: DASHBOARD / DASHBOARD DATA SOURCE
PURPOSE: Teach reconstruction of MCP request, authorization, execution, and evidence without changing validated searches.

SECURITY / OPERATIONAL QUESTION:

Did the requested MCP tool receive authorization, and did its handler actually begin?

EVIDENCE REQUIRED:

Principal, agent, requested tool/scope, coded allowed scope, CTRL-MCP-001 decision/reason, `mcp.started`/completion/failure, runtime handler count, run.id, and copy completeness.

TELEMETRY SOURCE:

`index=agentsec_telemetry`, `sourcetype=otel:agentic:json`; runtime evidence pack remains authoritative for handler non-execution.

INDEXED FIELDS VERIFIED:
YES — previously validated Q-MCP contracts plus fresh post-build ATTACK/RETEST rows.

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS — `agentsec.run.id`; event order uses `agentsec.sequence`.

SPL CORRECTNESS:
PASS — preserve existing Q-MCP files and token/literal substitution. No SPL simplification is authorized.

NO-DATA SEMANTICS:
PASS — zero rows remain neither DENY nor prevention.

PERFORMANCE:
PASS — existing searches are index/sourcetype/run constrained and avoid join/transaction/map.

CIM:
NOT APPLICABLE

KO DUPLICATION:
NONE — presentation-only data sources reuse existing hunts.

DETECTION READINESS:
NOT APPLICABLE — DET-MCP-001 remains packaged disabled; no new detector.

LIVE SPLUNK VALIDATION:
PASS — Q-MCP-WHO, Q-MCP-AUTHZ, and Q-MCP-EXECUTED returned expected rows for checkpoint ATTACK `2b8949c2-1e11-4c91-a578-d73fa7e7d323` and RETEST `1b297f0b-d473-4125-bb56-773fe8479898`. Local event count equaled Splunk `dc(_raw)` (7/7 and 6/6).

DASHBOARD CONSUMER:
YES

LIMITATIONS:

Studio cannot receive the fresh Attack Service run.id automatically. Path A remains Splunk Search. Indexed absence is corroborative only after completeness is measured.

VERDICT:
PUBLISH — presentation changes passed fresh LIVE Splunk validation, UI review, and logic proof.
