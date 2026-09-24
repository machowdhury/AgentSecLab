# Splunk knowledge object review — Capstone prebuild

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: `ws_lab_agentsec_capstone` and its token-bound data sources  
TYPE: DASHBOARD / DASHBOARD DATA SOURCE  
PURPOSE: Teach reconstruction of the Capstone retrieve → persist → recall → request → authorization → execution chain without creating a new hunt or detector.

SECURITY / OPERATIONAL QUESTION:

How did untrusted bytes influence a later privileged request, which control decided authority, what executed, and what changed between ATTACK and RETEST?

EVIDENCE REQUIRED:

Three distinct run IDs; RAG document ID/hash/trust/control; memory ID/hash/source run/control; requested tool/scope/resource; MCP control ID/decision/reason; handler execution evidence; profile/mode; local-versus-indexed counts during LIVE validation.

TELEMETRY SOURCE:

Attack Service runtime events exported as `sourcetype=otel:agentic:json` in `index=agentsec_telemetry`.

INDEXED FIELDS VERIFIED:
YES — by prior Phase 16B LIVE validation; fresh validation is required after this build.

FIELD CONTRACT:
PASS

CORRELATION CONTRACT:
PASS — RETRIEVE, WRITE, and RECALL retain distinct run IDs; recall `source_run_id` links WRITE→RECALL; exact content-hash equality links RETRIEVE→WRITE because schema 1.9.0 has no direct field.

SPL CORRECTNESS:
PASS — dashboard binds existing validated Q-* searches. No Capstone-specific SPL is needed.

NO-DATA SEMANTICS:
PASS — current empty-state text rejects SAFE/prevention inference and distinguishes missing indexed evidence from DENY.

PERFORMANCE:
NOT MEASURED — searches are index/sourcetype/run constrained; fresh browser and Splunk validation remains pending.

CIM:
NOT APPLICABLE — AgentSec-specific control, memory, and agentic fields remain outside forced CIM mapping.

KO DUPLICATION:
NONE — the dashboard reuses Q-RAG, Q-MEMORY, Q-MCP, Q-GOAL, Q-AGENT-DELEGATION, and Q-RUN-EVENTS.

DETECTION READINESS:
HUNT ONLY — no defensible Capstone detector is required. `DET-MCP-001` remains a separate after-DENY behavior detector; zero rows are not SAFE.

LIVE SPLUNK VALIDATION:
NOT RUN for this build.

DASHBOARD CONSUMER:
YES

LIMITATIONS:

- Studio cannot bind arbitrary fresh Attack Service IDs into its fixed dropdowns; fresh IDs are investigated in Search.
- Hash equality covers exact bytes, not whole-experiment identity.
- Missing `mcp.started` does not independently prove non-execution.
- Splunk is evidence, not enforcement.
- Authentication, Goal Integrity, and Identity/Delegation are not active causal planes in this packet.
- HEC HTTP 200 does not prove searchable completeness.

VERDICT:
REVISE

## Required revision

Reduce the dashboard to MISSION, INVESTIGATE, EVIDENCE, and PATH B · ANSWERS. Keep Path A primary and move exact control/result answers behind Path B. Preserve every existing query byte-for-byte unless fresh validation demonstrates a defect.

## SPL change decision

No query change is justified. The evidence questions are already answered by validated searches. The build should alter presentation and layout only; query bytes must remain unchanged and be checked after generation.
