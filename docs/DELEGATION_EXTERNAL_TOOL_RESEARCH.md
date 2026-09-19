# Identity / A2A external tool research

**Status:** Phase 12A **DESIGN**. **No integrations executed.** Schema **1.7.0 unchanged**.  
**Evidence class:** **DOCUMENTED** (fetched 2026-09-18).

Parents: `docs/AGENTSEC_BUILD_VS_INTEGRATE.md`, `docs/A2A_TRUST_MODEL.md`.

---

## Classification key

**BUILD** — AgentSec owns the security property, fixtures, controls, telemetry.  
**INTEGRATE** — wrap a real tool and import output as evidence.  
**REFERENCE** — teach from the spec; do not run it.  
**DEFER** — later named phase.  
**REJECT** — would lie, overclaim, or reopen a closed chapter.

| Technology | Decision | Why |
|------------|----------|-----|
| AgentSec CTRL-MCP-001 + coded identity runner | **BUILD** | Only honest grant + A2A-shaped claim lab |
| CTRL-IDENTITY-001 (observe) | **BUILD** (12B+) | Observation ≠ authorization |
| Google / Linux Foundation A2A protocol | **REFERENCE** now; **DEFER** live transport | Spec: Agent Card + HTTP authn; server authz separate. First lab must not fake JSON-RPC. Spec: https://github.com/a2aproject/A2A/blob/v1.0.1/docs/specification.md |
| Cisco a2a-scanner | **DEFER** | Import-output later, like mcp-scanner. Not a PDP. |
| MCP OAuth 2026-07-28 | **REFERENCE / DEFER** | Resource server + RFC 8707 audience. Not AgentSec’s first identity proof. https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization |
| OAuth 2.x / OIDC / RFC 8693 token exchange | **REFERENCE / DEFER** | Teaching analogue for attenuation and `act` chains. Implementing an AS is out of lab scope. https://www.rfc-editor.org/rfc/rfc8693.html |
| SPIFFE / SPIRE | **DEFER** | Workload authn (SVID). Must not become tool authorization. https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/ |
| Cloud IAM (AWS IAM, GCP WIF, Azure MI) | **REJECT** for core | Enterprise overlay; not required to teach INV-001 amplification |
| LangGraph / CrewAI / AutoGen multi-agent | **REJECT** as the control plane | Optional later **adapter**. Property must not depend on a framework |
| AGNTCY | **DEFER** | Directory/identity ecosystem; easy to overclaim |
| OpenTelemetry GenAI conventions | **REUSE / REFERENCE** | Keep `gen_ai.agent.id`; do not invent `session.id` |
| Splunk | **BUILD** investigation later | Never PDP |
| OWASP Agentic Top 10 2026 | **REFERENCE** | ASI03 DIRECT; ASI07 RELATED. https://genai.owasp.org/download/52117 |
| NIST AI 600-1 / 100-2 | **REFERENCE** | Risk/AML language. Not a lab detector. |
| MITRE ATLAS | **REFERENCE** with **REQUIRES REVALIDATION** | AML.T0053 related; do not attach AML.T0073 |
| AgentWatch A2A regex / DID | **REJECT** | Predecessor theater |
| DefenseClaw as AcmeBank | **REJECT** | Same expansion-architecture law |

## BUILD vs INTEGRATE (this chapter)

**BUILD** the smallest in-process A2A-shaped identity lab (12B+).  
**INTEGRATE** nothing in 12A.  
**REFERENCE** A2A, OAuth, SPIFFE, OWASP, NIST, ATLAS.  
**DEFER** live A2A, OAuth AS, SPIRE, a2a-scanner, graph/MLTK.  
**REJECT** regex-A2A, JWT-as-grant, cloud IAM-as-core, framework-as-PDP.

## Cisco

Optional later: a2a-scanner as **imported evidence**, labeled OBSERVED-cli, never FAIL→DENY unless a tested pre-op caller exists. Core lab runs without Cisco.
