# AGENTSEC P1.6 — Enterprise telemetry and SIEM coverage matrix

**Purpose:** Coverage and roadmap. Not a requirement to integrate dozens of vendors before 15 October 2026.

**Evidence class:** DOCUMENTED from the repository and adapters. LIVE INTEGRATION claims below were independently MEASURED only where a search or launch is cited.

**Support vocabulary (exactly one per category):**

| Label | Meaning |
|-------|---------|
| LIVE INTEGRATION | Working source and validated ingestion on this lab |
| VALIDATED SAMPLE | Representative data with tested parsing or analysis |
| DOCUMENTED REFERENCE | Architecture, mapping, or teaching text only |
| NOT SUPPORTED | No meaningful implementation |

Do not represent a sample event as a working vendor product. Do not introduce production credentials.

Splunk Enterprise (lab container) is the only SIEM with live ingestion in this project. Other SIEM names are **not** supported products here.

---

## Category matrix

### 1. Endpoint detection and response

| Field | Value |
|-------|--------|
| Representative technologies | CrowdStrike, Microsoft Defender for Endpoint, SentinelOne |
| Relevant signals | Process start, file write, script execution, agent binary |
| AgentSecLab sources | None |
| Ingestion | None |
| Normalization | None |
| Correlation opportunity | Host process around an MCP handler (roadmap) |
| Validated detections | None |
| Support | **NOT SUPPORTED** |

### 2. Network detection and response

| Field | Value |
|-------|--------|
| Representative technologies | ExtraHop, Darktrace, NetWitness |
| Relevant signals | East-west flows, DNS, TLS JA3 |
| AgentSecLab sources | None as NDR |
| Support | **NOT SUPPORTED** |

Compose publishes exclusive localhost ports. That is lab binding, not NDR.

### 3. Firewalls and secure web gateways

| Field | Value |
|-------|--------|
| Representative technologies | Palo Alto NGFW, Zscaler, Cisco Umbrella |
| Support | **NOT SUPPORTED** |

### 4. Identity and access management

| Field | Value |
|-------|--------|
| Representative technologies | Okta, Entra ID, Ping |
| AgentSecLab sources | Educational `agentsec.principal.id` / `gen_ai.agent.id` on runtime events |
| Ingestion | OTel → HEC → `otel:agentic:json` |
| Normalization | AgentSec closed schema fields |
| Correlation opportunity | Same principal across ATTACK/RETEST |
| Validated detections | None for IdP |
| Support | **DOCUMENTED REFERENCE** for NHI workshops; **NOT SUPPORTED** as Okta/Entra |

Identity authentication is not modeled (no OAuth/OIDC/SPIFFE). LAB-AGENT-IDENTITY-NHI is REPLAY teaching.

### 5. Cloud audit and control plane

| Field | Value |
|-------|--------|
| Representative technologies | AWS CloudTrail, Azure Activity, GCP Audit |
| Support | **NOT SUPPORTED** |

### 6. Kubernetes and container security

| Field | Value |
|-------|--------|
| Representative technologies | Falco, Prisma Cloud, GuardDuty EKS |
| AgentSecLab sources | Docker Compose labels only |
| Support | **NOT SUPPORTED** as K8s security. Compose is the lab runtime, not a KSPM product. |

### 7. Vulnerability and exposure management

| Field | Value |
|-------|--------|
| Representative technologies | Tenable, Qualys, Wiz |
| AgentSecLab sources | Cisco mcp-scanner adapter + committed finding packs |
| Ingestion | `agentsec:scanner:finding` (finding plane) |
| Normalization | Scanner evidence contract; findings do **not** authorize tools |
| Correlation opportunity | Scanner finding vs later CTRL-MCP-001 decision on the same lab |
| Validated detections | Teaching searches in scanner workshop; not ES notables |
| Support | **VALIDATED SAMPLE** (scanner packs). Not a Tenable/Wiz integration. |

### 8. Threat intelligence

| Field | Value |
|-------|--------|
| Representative technologies | TAXII, MISP, vendor intel |
| Support | **NOT SUPPORTED** |

ATLAS labels on labs are educational and **REQUIRES REVALIDATION**. Not MITRE-verified mappings.

### 9. Email and collaboration security

| Field | Value |
|-------|--------|
| Support | **NOT SUPPORTED** |

### 10. SaaS audit

| Field | Value |
|-------|--------|
| Representative technologies | Salesforce, GitHub audit, M365 |
| Support | **NOT SUPPORTED** |

### 11. Data security and DLP

| Field | Value |
|-------|--------|
| Representative technologies | Purview, Nightfall, Netskope DLP |
| AgentSecLab sources | Privacy workshop REPLAY; `untrusted_data` on MCP results |
| Support | **DOCUMENTED REFERENCE** (INV-002 / privacy labs). **NOT SUPPORTED** as DLP product. |

### 12. HR and insider-risk context

| Field | Value |
|-------|--------|
| Support | **NOT SUPPORTED** |

### 13. AI agent runtime and MCP

| Field | Value |
|-------|--------|
| Representative technologies | AgentSec AcmeBank runtime, in-process MCP JSON-RPC, CTRL-MCP-001 |
| Signals | `agentsec.control.decision`, `agentsec.mcp.started`, scopes, profile, run.id, schema version |
| Ingestion | OTLP → collector HEC → Splunk `agentsec_telemetry` / `otel:agentic:json` |
| Normalization | Runtime schema **1.9.0** (LIVE). Historical REPLAY packs **1.1.0**. |
| Correlation | ATTACK vs RETEST by run.id; decision vs handler start |
| Validated searches | Academy evidence API; `scripts/p1_6_reconcile_live_evidence.py` — 4 LIVE + 3 REPLAY run.ids reconciled local vs Splunk (events, single decision, `mcp.started`, `pipeline.stopped`), P1.6 MEASURED |
| Support | **LIVE INTEGRATION** |

This is the October 15 demonstration core.

### 14. Application and API telemetry

| Field | Value |
|-------|--------|
| Representative technologies | OpenTelemetry traces, application logs |
| AgentSecLab sources | OTel GenAI + `agentsec.*` on the lab runtime |
| Ingestion | OTLP 4317/4318 → collector |
| Support | **LIVE INTEGRATION** for the lab app. Not a general APM vendor. |

### 15. Infrastructure and network telemetry

| Field | Value |
|-------|--------|
| Representative technologies | Syslog, NetFlow, cloud VPC flow |
| AgentSecLab sources | Container stdout; collector file/HEC |
| Support | **DOCUMENTED REFERENCE** for lab ops. **NOT SUPPORTED** as infra SIEM onboarding. |

---

## Adjacent AgentSec planes (not the 15 categories, listed so they are not over-claimed)

| Plane | Sourcetype / contract | Support |
|-------|----------------------|---------|
| Scanner findings | `agentsec:scanner:finding` | VALIDATED SAMPLE |
| External evaluations (garak) | `agentsec:external:evaluation` / ExternalEvidence 1.0.0 | VALIDATED SAMPLE |
| Splunk Enterprise (this lab) | index `agentsec_telemetry` | LIVE INTEGRATION |
| Other SIEM products | — | NOT SUPPORTED |

ExternalEvidence **1.0.0** applies to garak/scanner packs. It is **not applicable** to LAB-MCP-001 runtime events.

---

## Example correlation (teaching, not a shipped notable)

If a future workshop had both a scanner finding and a LIVE MCP run:

1. Finding plane: tool exists / description risk (does not grant).
2. Runtime: CTRL-MCP-001 ALLOW or DENY on `lookup_customer_tier`.
3. Execution: `agentsec.mcp.started` present or NOT OBSERVED.

P1.6 does not claim that correlation is a published detection.

---

## Missing integration work (roadmap only)

EDR, NDR, firewall/SWG, IdP, cloud audit, Kubernetes, vuln scanners as products, threat intel, email, SaaS audit, DLP, HR. Also: MLTK, ES notables, DET-CAPSTONE, Microsoft Sentinel, Elastic, QRadar, Chronicle.

None of this is required for the October 15 LAB-MCP-001 demonstration.

## Prioritised Phase 2 gaps (recommendation; owner decides)

Ordered by how directly each gap strengthens the AgentSec lifecycle (attack → control → telemetry → Splunk → detection → evidence) at the lowest added complexity. This is INFERRED prioritisation, not a measured requirement.

| Priority | Gap | Current label | Why first | Smallest useful next step |
|----------|-----|---------------|-----------|---------------------------|
| P2-1 | AI agent runtime beyond LAB-MCP-001 | LIVE INTEGRATION (one lab measured) | The other six LIVE-capable labs are not re-measured; model-dependent paths are DEGRADED on this host | Restore the lab model, re-run and reconcile each allowlisted LIVE lab with the P1.6 script |
| P2-2 | Detection engineering on runtime telemetry | Packaged, all disabled | Detections are the SOC payoff; DET-MCP-001 cannot see fail-open ALLOW | Owner decision on enabling/revising DET-MCP-001 in the lab only |
| P2-3 | Identity (IdP / non-human identity) | DOCUMENTED REFERENCE | INV-004/INV-005 depend on principal attribution; today identity is educational fields only | VALIDATED SAMPLE: synthetic IdP sign-in events correlated to `agentsec.principal.id` |
| P2-4 | Vulnerability / exposure | VALIDATED SAMPLE | Scanner finding plane exists; correlation with runtime decisions is the missing teaching link | One correlation search, scanner finding vs CTRL-MCP-001 decision |
| P2-5 | Cloud audit control plane | NOT SUPPORTED | Agent tools in practice call cloud APIs | VALIDATED SAMPLE CloudTrail-shaped events, no live account |
| P2-6 | EDR / host process | NOT SUPPORTED | Shows what a handler did on the host after ALLOW | VALIDATED SAMPLE process events around a handler start |
| P2-7 | DLP / data security | DOCUMENTED REFERENCE | Customer-tier read is a data exposure; DLP would see it | Sample classification event on the MCP result |
| Later | NDR, firewall/SWG, Kubernetes, threat intel, email, SaaS audit, HR, other SIEMs | NOT SUPPORTED | Lower direct value for the agent-runtime curriculum | Stay DOCUMENTED REFERENCE until an owner-approved lab needs them |

Prefer VALIDATED SAMPLE before LIVE INTEGRATION. Do not add production credentials or vendor accounts.
