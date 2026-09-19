# Identity, delegation, and A2A — predecessor analysis

**Status:** Phase 12A **DESIGN / RESEARCH ONLY**. No runtime. Schema **1.7.0 unchanged**.  
**Lab (planned):** LAB-AGENT-DELEGATION-001. Attack id **A2A-001** (renamed from DELEGATION-001 so it is not mistaken for LAB-MCP-006).  
**Primary invariant:** INV-001 (inspected, not replaced). Supporting: INV-005, INV-004. **No INV-009.**  
**Evidence class:** **DOCUMENTED** research. AgentSec current behavior cited below is **OBSERVED**.  
**Research date:** 2026-09-18.

This phase does **not** reopen MCP, catalog/scanner, RAG, or memory chapters. Those paths remain complete for their designed scope.

---

## What this research is for

When one agent acts on behalf of a user, a service, or another agent, **what identity and authority is it actually permitted to exercise?**

That is not “did someone type a password.” Authentication, identity claims, delegation metadata, and authorization are different facts. MCP-006 already proved one two-agent failure: a **deputy with ambient privilege** spending that privilege for a caller who was not granted it. This chapter asks a **different** question:

Can an **A2A-shaped request**, **caller identity**, or **delegation claim** cause Agent B to obtain authority that **neither Agent A nor Agent B** was coded to have?

That is **authority amplification**, not ambient confused-deputy.

---

## REUSE / REDESIGN / DO NOT REUSE / NOT APPLICABLE

Inspected: INV-001–008, LAB-MCP-006 / CTRL-DELEGATION-001, `coded_policy()`, AllowTicket, per-run overlays, `gen_ai.agent.id`, `agentsec.principal.*`, `delegator.agent.id`, requested/allowed scope, MCP-004 resources, RAG/memory context models, schema 1.7.0, Q-MCP hunts, DET-MCP-001, Splunk field contracts, learning architecture, roadmap.

| Asset | Decision | Why |
|-------|----------|-----|
| **INV-001** | **REUSE (primary)** | “An agent cannot receive more authority than was explicitly delegated.” Amplification is that sentence applied to a **claimed** cross-agent request. Do not invent INV-009. |
| **INV-005** | **REUSE (supporting)** | Identity strings and Agent Cards are claims. Impersonation / trusted-caller lies must be rejected or detectable. First lab does **not** implement cryptographic passports. |
| **INV-004** | **REUSE (supporting)** | Who requested, who delegated, who was authorized, who executed, and on whose behalf must stay separable in evidence. |
| **INV-002** | **REUSE (composition)** | An A2A message body / Agent Card is **data**. Data cannot mint a grant. |
| **INV-003 / RAG / catalog / scanner** | **DO NOT REUSE as the attack** | Memory, retrieval, and catalog already taught content-as-grant. Keep those chapters closed. |
| **INV-006** | **NOT APPLICABLE for first lab** | No workflow-state skip. The loan `/process` sequence stays untouched. |
| **INV-007** | **REUSE (evidence duty)** | Principal → A → B → request → authz → execution must be reconstructable. |
| **INV-008** | **REUSE** | Missing identity/delegation context must not fail-open except the labeled lab overlay. |
| **CTRL-MCP-001** | **REUSE** | Only tool authorization engine. Do not create a second tool PDP. |
| **`coded_policy()` / AllowTicket** | **REUSE pattern** | Server-owned grants. Check/use bind remains. |
| Per-run overlay | **REUSE pattern** | One labeled fail-open: `vulnerable_profile_fail_open:caller_identity_derived_authority`. No global mutation. |
| Follow-on `lookup_customer_tier` / `customer:read` | **REUSE** | Harmless privileged teaching tool. Same banking function; **different** authority story than MCP-006. |
| A/B/C + same adversarial request | **REUSE** | ATTACK and RETEST use the **same** A2A-shaped request. Discriminator is authorization. |
| Handler counts / evidence packs | **REUSE** | Non-execution proof remains runtime invoke count. |
| Q-MCP-AUTHZ / TOOL / EXECUTED / AFTER-DENY | **REUSE later** | After 12B field discovery. **No SPL in 12A.** |
| DET-MCP-001 | **REUSE / UNCHANGED** | DENY-then-start only. Expected silent on preferred ATTACK. |
| **CTRL-DELEGATION-001** | **DO NOT REUSE / DO NOT OVERLOAD** | That control already means MCP-006 **ambient vs delegated** on credit→compliance. Overloading it would collapse two labs. |
| `agentsec.delegation.authority.source` enum `delegated` \| `ambient_deputy` | **DO NOT OVERLOAD** | Closed MCP-006 meanings. A2A claim is not ambient deputy. |
| `agentsec.delegator.agent.id` | **REUSE later as attribution only** | In-process prior hop. Not an A2A passport. Not a grant. |
| `gen_ai.agent.id` / `agentsec.principal.id` | **REUSE** | Already emitted. Insufficient alone to reconstruct claimed vs granted A2A authority. |
| HTTP extra-field reject | **REUSE** | Clients cannot supply `allowed_tools`, agent ids, or tokens as grants. |
| AgentWatch A2A regex / DID / `Delegation-Chain:` | **DO NOT REUSE** | Theater. Content-derived identity. **DROP** as control (already classified in MCP-006 predecessor). |
| Four-agent `/process` LLM path | **DO NOT BOLT ON** | Sequential in-process hops are **not** A2A. Dedicated lab runner. |
| Live A2A JSON-RPC / OAuth / SPIFFE | **DEFER** | Teaching analogues only in 12A. No protocol transport. |
| Completed MCP / RAG / memory workshops | **KEEP CLOSED** | Do not reopen. |

---

## MCP-006 vs this chapter (must stay separate)

| | LAB-MCP-006 (done) | LAB-AGENT-DELEGATION-001 (planned) |
|--|--------------------|--------------------------------------|
| Failure | Confused deputy: B **has** ambient `customer:read`, A does not, A induces B to spend **B’s** grant | Authority amplification: **neither** A nor B is coded `customer:read`; the **A2A/caller claim** is treated as a grant |
| Agents | credit-002 → compliance-004 | New coded pair (advisor-005 → fulfillment-006). Do not reuse MCP-006 ids. |
| Control | CTRL-DELEGATION-001 ALLOW/DENY then CTRL-MCP-001 | Proposed CTRL-IDENTITY-001 **OBSERVE**, then CTRL-MCP-001 ALLOW/DENY |
| Overlay | `ambient_deputy_authority` | `caller_identity_derived_authority` |
| In-process? | Yes (not network A2A) | Yes for first lab (A2A-**shaped** request; not live A2A transport) |
| What “on behalf of” means | Caller asks deputy to use deputy ambient | Caller asks callee to exercise a privilege **nobody in the chain was granted** |

MCP-006 remains the confused-deputy lab. This chapter does **not** re-teach it.

---

## What AgentSec already emits (OBSERVED)

| Field | What it can prove today | What it cannot prove |
|-------|-------------------------|----------------------|
| `agentsec.principal.id` / `.type` | Lab HTTP initiator (`applicant-web`, type `user`) | Human authentication, OAuth subject, tenant |
| `gen_ai.agent.id` | Coded agent for **this hop** | Caller vs callee on an A2A request; verified identity |
| `agentsec.delegator.agent.id` | Prior **in-process** hop when `hop.index >= 1` | A2A caller, delegation chain, cryptographic identity |
| `requested_scope` / `allowed_scope` | What this MCP hop asked vs coded grant | Whether a **claimed** delegated scope was validated |
| `CTRL-DELEGATION-001` + `authority.source` | MCP-006 ambient vs delegated | A2A claim trust |
| `run.id` | One lab invoke / pipeline | Cross-agent protocol session (do not invent `session.id`) |

**TELEMETRY GAP (honest):** grant snapshot (`allowed_tools`) still absent from the index. Writer≠reader, tenant, `gen_ai.tool.call.id` still absent. 12A does not invent them.

---

## AgentWatch / predecessor theater (do not copy)

Already **OBSERVED** in `docs/MCP006_PREDECESSOR_ANALYSIS.md`:

- Prompt regex DID → `requesting_agent_id`
- `Delegation-Chain:` copied as a string
- `cryptographic_passport_valid=True` with no key
- Global `_AGENT_USED_SCOPE`

**DROP** as controls. Teaching contrast only: **IDENTITY CLAIM != VERIFIED IDENTITY.**

---

## Industry research used (primary)

| Source | URL | Use |
|--------|-----|-----|
| A2A Protocol spec v1.0.1 | https://github.com/a2aproject/A2A/blob/v1.0.1/docs/specification.md | Agent Card is discovery + **declared** auth schemes. Authn ≠ authz. Servers MUST authorize independently. |
| A2A v1 notes | https://github.com/a2aproject/A2A/blob/main/docs/whats-new-v1.md | PKCE, no implicit/password; extended Agent Card is **authenticated** metadata, still not a grant. |
| MCP authorization (2026-07-28) | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization | MCP server is an OAuth **resource server**. Audience-bound tokens. REFERENCE; do not implement in 12A. |
| RFC 8693 Token Exchange | https://www.rfc-editor.org/rfc/rfc8693.html | Delegation vs impersonation; attenuation; `act` chain. Teaching analogue. No tokens in the lab. |
| OWASP Agentic Top 10 2026 | https://genai.owasp.org/download/52117 | ASI03 Identity & Privilege Abuse **DIRECT**. ASI07 related (message/card spoof), not the first ATTACK. |
| NIST AI 600-1 | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf | RELATED risk profile. Not a technique mapping. |
| NIST AI 100-2e2025 | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf | AML taxonomy. **UNMAPPED** for this architectural grant failure. |
| MITRE ATLAS data | https://github.com/mitre-atlas/atlas-data (AML.T0053 in `techniques.yaml`) | RELATED / **REQUIRES REVALIDATION** against atlas.mitre.org HTML (name has shifted: plugin compromise vs agent tool invocation). |
| SPIFFE ID / SVID | https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/ | Workload identity ≠ agent grant. DEFER. Do not log SVID/JWT bodies. |

Do not invent MITRE IDs. AML.T0073 (impersonation of a person/org in ATLAS) is **UNMAPPED** for the preferred ATTACK. ATT&CK T1134 Windows token impersonation is **UNMAPPED**.

---

## Invariant decision (preview)

The candidate sentence “an agent cannot acquire, amplify, or delegate authority beyond the validated authority of the principal and delegation chain” is **INV-001 restated** for a principal + A2A hop. Existing MCP-006 coverage is **insufficient pedagogically** (ambient deputy, different agents, different overlay) but **sufficient as an invariant**. **Do not create INV-009.**

---

## Stop

Do not start Phase 12B from this file. No runtime, schema bump, SPL, DET-DELEGATION, DET-A2A, Studio, OAuth, SPIFFE, or A2A transport.
