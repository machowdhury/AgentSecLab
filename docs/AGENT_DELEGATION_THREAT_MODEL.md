# Agent delegation threat model

**Status:** Phase 12A **DESIGN**. Runtime **ABSENT**. Schema **1.7.0 unchanged**.  
**Attack id:** **A2A-001**. Lab: LAB-AGENT-DELEGATION-001.  
**Evidence class:** **DOCUMENTED**.

Parents: `docs/AGENT_IDENTITY_SECURITY_MODEL.md`, `docs/IDENTITY_DELEGATION_PREDECESSOR_ANALYSIS.md`.

---

## Security question

When Agent A asks Agent B to perform an operation “on behalf of” a principal, can that **request** (or the caller’s identity) **amplify** authority beyond the **coded** grants of principal, A, and B?

## Invariant decision — no INV-009

Candidate: “An agent cannot acquire, amplify, or delegate authority beyond the validated authority of the principal and delegation chain under which it is acting.”

| Existing invariant | Coverage |
|--------------------|----------|
| **INV-001** Delegated authorization | **Covers the property.** Amplification is receiving more authority than was explicitly delegated. |
| **INV-005** Agent identity integrity | Covers **spoofed / unverified identity**. Does not by itself describe grant algebra. |
| **INV-004** Privileged action attribution | Covers **who** must appear in evidence. Not the grant decision. |
| **INV-002** | Covers A2A payload as **data**. Composition, not a replacement. |

MCP-006 already **used** INV-001 for **ambient deputy**. That specimen is not this specimen. Pedagogical gap ≠ missing invariant.

**Decision:** do **not** create INV-009. State the teaching sentence as INV-001 applied to **principal + A2A claim**. Evidence that proves it: coded grants vs requested tool + CTRL-MCP-001 decision + handler count. Evidence that cannot prove it: identity strings, Agent Cards, Splunk silence, DET-MCP-001 0 rows.

## Assets

- Coded tool grants for Agent A and Agent B (`{lookup_policy}` only)
- Customer-tier fixture (`cust-001`) — harmless privileged read
- Principal label `applicant-web`
- Future: Agent Card / A2A message as **untrusted metadata**

## Attackers

| Attacker | What they can influence | What they cannot |
|----------|-------------------------|------------------|
| Lab operator / fixture | Requested tool+scope on the A2A-shaped call | Coded `allowed_tools`, agent ids |
| Compromised Agent A (story) | What A asks B to do | B’s coded policy in `defended` |
| Network attacker (deferred) | Live A2A/MITM | Out of first lab |

## Threats (architectural)

### T1 — Authority amplification (PREFERRED ATTACK)

Agent A requests `lookup_customer_tier`. Neither A nor B is coded `customer:read`. Vulnerable profile treats **caller identity / claimed delegation** as authority. CTRL-MCP-001 ALLOW. Handler 1.

**Not:** regex, magic phrase, fake token, client `allowed_tools`, global mutation, RAG/memory/scanner.

### T2 — Confused deputy (ALREADY TAUGHT)

Agent B **has** the privilege; A induces B to spend it. **LAB-MCP-006.** Do not duplicate as 12A ATTACK.

### T3 — Identity spoofing

Request content claims `gen_ai.agent.id` of a privileged agent. First lab: extra HTTP/identity keys **ERROR** (existing reject). Preferred ATTACK is T1, not spoof-as-success.

### T4 — Token forwarding / OAuth impersonation

Forwarding a broad user token to B. **DEFER** (needs OAuth). Teaching analogue: RFC 8693 attenuation. Do not implement tokens.

### T5 — Agent Card as grant

Skills listed on an A2A Agent Card treated as `allowed_tools`. **RELATED** (ASI07). First lab may show a **fixture card** as OBSERVE-only metadata, not a live registry.

### T6 — Delegation-chain expansion

A delegates subset; B re-delegates a wider set. **DEFER** (multi-hop). First lab is one hop.

## Confused deputy vs amplification (do not collapse)

| Question | MCP-006 | A2A-001 |
|----------|---------|---------|
| Does B possess authority A lacks? | **Yes** (ambient `customer:read`) | **No** (B also lacks it) |
| Can A induce B to exercise B’s own authority? | That **is** the lab | Not this lab |
| Should B act under its own identity or delegated principal? | Own identity, **delegated** grant | Own identity, **own** coded grant; principal is attribution |
| What should be attenuated? | Caller→deputy delegated set | Claimed scope cannot exceed coded grants of A **and** B **and** principal |
| Which principal appears in telemetry? | `applicant-web` | `applicant-web` (same) |
| Which identity caused the operation? | Credit asked; compliance executed | Advisor asked; fulfillment would execute only after ALLOW |
| What does “on behalf of” mean? | Attribution + delegated grant check | Attribution only; it is **not** a grant |
| Can caller identity be trusted as authority? | **No** | **No** — that **is** the fail-open |
| Can delegation metadata become authority? | Ambient set was the lie | Claimed scope is the lie |
| Can the tool distinguish direct vs delegated access? | Not today (`tool.call.id` absent) | Still absent; do not invent |

Keep six columns in teaching:

WHO REQUESTED · WHO DELEGATED · WHO AUTHENTICATED · WHO WAS AUTHORIZED · WHO EXECUTED · ON WHOSE BEHALF

First lab authenticates **nothing cryptographically**. Ids are coded. “WHO AUTHENTICATED” is taught as **ABSENT / not proven**, not faked as `passport_valid=True`.

## Framework mapping

| Framework | ID | Classification | Note |
|-----------|----|----------------|------|
| OWASP Agentic 2026 | ASI03 Identity & Privilege Abuse | **DIRECT** | Un-scoped inheritance; cross-agent trust. Official: https://genai.owasp.org/download/52117 |
| OWASP Agentic 2026 | ASI07 Insecure Inter-Agent Communication | **RELATED** | Message/card spoof, MITM. Not the first ATTACK. |
| OWASP LLM | LLM06 Excessive Agency | **RELATED** | Over-agency; not the precise A2A claim-as-grant story |
| A2A spec v1.0.1 | Authn vs authz sections | **RELATED** | Agent Card declares schemes; server MUST authorize separately |
| RFC 8693 | Token exchange | **RELATED** | Delegation ≠ impersonation; attenuation. Not implemented. |
| MCP auth 2026-07-28 | Resource server / RFC 8707 | **RELATED** | Audience-bound tokens. Not implemented. |
| MITRE ATLAS | AML.T0053 | **RELATED / REQUIRES REVALIDATION** | YAML name “AI Agent Tool Invocation”; older materials “LLM Plugin Compromise”. No dedicated atlas.mitre.org HTML verified in this research window. |
| MITRE ATLAS | AML.T0073 Impersonation | **UNMAPPED** | Person/org social impersonation. Do not inherit AgentWatch mapping. |
| MITRE ATT&CK | T1134 | **UNMAPPED** | Windows access tokens. |
| NIST AI 600-1 | GenAI profile | **RELATED** | Risk actions, not a technique. |
| NIST AI 100-2e2025 | AML taxonomy | **UNMAPPED** | Does not name this architectural grant failure. |
| SPIFFE | SVID | **UNMAPPED** as a grant | Workload authentication analogue only. |

Do not invent MITRE IDs.

## STRIDE (short)

| | Mapping |
|--|---------|
| Spoofing | T3 deferred as negative test |
| Tampering | Live A2A MITM deferred (ASI07) |
| Repudiation | INV-004 evidence duty |
| Information disclosure | Token/JWT logging forbidden |
| Denial of service | Out of scope |
| Elevation of privilege | **T1 preferred** |

## Vulnerable profile (one)

`vulnerable_profile_fail_open:caller_identity_derived_authority`

- LAB ONLY, per-request, recall-equivalent: does **not** persist
- Does not mutate `coded_policy()` / `ALLOWED_TOOLS`
- Cannot survive into RETEST
- Not a production IOC

## Defended profile

CTRL-IDENTITY-001 OBSERVE (claim recorded). CTRL-MCP-001 DENY `tool_not_granted` for `lookup_customer_tier`. Handler 0.

## What we refuse to model as the ATTACK

Prompt injection alone, catalog/RAG/memory overlays, scanner FAIL, Splunk as PDP, LLM as PDP, hardcoded admin, client-supplied grants, fake JWTs that “succeed.”

## Security review (anti-patterns)

| Anti-pattern | Design response | Severity if missed |
|--------------|-----------------|-------------------|
| Caller-provided `allowed_tools` | Extra-key ERROR. Grants remain `coded_policy()`. | BLOCKER — **closed** |
| Caller-provided scopes as grants | `claimed_scope` is observation only; `allowed_scope` is coded | BLOCKER — **closed** |
| Caller-provided identity as trusted identity | Ids coded in runner; prompt/DID ignored | BLOCKER — **closed** |
| Delegation metadata as authority | Overlay is the only lie; labeled lab-only | BLOCKER — **closed** (vulnerable path explicit) |
| Downstream inherits all caller privileges | B’s coded set is independent and **smaller or equal**, never union-with-A | BLOCKER — **closed** |
| Upstream inherits downstream privileges | A is not coded `customer:read` even if a later agent were | BLOCKER — **closed** |
| Global policy mutation | Per-request overlay; MCP-006 already forbade globals | BLOCKER — **closed** |
| Persisted vulnerable overlay | Must not survive RETEST | BLOCKER — **closed** in spec |
| Bearer / JWT / Authorization logging | Privacy model: do not index | BLOCKER — **closed** |
| Secrets in evidence bundles | Same privacy model | BLOCKER — **closed** |
| Splunk as PDP | Investigation only | HIGH — **closed** in teaching |
| LLM as PDP | Coded runner; LLM does not ALLOW | HIGH — **closed** |
| ML as PDP | FUTURE teaser only | HIGH — **closed** |
| Authentication as authorization | Taught as 401 vs 403 / OBSERVE vs CTRL-MCP-001 | HIGH — **closed** |
| `mcp.started` as success | Existing MCP teaching | HIGH — **closed** |
| DENY as proof of non-execution | Handler count authoritative | HIGH — **closed** |
| Missing telemetry as prevention | Completeness rules unchanged | HIGH — **closed** |

No remaining BLOCKER/HIGH design defects for 12A. Implementation defects are out of scope until 12B.
