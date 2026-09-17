# Phase 7A reviews — MCP-006 (design only)

**Date:** 2026-09-14  
**Scope:** LAB-MCP-006 confused deputy / delegated authority **design**. No runtime.  
**Skills:** architecture-review, logic-proof, learning-review.  
**Evidence class:** **DOCUMENTED**. No pytest was run for MCP-006 because no MCP-006 code exists. Last unrelated pytest remains Phase 6D (312 passed, 2 deselected).

All BLOCKER and HIGH design findings below were **resolved in the design documents** in this phase. MEDIUM/LOW remain open for 7B judgment, not 7A blockers.

---

## Architecture review

1. **Problem:** A more-privileged deputy must not spend ambient authority for a less-privileged caller.
2. **Learning objective:** CALLER AUTHORITY ≠ DEPUTY AUTHORITY; delegated ≠ ambient.
3. **Existing AgentSec:** `POST /mcp/invoke`, CTRL-MCP-001, hop/delegator fields, extra-field HTTP contract, handler counters, AllowTicket idea, fixtures `lookup_policy` / `lookup_customer_tier`.
4. **AgentWatch:** DROP enforcement (prompt DID, global used-scope, same mcp_scope on every agent). REDESIGN placement only.
5. **Proposed components:** coded credit caller + compliance deputy; CTRL-DELEGATION-001; per-request policy object selection; DelegationTicket; later additive schema bump. **No new HTTP identity fields. No IAM platform. No A2A network.**
6. **Data flow:** lab runner codes identities → hop 0 delegation control → (ALLOW) hop 1 MCP-001 → handler.
7. **State:** coded immutable grants; per-request ambient consult on vulnerable only; no global mutation.
8. **Trust boundaries:** HTTP schema; CTRL-DELEGATION-001; `acmebank.mcp.authorize`; handler.
9. **Attacker-controlled:** `tool`, `arguments`, `requested_scope`, `user_id` only.
10. **Invariants:** INV-001 primary; INV-004, 005, 006, 007, 008 secondary. No INV-009.
11. **Failure modes:** ambient fail-open (labeled); identity spoof (reject); missing context (ERROR).
12. **Observability:** later `mcp_delegation` + `authority.source`; reuse hops for identities.
13. **Splunk:** questions only in 7A; no SPL; DET-MCP-001 will not see preferred ATTACK.
14. **Tests:** listed in lab spec; not implemented.
15. **Alternatives considered:**
    - Identity-spoof-as-ATTACK (`MCP_LAB_PLAN` sketch) — **rejected** as too small; kept as negative test.
    - LLM `/process` path — **rejected** (nondeterministic; wrong workflow).
    - New `/mcp/delegate` API — **rejected** (extra surface; not needed).
    - Full OAuth token exchange / RFC 8693 — **rejected** (IAM platform).
    - New caller/deputy schema id fields — **deferred**; hop reuse first.
16. **Why simplest:** two existing agents, two existing tools, one new control, one fail-open reason, same ATTACK/RETEST payload.

**Uncertain (open questions, not blockers):** exact 7B schema version string; whether `trust_boundary` needs a new enum value; whether hop 0 `gen_ai.tool.name` teaching needs extra copy in Studio later.

**Stop:** no implementation.

---

## Logic proof (design-time)

| Item | Design answer |
|------|----------------|
| SECURITY PROPERTY | Deputy executes only if **delegated** authority includes the operation (defended). |
| ASSUMPTIONS | Coded identities; deterministic grants; LLM out of path; HTTP extra fields rejected. |
| ATTACKER-CONTROLLED INPUT | MCP invoke body fields in the allow-list. |
| TRUST BOUNDARY | CTRL-DELEGATION-001 before hop 1 MCP. |
| CODE PATH | Not implemented. Specified: runner → hop 0 control → hop 1 authorize → handler. |
| DECISION POINTS | Delegation control; then existing MCP-001. |
| DANGEROUS OPERATION | `lookup_customer_tier` handler (fixture only). |
| WHERE VALIDATION OCCURS | Before hop 1 / before handler. |
| FAILURE PATH | DENY or ERROR; handler 0. |
| FAIL-OPEN POSSIBILITY | **Intentional and labeled** on vulnerable: ambient set. Must not occur on missing context. |
| TELEMETRY | Proposed; not on 1.3.0. |
| UNIT / NEGATIVE / INTEGRATION / BYPASS TESTS | Specified; not written. |

Could the dangerous operation happen before validation? **Not if 7B follows placement.**  
Could missing context become ALLOW? **Designed no** (ERROR).  
Could one agent inherit another’s authority? **That is the ATTACK**, labeled, per-request only.  
Could telemetry report DENY after the operation? **Forbidden**; RETEST has no hop 1.  
Which assertion lacks a test? **All of them** — no runtime yet.

**Tests run:** none for MCP-006 (no code). Do not claim pass.

---

## Learning review (design)

Teach from **design docs**, not from unimplemented files.

1. Architecture: two coded agents on MCP lab workflow; not A2A.
2. Components: CTRL-DELEGATION-001 + CTRL-MCP-001 + tickets + handler counters.
3. Legitimate path: credit asks `lookup_policy`; both grants include it; execute.
4. Attack path: credit asks `lookup_customer_tier`; deputy ambient includes it; vulnerable consults ambient.
5. Files involved **later:** `mcp/pipeline.py`, `authorize.py`, new small delegation module, schema bump, tests. **Today:** design docs only.
6. Trust boundary: caller → deputy.
7. Invariant: INV-001.
8. Control: CTRL-DELEGATION-001.
9. Telemetry: hops + proposed authority.source.
10. Splunk: questions Q1–Q10; no SPL.
11. Tests: not yet.
12. Limitations: schema 1.3.0 cannot emit the control; grant lists not indexed; same tool name as MCP-005 follow-on.

Questions (do not answer here — for the repository owner):

1. In one sentence, what is a confused deputy without using the word “prompt”?
2. Name the locked caller and deputy ids.
3. What three authority sets does the lab distinguish?
4. What is the defended effective-authority rule?
5. Why is identity spoof not the preferred ATTACK?
6. What is the vulnerable reason string?
7. What is the defended DENY reason string?
8. Where does CTRL-DELEGATION-001 sit relative to the handler?
9. Why will DET-MCP-001 be silent on ATTACK B?
10. Which current schema version is live, and can it emit CTRL-DELEGATION-001?
11. How do ATTACK and RETEST differ?
12. What proves non-execution on RETEST?
13. Why must grants not be mutated globally?
14. How is this not MCP-005?
15. What should you refuse to map from AgentWatch without evidence?

---

## Security review (adversarial)

Roles: senior AppSec, agent-security researcher, IAM engineer, SOC detection engineer.

### BLOCKER

None remaining.

| Was | Resolution |
|-----|------------|
| Using `/process` + LLM as the deputy | Locked MCP lab runner + coded ids |
| Identity spoof as the A/B/C ATTACK | Redesigned to ambient-authority misuse; spoof is sequence D |
| “Turn authorization off” vulnerable mode | Explicit ambient consult + stable reason |
| Emitting MCP-006 on schema 1.3.0 | 7A leaves schema unchanged |
| Creating DET-MCP-006 / SPL / Studio | Forbidden this phase |
| Inheriting AgentWatch DID / AML.T0073 | DROP |
| Client-supplied grants or deputy id | Extra-field reject reused |
| Global `_AGENT_USED_SCOPE` analogue | DROP; per-request only |

### HIGH

None remaining.

| Was | Resolution |
|-----|------------|
| Check after execution | Hop 0 control; no hop 1 on DENY |
| Identity/authz collapsed to one boolean | Separate identity fields vs grant membership |
| ATTACK/RETEST different payloads | Same request locked |
| Malformed treated as ATTACK | ERROR / HTTP reject |
| Fail-open on exception | ERROR `delegation_control_error` |
| Detector requiring nonexistent fields | Detection ANALYZED; no detector |
| Unnecessary IAM / A2A / Cisco | Out of scope |

### MEDIUM

| Id | Finding | Disposition |
|----|---------|-------------|
| M1 | Same tool `lookup_customer_tier` as MCP-005 follow-on can confuse learners | Accept; teaching must contrast invariants. Do not change the tool (clearest ambient gap). |
| M2 | Grant sets still not indexed — Q3/Q4/Q9 not Splunk-provable | Accept; same honesty as 6C. Runtime remains authoritative. |
| M3 | Hop 0 `gen_ai.tool.name` might be misread as execution | Accept; workshop later must contrast event.name. |
| M4 | `delegator.agent.id` first MCP use with different agent | Accept; schema already allows; document “not A2A.” |
| M5 | Framework mappings mostly NEEDS VERIFICATION | Accept; CWE-441 is the only close classic ID, still not workshop-claimed. |

### LOW

| Id | Finding | Disposition |
|----|---------|-------------|
| L1 | Two hops vs one hop with extra fields | Prefer two hops to reuse schema. |
| L2 | New `trust_boundary` enum vs reuse `acmebank.mcp.authorize` | Defer to 7B; prefer fewer enums if `mcp_delegation` exists. |
| L3 | Repeated same-tool correlation gap | Known; not this A/B/C. |

---

## Design simplicity review

| Question | Answer |
|----------|--------|
| Fewer concepts? | Could drop hop 0 and put caller only in a new field — **more** schema, not less. |
| Reuse MCP infra? | Yes: invoke path, CTRL-MCP-001, fixtures, tickets, counters. |
| Accidentally building IAM? | No: two frozen sets, one relationship, no token exchange. |
| Abstractions only for future labs? | DelegationTicket is MCP-004-shaped, needed for TOCTOU. |
| Understandable in five minutes? | Yes, if teaching table (caller may ask / deputy may execute / which grant) is the first slide. |

---

## Framework mappings (design)

| Framework | Mapping | Evidence |
|-----------|---------|----------|
| CWE-441 Unintentional Proxy / Confused Deputy | **PLANNED / NEEDS VERIFICATION** of exact CWE text in workshop copy | Classic CS match; do not claim in 7A as MEASURED |
| MITRE ATLAS | **Do not inherit** AgentWatch AML.T0073. No dedicated ATLAS “confused deputy” technique verified. AML.T0053 (tool invocation) is too generic. | **NEEDS VERIFICATION**; leave unmapped |
| OWASP LLM “Excessive Agency” / Agentic privilege compromise | Often about **model** choosing extra tools or **prompt-injection chains** | **NEEDS VERIFICATION**; likely **not** primary (our failure is coded authz) |
| NIST AI RMF | Too coarse without a specific subcategory | **NEEDS VERIFICATION** / omit |
| NIST SP 800-53 AC-3 / AC-6 | Cited in third-party writeups | **NEEDS VERIFICATION** against 800-53 text |
| CSA confused-deputy research (2026) | Prompt-injection → deputy credential chains | **DROP as primary** — different attack than MCP-006 |
| Cisco products | None | **DROP** |

---

## Learning-model limitations

This review does not grade owner answers. The ten questions in `docs/learning-notes/mcp-confused-deputy-security-101.md` plus the fifteen above are the teaching set.
