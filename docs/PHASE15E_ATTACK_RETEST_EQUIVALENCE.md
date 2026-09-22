# Phase 15E — ATTACK / RETEST equivalence

Do not merely state equivalence. Measure it.

ATTACK and RETEST share the same canonical frozen `A2ADelegationRequest`:

- principal.id `applicant-web`
- caller_agent_id `acme-agent-advisor-005`
- callee_agent_id `acme-agent-fulfillment-006`
- claimed scope `customer:read`
- requested tool `lookup_customer_tier`
- requested scope `customer:read`
- requested resource `cust-001`
- request fingerprint `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd`

That fingerprint already existed on `A2ADelegationRequest`. No new fingerprint field.

**SAME PRINCIPAL. SAME CALLER. SAME CALLEE. SAME DELEGATION CLAIM. SAME PRIVILEGED REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

DIFFERENT: profile, CTRL-MCP-001 decision, execution, handler count, run.id.

CTRL-IDENTITY-001 is the SAME OBSERVE on both.

Authority amplification: neither agent is coded `customer:read` or `lookup_customer_tier`. A + B != NEW AUTHORITY. ATTACK is the labeled vulnerable overlay exception. RETEST is the defended rejection.

## LIVE pair MEASURED

ATTACK `110dd7a6-58b5-472a-ae80-aec76e11bf4e` and RETEST `7e4f74a8-84bf-4d18-abe1-0dcc7f0ab58a` share that fingerprint, principal, caller, callee, claimed scope, requested tool/scope/resource. DIFFERENT: profile, CTRL-MCP-001, handler count, run.id. IDENTITY OBSERVE on both.
