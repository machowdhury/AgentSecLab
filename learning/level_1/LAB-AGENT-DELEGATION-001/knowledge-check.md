# Knowledge check — LAB-AGENT-DELEGATION-001

Not a scored LMS. Not certification.

## Questions

1. CTRL-IDENTITY-001 emitted OBSERVE. Has the caller been authenticated?
2. Is a caller agent id a grant?
3. Is a delegation claim authorization?
4. Which control is the tool PDP on this lab?
5. What did CTRL-MCP-001 decide on ATTACK versus RETEST?
6. Did identity ALLOW the tool?
7. Must identity failure explain every tool execution?
8. What remains identical across ATTACK and RETEST?
9. What changed?
10. Why is this not the Confused Deputy lab (MCP-006)?

## Answers

1. **NOT PROVEN / NOT MODELED.** OBSERVE classifies a claim. It does not authenticate. IDENTITY CLAIM != AUTHENTICATION.
2. No. CALLER ID != GRANT. The id is data on the request.
3. No. DELEGATION CLAIM != AUTHORIZATION. A+B does not mint a new grant.
4. **CTRL-MCP-001.** Identity is OBSERVE on this lab, not a grant engine.
5. ATTACK: overlay ALLOW (intentionally vulnerable profile). RETEST: DENY `tool_not_granted`. Handler 1 versus 0.
6. No. Identity stayed OBSERVE. MCP decided the grant.
7. No. A tool can execute because MCP ALLOWed it. Do not invent an identity failure to explain MCP ALLOW.
8. The closed A2A-shaped claim bytes / fingerprint, and identity OBSERVE.
9. Server-owned ExperimentContext / profile, then MCP decision and execution.
10. MCP-006 is Confused Deputy (REPLAY). This lab is identity/delegation claims versus coded grants. Do not collapse them.

## Common wrong answers (do not teach these)

- “The caller was authenticated.”
- “Identity ALLOWED the tool.”
- “OBSERVE means ALLOW.”
- “Splunk authenticated the agent.”
- “Identity must explain the capstone.”
- “One RETEST is universal identity security.”
