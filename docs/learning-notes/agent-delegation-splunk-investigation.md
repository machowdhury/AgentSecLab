# Agent identity / delegation Splunk investigation (Phase 12C)

**Status:** Phase 12C live Splunk validated. No Dashboard Studio. No DET-A2A. No live A2A.  
**Parents:** `docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`, `docs/learning-notes/agent-delegation-runtime.md`.

---

## WHAT IS IT?

Live proof that schema **1.8.0** identity/delegation fields actually extract in Splunk, and that one hunt can reconstruct caller → callee → untrusted claim → CTRL-MCP-001 → execution without treating the claim as authentication or a grant.

## WHY DOES IT EXIST?

12B proved the runtime invariant locally: an A2A-shaped request cannot mint authority neither agent possesses. Splunk is the SOC evidence plane. Field names in a schema file are not indexed fields until live discovery. MCP-006’s hunt answers ambient confused-deputy (B **has** `customer:read`). This lab is amplification (neither has it).

## HOW DOES IT WORK?

Fresh A/B/C runs with OTEL on went OTLP → collector → HEC → `index=agentsec_telemetry`. Completeness used `dc(_raw)` vs `events.jsonl`. Fields were collapsed with `mvindex(mvdedup(…),0)`. Existing Q-MCP searches were reused unchanged. One new hunt, `Q-AGENT-DELEGATION-AUTHORITY`, binds `__RUN_ID__`.

## WHERE DOES IT SIT IN AGENTSEC?

After LAB-AGENT-DELEGATION-001 runtime (12B) and before workshop (12E) or detection implementation (not started). Same index/sourcetype as MCP labs. Different control (`CTRL-IDENTITY-001`) than CTRL-DELEGATION-001.

## WHAT IS THE TRUST BOUNDARY?

Indexed `agentsec.trust_boundary=agent.identity.claim` on IDENTITY-001. Authorization remains `acmebank.mcp.authorize` on hop-1 CTRL-MCP-001. Splunk does not sit on that boundary.

## WHAT COULD AN ATTACKER CONTROL?

The A2A-shaped request document (principal/caller/callee/tool/scope/resource/claim). Not coded grants, not profile, not indexed `control.decision`. Splunk cannot be used to mint ALLOW.

## WHAT CAN GO WRONG?

Treating OBSERVE as ALLOW; treating a valid-looking agent id as authentication; treating claimed scope as allowed scope; treating overlay reason as a production IOC; treating DET-MCP-001 silence as “safe”; treating missing `mcp.started` as prevention; comparing hop-1 MCP hashes as the claim fingerprint; rewriting Q-MCP-DELEGATION; inventing `allowed_tools` in SPL.

## WHAT TELEMETRY SHOULD EXIST?

IDENTITY-001: caller, callee, `untrusted_claim`, claimed scope, OBSERVE `identity_claim_is_not_grant`, claim SHA-256. Hop-1: CTRL-MCP-001 ALLOW/DENY. Optional `mcp.started`/`completed`. All were **OBSERVED** live. Per-agent grant snapshot was **not** indexed (**TELEMETRY GAP**).

## HOW WILL SPLUNK SHOW IT?

Q-MCP-AUTHZ shows the OBSERVE row plus hop-1. Q-MCP-WHO shows callee only. The new hunt adds caller/callee/claim columns and collapses one row per specimen. DET-MCP-001 stays 0 on A/B/C.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE` on that run. Splunk only records it. CTRL-IDENTITY-001 never switches to ALLOW.

## WHAT TEST PROVES THE LOGIC?

Live `dc(_raw)` COMPLETE on three IDs; B IDENTITY hash == C; hunt A `mcp.completed_observed` on `lookup_policy`, B overlay ALLOW + `mcp.completed_observed`, C DENY + `no_indexed_followon_execution_event`; runtime handler 1/1/0 for the intended tools.

---

## What I should now be able to explain

1. Why schema 1.8.0 field names still needed live field discovery.
2. Why `dc(_raw)` is the completeness metric, not `stats count`.
3. Why `gen_ai.agent.id` is the callee on both hops and is not “who called.”
4. Why CTRL-IDENTITY-001 OBSERVE is indexed on ATTACK as well as BASELINE.
5. Why hop-1 `content.hash` is not the delegation-request fingerprint.
6. Why one Q-AGENT-DELEGATION-AUTHORITY hunt was justified and Q-A2A-* files were not.
7. Why Q-MCP-DELEGATION returns zero rows here and must not be rewritten.
8. Why DET-MCP-001 is silent on the preferred ATTACK.
9. Why Splunk cannot prove neither agent owned `customer:read` without `allowed_tools`.
10. Why WHO AUTHENTICATED remains NOT PROVEN / NOT MODELED, and why Phase 12D / Studio / live A2A must not start from this file.
