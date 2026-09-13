# MCP scope in Splunk

**Status:** Phase 4C validated on live Splunk. Phase 4D workshop is `docs/learning-notes/mcp-scope-workshop.md`. DET-MCP-003 is **not** created.  
**Parents:** `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`, `docs/MCP003_SPLUNK_FIELD_VALIDATION.md`, `docs/MCP_SEARCH_CONTRACT.md`.  
**SPL:** existing LAB-MCP-001 Q-MCP searches. Same `__RUN_ID__` token.

---

## WHAT IS IT?

The same investigation questions used for LAB-MCP-001, pointed at MCP-003 runs: who asked, what CTRL-MCP-001 decided, what scope was requested vs coded, and whether the tool actually started.

Splunk is not a second authorizer.

## WHY DOES IT EXIST?

Phase 4B proved scope membership in the runtime with a handler spy. Splunk is where you reconstruct **the same story** after the copy is indexed: granted tool + ungranted scope, labeled fail-open, unknown catalog token as ERROR, and DENY without later `mcp.started`.

## HOW DOES IT WORK?

1. AcmeBank emits schema 1.1.0 JSON over OTLP (same path as LAB-MCP-001).
2. Collector → HEC → `index=agentsec_telemetry`.
3. Some scalars appear two or three times. SPL collapses copies with `mvindex(mvdedup('field'),0)`.
4. Bind `__RUN_ID__` on the existing Q-MCP files. Do not invent Q-MCP-003.

`Q-MCP-SCOPE` `scope_relation` is a **display helper**. ERROR is evaluated first so `unknown_scope` is `not_a_grant`, not `known_but_ungranted`.

## WHERE DOES IT SIT IN AGENTSEC?

HUNT / MEASURE for LAB-MCP-003. Detection stays DET-MCP-001 (execution after DENY). Scope mismatch by itself is a hunt, not a new notable.

## WHAT IS THE TRUST BOUNDARY?

Still `acmebank.mcp.authorize` before `mcp.tool.execute`. Splunk cannot ALLOW, DENY, or ERROR a tool.

## WHAT COULD AN ATTACKER CONTROL?

Still `tool`, `arguments`, `requested_scope`, `user_id`. They cannot pick `run.id`, profile, `allowed_scope`, or `control.decision`. They cannot make Splunk invent `mcp.started`.

## WHAT CAN GO WRONG?

- Treating `known_but_ungranted` as a detector (ATTACK is ALLOW fail-open).
- Collapsing ERROR `unknown_scope` into DENY `scope_not_granted`.
- Treating 0 Q-MCP-TOOL rows as DENY.
- Treating 0 DET-MCP-001 rows as proof the handler never ran.
- Reading control `executed=false` on ALLOW as “the tool did not run.”
- Treating `mcp.failed` as prevention.
- Measuring `mvcount` after overwriting the field with `eval`.

## WHAT TELEMETRY SHOULD EXIST?

Control row always if authorize ran: requested vs coded allowed, decision, reason. `mcp.started` only after ALLOW. `mcp.completed` or `mcp.failed` after start. Schema 1.1.0. Attack id `MCP-003`.

## HOW WILL SPLUNK SHOW IT?

| Question | Search |
|----------|--------|
| Who / which tool? | Q-MCP-WHO |
| ALLOW / DENY / ERROR + reason? | Q-MCP-AUTHZ |
| Requested vs allowed? | Q-MCP-SCOPE |
| Did execution begin? | Q-MCP-TOOL / Q-MCP-EXECUTED |
| DENY then start? | Q-MCP-AFTER-DENY / DET-MCP-001 |

BASELINE: ALLOW `tool_granted`, `granted`, `mcp.completed`.  
ATTACK: ALLOW fail-open, `known_but_ungranted`, `mcp.completed`.  
RETEST: DENY `scope_not_granted`, `known_but_ungranted`, no MCP execution event.  
UNKNOWN SCOPE: ERROR `unknown_scope`, `not_a_grant`, no MCP execution event.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE=defended` vs `vulnerable` on the same `lookup_policy` + `policy:restricted:read` request. Splunk will show DENY vs labeled ALLOW. The coded grant stays `policy:read`.

## WHAT TEST PROVES THE LOGIC?

Live CLI in `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`. Pytest only checks search files, field names, ERROR-first helper order, and that DET-MCP-003 was not created. Handler counts in `manifest.json` remain the non-execution proof.

---

## What I should now be able to explain

1. Why MCP-003 did not need new Q-MCP query IDs.
2. Why Q-MCP-SCOPE is the key hunt for this lab.
3. Why `known_but_ungranted` appears on both ATTACK ALLOW and RETEST DENY.
4. Why ERROR `unknown_scope` must display `not_a_grant`, not `known_but_ungranted`.
5. Why DET-MCP-001 stays 0 on all six live MCP-003 specimens.
6. Why a SIMULATED DENY-then-`mcp.started` with `scope_not_granted` still uses DET-MCP-001.
7. Why 0 TOOL / AFTER-DENY / DET rows do not prove the handler never ran.
8. Why control `executed=false` on ALLOW is not a contradiction of `mcp.started`.
9. Why `mcp.failed` is not prevention.
10. Why schema stayed 1.1.0 and `scope_relation` is not an indexed field.
