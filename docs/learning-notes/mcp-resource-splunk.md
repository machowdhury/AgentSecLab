# MCP resource hunt in Splunk

**Status:** Phase 5C validated on live Splunk. Dashboard Studio is **not** this phase. DET-MCP-004 is **not** created.  
**Parents:** `docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md`, `docs/MCP004_SPLUNK_FIELD_VALIDATION.md`, `docs/MCP_SEARCH_CONTRACT.md`.  
**SPL:** existing LAB-MCP-001 Q-MCP searches (schema-version agnostic) plus `Q-MCP-RESOURCE-AUTHZ`.

---

## WHAT IS IT?

The same investigation questions used for LAB-MCP-001, pointed at MCP-004 runs, plus one new hunt: requested **resource** vs coded **grant** vs CTRL-MCP-001 decision.

Splunk is not a second authorizer.

## WHY DOES IT EXIST?

Phase 5B proved resource membership in the runtime with a handler spy. Splunk is where you reconstruct **the same story** after the copy is indexed: granted tool + granted scope + ungranted resource, labeled fail-open, unknown catalog id as ERROR, and DENY without later `mcp.started`.

Q-MCP-SCOPE cannot tell this story. On ATTACK, scope is still `policy:read`, so SCOPE says `granted` while the resource is not.

## HOW DOES IT WORK?

1. AcmeBank emits schema **1.2.0** JSON over OTLP (same path as LAB-MCP-001).
2. Collector → HEC → `index=agentsec_telemetry`.
3. Some scalars appear two or three times. SPL collapses copies with `mvindex(mvdedup('field'),0)`.
4. Bind `__RUN_ID__` on existing Q-MCP files. They do **not** filter `schema.version=1.1.0`.
5. `Q-MCP-RESOURCE-AUTHZ` adds structured `resource.id` / `allowed_resource.ids`. Preview/hash stays provenance.

`resource_relation` is a **display helper**. ERROR is evaluated first. Fail-open ALLOW with `resource_not_granted` in the reason is `known_but_ungranted`, not granted.

## WHERE DOES IT SIT IN AGENTSEC?

HUNT / MEASURE for LAB-MCP-004. Detection stays DET-MCP-001 (execution after DENY). Resource mismatch by itself is a hunt, not a new notable.

## WHAT IS THE TRUST BOUNDARY?

Still `acmebank.mcp.authorize` before `mcp.tool.execute`. Splunk cannot ALLOW, DENY, or ERROR a resource.

## WHAT COULD AN ATTACKER CONTROL?

Still `tool`, `arguments.policy_id`, `requested_scope`, `user_id`, extra JSON, duplicate keys. They cannot pick `run.id`, profile, `allowed_policy_ids`, or `control.decision`. They cannot make Splunk invent `mcp.started`.

## WHAT CAN GO WRONG?

- Treating Q-MCP-SCOPE `granted` as resource authorization.
- Treating fail-open ALLOW as “the resource became granted.”
- Collapsing ERROR `unknown_resource` into DENY `resource_not_granted` because both ids are absent from the grant.
- Treating 0 Q-MCP-TOOL rows as DENY.
- Treating 0 DET-MCP-001 rows as proof the handler never ran.
- Treating `mvcount=2` on `allowed_resource.ids` as two grants.
- Parsing preview JSON instead of using structured resource fields.
- Fabricating `resource.id` on malformed_arguments.

## WHAT TELEMETRY SHOULD EXIST?

Control row when authorize ran: resource id (if extracted), coded allowed ids, decision, reason. `mcp.started` only after ALLOW. Schema 1.2.0. Attack id `MCP-004`. Duplicate-key HTTP failure: `run.failed` only.

## HOW WILL SPLUNK SHOW IT?

| Question | Search |
|----------|--------|
| Who / which tool? | Q-MCP-WHO |
| ALLOW / DENY / ERROR + reason? | Q-MCP-AUTHZ |
| Requested vs allowed **scope**? | Q-MCP-SCOPE (constant here) |
| Requested vs allowed **resource**? | **Q-MCP-RESOURCE-AUTHZ** |
| Argument preview/hash? | Q-MCP-PARAMS |
| Did execution begin? | Q-MCP-TOOL / Q-MCP-EXECUTED |
| DENY then start? | Q-MCP-AFTER-DENY / DET-MCP-001 |

BASELINE: ALLOW `tool_granted`, relation `granted`, `mcp.completed`.  
ATTACK: ALLOW fail-open, relation `known_but_ungranted`, grant still `lending-basics`, `mcp.completed`.  
RETEST: DENY `resource_not_granted`, `known_but_ungranted`, no MCP execution event.  
UNKNOWN: ERROR `unknown_resource`, `not_a_grant`.  
MALFORMED: ERROR `malformed_arguments`, empty resource id, `not_a_grant`.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE=defended` vs `vulnerable` on the same `lookup_policy` + `policy:read` + `executive-restricted` request. Splunk will show DENY vs labeled ALLOW. The coded grant stays `lending-basics`.

## WHAT TEST PROVES THE LOGIC?

Live CLI in `docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md`. Pytest only checks search files, field names, ERROR-first helper order, and that DET-MCP-004 was not created. Handler counts in `manifest.json` remain the non-execution proof.

---

## What I should now be able to explain

1. Why LAB-MCP-001 `catalog.json` saying 1.1.0 does not exclude schema 1.2.0 events.
2. Why Q-MCP-SCOPE says `granted` on MCP-004 ATTACK.
3. Why fail-open ALLOW must still show `allowed_resource.ids=lending-basics`.
4. Why `does-not-exist` is `not_a_grant` and `executive-restricted` is `known_but_ungranted`.
5. Why `mvcount=2` on allowed_resource.ids is not two grants.
6. Why missing `resource.id` on malformed_arguments is expected.
7. Why 0 DET-MCP-001 rows does not prove the handler never ran.
8. Why DET-MCP-001 `run_id`+tool correlation is enough for one invoke per run and what breaks with two.
9. Why duplicate-key rejection has no CTRL-MCP-001 row in Splunk.
10. Why preview/hash is not the resource-authorization hunt.
