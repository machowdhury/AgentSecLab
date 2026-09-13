# LAB-MCP-004 knowledge checks

Not a scored LMS. Not certification. Answers use Phase 5B / 5C facts only.

## Questions

1. Why is `executive-restricted` not malformed?

2. Why is `executive-restricted` DENY but `does-not-exist` ERROR?

3. Does ALLOW mean the resource was granted?

4. Why does vulnerable ATTACK show ALLOW while `resource_relation` remains `known_but_ungranted`?

5. Can tool arguments widen `allowed_resource.ids`?

6. Why does AllowTicket.resource_id matter?

7. Why is no `mcp.started` row not authoritative proof of non-execution?

8. Why can DET-MCP-001 be reused?

9. Why might `run_id` + tool become insufficient later?

10. Why is known-but-ungranted not the same as unknown?

11. Why is `mcp.failed` not prevention?

12. Can Splunk ALLOW or DENY the resource?

13. Is the DETECT right-hand table OBSERVED runtime evidence?

14. Does tool granted plus scope granted mean every catalog resource is granted?

15. Why does duplicate-key rejection have no Q-MCP-AUTHZ row?

## Answers

1. `{"policy_id": "executive-restricted"}` is a valid argument shape: the key exists and the value is a string. Malformed is `{}` or `{"policy_id": 123}` → ERROR `malformed_arguments`. `executive-restricted` is known to the catalog and not granted → authorization, not schema.

2. `executive-restricted` is in the lookup_policy catalog and not in the agent grant `{lending-basics}`. Known-but-ungranted is an authorization failure → **DENY** `resource_not_granted` (or labeled fail-open). `does-not-exist` is **not** in the catalog. CTRL-MCP-001 cannot grant what the tool does not define. Decision is **ERROR** `unknown_resource`. ERROR is not DENY. Do not treat unknown as RETEST.

3. No. ALLOW is the control decision. BASELINE ALLOW `tool_granted` happens to match a granted resource. ATTACK ALLOW `vulnerable_profile_fail_open:resource_not_granted` is fail-open, not a grant. On ALLOW rows, Q-MCP-AUTHZ still shows control `executed=false`. Execution begins at `mcp.started`.

4. Fail-open is a labeled decision, not a rewritten policy. Q-MCP-RESOURCE-AUTHZ labels `known_but_ungranted` whenever the reason contains `resource_not_granted`, including ALLOW. Telemetry must still show requested `executive-restricted` versus coded allowed `lending-basics`. If the grant changed, you could not hunt the mismatch.

5. No. HTTP accepts only `tool`, `arguments`, `requested_scope`, `user_id`. Clients cannot set `allowed_resource.ids`. Arguments name the requested `policy_id`. INV-002: data cannot grant authority.

6. Authorization checks one resource id, then the handler must use **that** id. AllowTicket.resource_id binds check to use so a later body change cannot execute a different policy. Resource authorized means resource used.

7. Missing `mcp.started` in Splunk can be DENY, ERROR, incomplete copy, wrong `run.id`, or HTTP-boundary rejection with no control event. Runtime `handler_invoke_count` is authoritative. Splunk absence is corroboration only on a complete copy.

8. DET-MCP-001’s invariant is DENY then later `mcp.started` for the same run/tool. It does not care whether the DENY reason was `tool_not_granted`, `scope_not_granted`, or `resource_not_granted`. LIVE MCP-004 runs have no DENY-then-start. A SIMULATED resource fixture still fires the same detector. No DET-MCP-004.

9. Current canonical labs emit one invoke per run. DET-MCP-001 correlates `run_id` + tool. Multiple same-tool invocations against different resources in one run would need a future per-invocation identity. This workshop does not add that field.

10. Known-but-ungranted (`executive-restricted`) is in the catalog and not in the grant → DENY (or labeled fail-open). Unknown (`does-not-exist`) is not in the catalog → ERROR `not_a_grant`. Both ids are absent from `allowed_resource.ids`. Only the control reason distinguishes them.

11. `mcp.failed` means the handler **began** and then errored. Prevention is DENY/ERROR **before** start (`executed=false`, `outcome=prevented`, handler count 0).

12. No. CTRL-MCP-001 runs inside AcmeBank before the handler. Searches read a copy after the fact.

13. No. The DETECT right-hand table is **SIMULATED** `| makeresults` (`DET-MCP-001-RESOURCE-POSITIVE-CONTROL`). It was not indexed. It is not OBSERVED runtime.

14. No. LAB-MCP-001 granted the **tool**. LAB-MCP-003 granted the **scope** `policy:read`. LAB-MCP-004 still checks the **resource** against the agent grant. `lookup_policy` may read `lending-basics`. It may not read `executive-restricted` unless the lab’s vulnerable profile labels a fail-open.

15. Duplicate JSON keys are rejected at the HTTP boundary before authorize. Phase 5C specimen G emitted `run.failed` `duplicate_json_keys` only. There is no CTRL-MCP-001 `control.decision` to hunt. Do not fabricate one.

## Common wrong answers (do not teach these)

- “Zero Splunk rows means the resource attack was blocked.”
- “ALLOW means the resource was granted.”
- “ALLOW means the handler ran.”
- “`mcp.started` means success.”
- “`mcp.failed` means prevented.”
- “Unknown resource is DENY.”
- “Known-but-ungranted is ERROR.”
- “Fail-open rewrote `allowed_resource.ids`.”
- “A valid `policy_id` string is authorized.”
- “Arguments can add `executive-restricted` to the grant.”
- “The makeresults row is OBSERVED runtime.”
- “Splunk authorized the invoke.”
- “We needed DET-MCP-004.”
- “No detector hit means the system is secure.”
