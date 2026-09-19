# LAB-MCP-003 knowledge checks

Not a scored LMS. Not certification. Answers use Phase 4B / 4C facts only.

## Questions

1. Why is `policy:restricted:read` DENY rather than ERROR in the defended profile?

2. Why is `policy:write` ERROR?

3. Does ALLOW mean the tool executed?

4. Why must `allowed_scope` remain `policy:read` during vulnerable fail-open?

5. Can arguments grant a broader scope?

6. Why can DET-MCP-001 be reused for MCP-003?

7. Why is no detector hit not proof that the handler never ran?

8. Why is known-but-ungranted not the same as unknown?

9. Why is `mcp.failed` not prevention?

10. Can Splunk ALLOW or DENY the tool?

11. Is the DETECT right-hand table OBSERVED runtime evidence?

12. Does tool granted mean every catalog scope is granted?

## Answers

1. `policy:restricted:read` is in `lookup_policy` `valid_scopes` (known to the tool) but not in the agent grant `{policy:read}`. Known-but-ungranted is an authorization failure → **DENY** `scope_not_granted`. ERROR is reserved for tokens the catalog does not define, missing scope, malformed arguments, and control-evaluation failures.

2. `policy:write` is **not** in the tool catalog. CTRL-MCP-001 cannot grant what the tool does not define. Decision is **ERROR** `unknown_scope`, handler count 0, no `mcp.started`. Do not call that DENY. Do not treat it as RETEST.

3. No. ALLOW is the control decision. On BASELINE, Q-MCP-AUTHZ shows `executed=false` on the ALLOW row. Execution begins at `mcp.started`.

4. Fail-open is a labeled decision, not a rewritten policy. Telemetry must still show requested `policy:restricted:read` versus coded allowed `policy:read`. If `allowed_scope` changed, you could not hunt the mismatch.

5. No. HTTP accepts only `tool`, `arguments`, `requested_scope`, `user_id`. Scope keys inside arguments are malformed. Clients cannot set `allowed_scope`. INV-002: data cannot grant authority.

6. DET-MCP-001’s invariant is DENY then later `mcp.started` for the same run/tool. It does not care whether the DENY reason was `tool_not_granted` or `scope_not_granted`. LIVE MCP-003 runs have no DENY-then-start. A SIMULATED scope fixture still fires the same detector. No DET-MCP-003.

7. Zero DET-MCP-001 rows means no indexed invariant violation was found. The handler might still have run (fail-open ALLOW, incomplete copy, or DET window). Runtime `handler_invoke_count` remains authoritative. Splunk corroborates a complete copy.

8. Known-but-ungranted (`policy:restricted:read`) is in the catalog and not in the grant → DENY (or labeled fail-open). Unknown (`policy:write`) is not in the catalog → ERROR `not_a_grant`. Q-MCP-SCOPE must not label ERROR as `known_but_ungranted`.

9. `mcp.failed` means the handler **began** and then errored. Prevention is DENY/ERROR **before** start (`executed=false`, `outcome=prevented`, handler count 0).

10. No. CTRL-MCP-001 runs inside AcmeBank before the handler. Searches read a copy after the fact.

11. No. The DETECT right-hand table is **SIMULATED** `| makeresults` (`DET-MCP-001-SCOPE-POSITIVE-CONTROL`). It was not indexed. It is not OBSERVED runtime.

12. No. LAB-MCP-001 granted the **tool**. LAB-MCP-003 still checks the **requested scope** against the agent grant. `lookup_policy` may run at `policy:read`. It may not run at `policy:restricted:read` unless the lab’s vulnerable profile labels a fail-open.

## Common wrong answers (do not teach these)

- “Zero Splunk rows means scope escalation was blocked.”
- “ALLOW means the handler ran.”
- “`mcp.started` means success.”
- “`mcp.failed` means prevented.”
- “Unknown scope is DENY.”
- “Known-but-ungranted is ERROR.”
- “Fail-open rewrote `allowed_scope`.”
- “Arguments can add `policy:restricted:read`.”
- “The makeresults row is OBSERVED runtime.”
- “Splunk authorized the invoke.”
- “We needed DET-MCP-003.”
