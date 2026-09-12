# LAB-MCP-001 knowledge checks

Not a scored LMS. Not certification. Answers use Phase 3B / 3C facts only.

## Questions

1. Why is `lookup_customer_tier` DENY instead of ERROR in the defended profile?

2. Why is an unknown tool ERROR?

3. Does ALLOW prove the tool executed?

4. What proves the handler actually began?

5. Why is `mcp.failed` not prevention?

6. Why can't zero Splunk events alone prove the handler never executed?

7. Why are MCP tool results classified as `untrusted_data`?

8. Can Splunk ALLOW or DENY the tool?

9. What does Q-MCP-AFTER-DENY returning 0 rows mean?

10. Is the DETECT right-hand table OBSERVED runtime evidence?

11. Why is DENY alone not a DET-MCP-001 alert?

12. Why is `mcp.failed` after ALLOW not the same condition as DET-MCP-001?

13. Does DET-MCP-001 enforce MCP authorization?

## Answers

1. The tool is **registered** (known) but **not granted** to `acme-agent-mcp-001`. Known-ungranted is an authorization failure → **DENY** (`tool_not_granted`). ERROR is reserved for unknown tools, malformed arguments, and control-evaluation failures.

2. Unknown means the name is not in the registry. CTRL-MCP-001 cannot grant what it does not know. Decision is **ERROR** `unknown_tool`, handler count 0, no `mcp.started`. Do not call that DENY.

3. No. ALLOW is the control decision. On BASELINE, Q-MCP-AUTHZ shows `executed=false` on the ALLOW row. Execution begins at `mcp.started`.

4. Runtime: `handler_invoke_count` / registry spy. Telemetry corroboration: `event.name=agentsec.mcp.started` with `operation.executed=true`. ALLOW alone is not enough.

5. `mcp.failed` means the handler **began** and then errored (`executed=true`, `outcome=error`). Prevention is DENY/ERROR **before** start (`executed=false`, `outcome=prevented`, handler count 0).

6. Export can be incomplete. Absence in a partial copy looks like DENY. You need runtime handler count plus complete local `events.jsonl`, then Splunk as corroboration of that copy.

7. INV-002: retrieved or returned content cannot independently authorize privileged actions. Completed results emit `agentsec.mcp.result.trust=untrusted_data`. They do not widen `allowed_tools`. MCP-005 (result used as authority) is not this lab.

8. No. CTRL-MCP-001 runs inside AcmeBank before the handler. Searches read a copy after the fact.

9. No indexed DENY-then-mcp sequence was found for that `run.id`. On a complete copy of RETEST that matches local events, it corroborates the contract. It does not independently prove the runtime never invoked the handler.

10. No. The DETECT right-hand table is **SIMULATED** `| makeresults` (`DET-MCP-001-POSITIVE-CONTROL`). It was not indexed. It is not OBSERVED runtime. The hunt fixture `Q-MCP-AFTER-DENY-POSITIVE-CONTROL` is also SIMULATED.

11. DENY with no later `mcp.started` is the control working (RETEST). The detection asks whether execution began **after** DENY, not whether a DENY happened.

12. `mcp.failed` after ALLOW means the handler **began** and then errored. There was no DENY. DET-MCP-001 requires DENY then later `mcp.started` for the same run/tool.

13. No. CTRL-MCP-001 enforces authorization in AcmeBank before the handler. DET-MCP-001 reads a Splunk copy after the fact. Splunk does not ALLOW or DENY the tool.

## Common wrong answers (do not teach these)

- “Zero Splunk rows means the tool was blocked.”
- “ALLOW means the handler ran.”
- “`mcp.started` means success.”
- “`mcp.failed` means prevented.”
- “Unknown tool is DENY.”
- “Known-ungranted tool is ERROR.”
- “The makeresults row is OBSERVED runtime.”
- “Splunk authorized the invoke.”
- “Dashboard Studio proved INV-001.”
