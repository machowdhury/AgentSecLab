# LAB-MCP-005 knowledge checks

Not a scored LMS. Not certification. Answers use Phase 6B / 6C facts only.

## Questions

1. Why does an authorized tool not make its result authoritative?

2. What is the difference between provenance and authority?

3. What security invariant does MCP-005 test?

4. Why does the ATTACK follow-on receive ALLOW?

5. Why does RETEST receive DENY for the same follow-on?

6. Why is DET-MCP-001 silent during the preferred ATTACK?

7. Why does a matching result hash not prove trust?

8. What proves that the RETEST follow-on handler did not execute?

9. Why is MCP-005 different from prompt-injection resistance?

10. Why would repeated same-tool invocations require stronger correlation?

## Answers

1. CTRL-MCP-001 authorized the **invoke** (`lookup_policy` at `policy:read`). The handler then returned **data**. INV-002: retrieved content cannot independently authorize privileged actions. Follow-on operations still require a normal authorization check. AUTHORIZED TOOL ≠ AUTHORITATIVE RESULT.

2. **Provenance** records where the bytes came from (here: `mcp.tool.handler` after an authorized call). **Content** is what those bytes contain. **Authority** is what is actually permitted by server-owned grant. A result can come from an authorized tool while its content remains non-authoritative data. PROVENANCE ≠ AUTHORITY.

3. **INV-002 — Data Cannot Grant Authority.** MCP-005 begins after a legitimate tool execution and asks whether returned data can alter future authority.

4. Profile `vulnerable` is **INTENTIONALLY VULNERABLE LAB BEHAVIOR**. CTRL-MCP-RESULT-001 classifies the MALICIOUS payload, then an overlay labels hop-1 CTRL-MCP-001 ALLOW `result_derived_grant` for `lookup_customer_tier`. That ALLOW is **result-derived**, not a coded server grant. Coded `allowed_scope` stays `policy:read`. Preview still lists `server_owned_allowed_tools": "lookup_policy"`.

5. Profile `defended`. Same MALICIOUS fixture (same hash). RESULT-001 stays OBSERVE `result_is_data`. No overlay. Hop-1 CTRL-MCP-001 DENY `tool_not_granted` because `lookup_customer_tier` is not in the server-owned grant. SAME HOSTILE DATA + DIFFERENT SECURITY PROFILE = DIFFERENT AUTHORIZATION OUTCOME.

6. DET-MCP-001’s invariant is **DENY → later `mcp.started`** for the same run/tool. The preferred MCP-005 ATTACK is **bad authority → ALLOW → execution**. There is no DENY-then-start to match. Silence is expected. It is not a detector failure. No DET-MCP-005 exists.

7. The hash is **content identity evidence**. ATTACK and RETEST share `sha256:f7d67b151741ef7c7efb60242b96f8325996709128293da424f53a547230c358`. That supports “same fixture.” It does not make the content trusted and it does not create authority. Hash ≠ trust. Hash ≠ authority.

8. **Runtime follow-on handler count = 0** is authoritative in this controlled lab. Splunk observed **no indexed follow-on execution event**. That Splunk absence is corroboration only, and only on a complete copy (RETEST 12=12). Do not say Splunk proved the handler never ran.

9. MCP-005 does not prove the model ignored a malicious instruction. The AI can interpret the data. The data still does not get to create permission. The lab proves an **authorization boundary**, not prompt-injection resistance.

10. There is no indexed `gen_ai.tool.call.id`. This lab is tractable because the initial tool (`lookup_policy`) and follow-on (`lookup_customer_tier`) differ, plus `run.id` + `sequence` + `hop.index`. Repeated invocations of the **same** tool in one run would collide under run+tool correlation.

## Common wrong answers (do not teach these)

- “Splunk blocked the action.”
- “Splunk prevented the attack.”
- “The detector caught MCP-005.”
- “The result was trusted.”
- “The hash proves the result is safe.”
- “ALLOW proves execution.”
- “No mcp.started proves the handler never ran.”
- “The server granted lookup_customer_tier.”
- “Zero hunt rows mean the control worked.”
- “No DET-MCP-001 match means no security violation occurred.”
- “The AI ignored the malicious instruction.”
- “We needed DET-MCP-005.”
- “No detector hit means the system is secure.”
- “The makeresults row is OBSERVED runtime.”
- “There is an indexed allowed_tools field.”
