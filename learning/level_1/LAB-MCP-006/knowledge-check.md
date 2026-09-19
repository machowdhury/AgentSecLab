# LAB-MCP-006 knowledge checks

Not a scored LMS. Not certification. Answers use Phase 7B / 7C facts only.

## Questions

1. Why can the deputy possess more authority than the caller?

2. Why is that dangerous?

3. Why is ambient authority different from delegated authority?

4. Why isn't downstream MCP ALLOW sufficient proof of caller authorization?

5. Why doesn't execution prove caller authorization?

6. Why can DET-MCP-001 correctly remain silent?

7. What evidence would you need before claiming confused-deputy misuse?

8. What control should execute before the dangerous operation?

9. What proves that the RETEST handler did not execute?

10. Why does an empty Splunk execution table not independently prove prevention?

11. Who was the caller and who acted as deputy on the Phase 7C specimens?

12. Why would repeated same-tool invocations require stronger correlation?

## Answers

1. Compliance Agent is a real MCP principal with its **own** coded grant (`lookup_policy` and `lookup_customer_tier`). Credit Agent is delegated only `lookup_policy`. Ambient deputy authority is independent of the caller’s grant. DEPUTY AUTHORITY ≠ CALLER AUTHORITY.

2. If the deputy spends ambient authority on a caller request, the caller can cause an operation the caller was not entitled to delegate. That is the confused-deputy failure. INV-001: an agent cannot receive more authority than was explicitly delegated.

3. **Delegated authority** is what the caller actually authorized for this request (runtime: `lookup_policy`). **Ambient authority** is what the deputy possesses for its own work (runtime includes `lookup_customer_tier`). Indexed `agentsec.delegation.authority.source` records which set CTRL-DELEGATION-001 consulted (`delegated` vs `ambient_deputy`). Ambient is not delegated.

4. CTRL-MCP-001 answers: may the **selected MCP policy** call this tool at this scope? On ATTACK the selected policy is the deputy’s ambient object, so MCP ALLOW `tool_granted` is true for Compliance and still false as a Credit grant. CTRL-DELEGATION-001 is the caller/deputy question.

5. Execution shows the handler began (`mcp.started` / runtime handler count). ATTACK executed after a vulnerable ALLOW. Successful execution is not proof the caller was authorized to cause it.

6. DET-MCP-001’s invariant is **DENY → later `mcp.started`** for the same run/tool. The preferred MCP-006 ATTACK is **vulnerable ALLOW → execution**. There is no DENY-then-start to match. Silence is expected. It is not a detector failure. No DET-MCP-006 exists.

7. At minimum: caller identity, deputy identity, requested operation, indexed `authority.source`, CTRL-DELEGATION-001 decision/reason, whether downstream MCP ran, and whether execution began. Runtime grant lists remain necessary because there is no indexed `allowed_tools`. Do not claim confused-deputy misuse from deputy possession alone (BASELINE also possesses ambient `lookup_policy` with source=`delegated`).

8. **CTRL-DELEGATION-001** must run before MCP authorize and before the tool handler. Dangerous operation = handler invoke. Defended RETEST DENYs at delegation (`delegated_authority_not_granted`) so CTRL-MCP-001 never starts.

9. **Runtime handler count = 0** is authoritative in this controlled lab. Splunk observed **no indexed MCP execution event**. That Splunk absence is corroboration only, and only on a complete copy (RETEST 6=6). Do not say Splunk proved the handler never ran.

10. Missing `mcp.started` can mean DENY, ERROR, schema failure, or export loss. On an incomplete copy it can also mean the start event never arrived. Runtime handler count remains the non-execution proof. Empty table ≠ DENY.

11. Caller: `acme-agent-credit-002`. Deputy: `acme-agent-compliance-004`. RETEST hop 1 is not indexed (`deputy_not_on_indexed_hop1`); runtime/manifest still name the deputy.

12. There is no indexed `gen_ai.tool.call.id`. This lab is one operation per run, correlated by `run.id` + `sequence` + `hop.index`. Repeated invocations of the same tool in one run would collide under run+tool correlation.

## Common wrong answers (do not teach these)

- “Splunk blocked the action.”
- “Splunk prevented the attack.”
- “The detector caught MCP-006.”
- “ALLOW proves execution.”
- “No mcp.started proves the handler never ran.”
- “The caller was granted lookup_customer_tier.”
- “Deputy has the tool, therefore the caller may ask for it.”
- “Empty Splunk table proves prevention.”
- “Zero hunt rows mean the control worked.”
- “No DET-MCP-001 match means no security violation occurred.”
- “We needed DET-MCP-006.”
- “No detector hit means the system is secure.”
- “The makeresults row is OBSERVED runtime.”
- “There is an indexed allowed_tools field.”
- “Ambient authority equals delegated authority.”
