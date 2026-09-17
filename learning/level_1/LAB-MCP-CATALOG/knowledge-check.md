# LAB-MCP-CATALOG knowledge checks

Not a scored LMS. Not certification. Answers use Phase 8C / 8D facts only.

## Questions

1. Was the first tool legitimate?

2. Was its catalog metadata treated as authority?

3. Did the metadata influence a follow-on request?

4. Who authorized the follow-on?

5. Did the follow-on handler begin?

6. What changed between ATTACK and RETEST?

7. What evidence is runtime-authoritative?

8. What evidence is Splunk corroboration?

9. Why is DET-MCP-001 silent?

10. Why would scanner output still not be authorization?

11. Why can Q-MCP-EXECUTED show an extra OBSERVE row?

12. Why must ATTACK/RETEST equality use the hash, not the preview?

13. Which invariant forbids retrieved/tool-provided content from independently widening authority?

## Answers

1. Yes. `lookup_policy` is a granted tool. CTRL-MCP-001 ALLOW `tool_granted` on BASELINE, ATTACK, and RETEST. Authorized tool ≠ trusted description.

2. No. CTRL-MCP-METADATA-001 is **OBSERVE** `metadata_is_data` on A/B/C. OBSERVE ≠ ALLOW. Metadata is `untrusted_data` with provenance `mcp.catalog.snapshot`. Provenance ≠ content trust.

3. BASELINE: no. ATTACK and RETEST: yes — a follow-on REQUEST for `lookup_customer_tier` after the catalog snapshot. REQUEST ≠ GRANT.

4. CTRL-MCP-001 on hop 1. ATTACK: vulnerable ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`. RETEST: DENY `tool_not_granted`. The description itself was not authorized. Splunk did not authorize. A scanner did not authorize.

5. ATTACK: yes (runtime `lookup_customer_tier` handler **1**, indexed `mcp.started` / `mcp.completed`). RETEST: no (runtime handler **0**).

6. The **security profile**, not the metadata. ATTACK hash == RETEST hash `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`.

7. Runtime handler counts. RETEST follow-on handler 0 is the authoritative non-execution proof.

8. A COMPLETE Splunk copy (`dc(_raw)` equals local count) showing no hop-1 `mcp.started`. Corroboration only. Do not say Splunk proves it was blocked.

9. DET-MCP-001’s invariant is DENY then later `mcp.started`. Catalog ATTACK is ALLOW-path fail-open. RETEST DENYs with no later start. Silence is a **DETECTION GAP**, not a detector failure. No DET-MCP-CATALOG.

10. Scanner PASS ≠ trusted. Scanner FAIL ≠ runtime DENY. Scanners are not wired into authorization in this lab. Catalog metadata remains data until CTRL-MCP-001 decides.

11. Q-MCP-EXECUTED groups by `run.id` + tool. METADATA-001 is also `lookup_policy`, so the OBSERVE row may inherit `mcp.completed`. Control-event executed=false is not handler non-execution. Do not teach “metadata executed.”

12. Preview is bounded and is not the authorization input. Hash is the content fingerprint. Do not correlate ATTACK and RETEST by preview text.

13. **INV-002:** Retrieved/tool-provided content cannot independently widen authority. Catalog metadata is retrieved/tool-provided content.

## Common wrong answers (do not teach these)

- “Splunk blocked the attack.”
- “Scanner blocked the tool.”
- “OBSERVE means ALLOW.”
- “OBSERVE means DENY.”
- “Authorized tool means trusted description.”
- “Malicious metadata means malicious tool.”
- “Metadata provenance means content trust.”
- “Request equals grant.”
- “ALLOW proves execution.”
- “mcp.started means success.”
- “No Splunk row means blocked.”
- “DET-MCP-001 silence means safe.”
- “The makeresults row is OBSERVED runtime.”
- “We needed DET-MCP-CATALOG in this phase.”
- “Metadata executed.”
- “OBSERVE caused execution.”
