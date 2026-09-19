# Knowledge check — LAB-MEMORY-001

## Questions

1. Which run wrote the memory?
2. Which later run recalled it?
3. What memory.id links the evidence?
4. What SHA-256 fingerprints the content (`content.hash`)?
5. Does provenance imply trust?
6. What trust classification was applied?
7. Was the memory classified with ALLOW?
8. Did recall influence a privileged request?
9. What tool was requested?
10. What scope was requested?
11. Which control decided authority?
12. Did memory itself authorize the tool?
13. What happened in ATTACK?
14. What happened in RETEST?
15. Why is ATTACK not proof that malicious memory always executes?
16. Why is RETEST missing mcp.started only corroboration?
17. Why does DET-MCP-001 return zero for ATTACK?
18. Why does DET-MCP-001 return zero for RETEST?
19. Why should AGENT MEMORY NOTE not become a detector?
20. Why is the vulnerable overlay reason not a production IOC?
21. What is INV-003?
22. How is memory different from RAG?
23. Which evidence plane determines authorization?
24. Which evidence plane determines execution?
25. What telemetry is missing for cross-agent memory?
26. What telemetry is missing for tenant isolation?
27. Why is anomaly != incident?
28. Can ML grant or deny authority?
29. Can Splunk authorize a tool?
30. What evidence would be required before creating a production memory-security detection?

## Answers

1. BASELINE WRITE `a8407246-7992-4ad8-bd02-cb701e150f30`. ATTACK WRITE `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464`. RETEST WRITE `060a0a72-ceb5-4b99-8330-98de81d8ae5e`. Writer `run.id` is Plane 1.
2. BASELINE RECALL `914c41ce-5123-49eb-892c-c948295dbc46`. ATTACK RECALL `b8737cd9-9b6b-48f2-acfa-178ae1446ddc`. RETEST RECALL `5d5b9d1b-092d-4ddb-8422-4092d289cd49`. Linked by `source_run_id` = writer.
3. BASELINE `mem.lending-preference.normal`. ATTACK and RETEST `mem.lending-preference.malicious`. Fixture identity; not a unique specimen key (ATTACK and RETEST share it).
4. NORMAL `sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b`. MALICIOUS (ATTACK = RETEST) `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9`. Indexed field `content.hash`.
5. No. Provenance `agentsec.memory.fixture` names the source. Provenance != trust.
6. `untrusted_data` via CTRL-MEMORY-CONTEXT-001 OBSERVE `memory_context_is_data`. Classification, not malice.
7. No. OBSERVE != ALLOW. Memory was never classified with ALLOW.
8. BASELINE: no privileged follow-on. ATTACK and RETEST: yes — hop-1 REQUEST formed after recall.
9. ATTACK and RETEST: `lookup_customer_tier`. BASELINE: none.
10. ATTACK and RETEST: `customer:read`. BASELINE: n/a.
11. Hop-1 **CTRL-MCP-001**. CTRL-MEMORY-CONTEXT-001 only classifies.
12. No. Memory itself did not authorize the tool. REQUEST != GRANT.
13. **INTENTIONALLY VULNERABLE LAB PROFILE**. Overlay ALLOW `vulnerable_profile_fail_open:memory_derived_authority`. Then mcp.started and mcp.completed. Handler 1. Recalled memory influenced the request; the overlay granted it.
14. Defended CTRL-MCP-001 **DENY** `tool_not_granted`. Handler 0. Same memory, same request, different authorization.
15. ATTACK used a labeled lab fail-open on the recall run. Malicious stored bytes are not authorization bypass. Overlay ALLOW is not automatically successful execution in every profile.
16. Runtime **handler count = 0** is authoritative non-execution. Missing indexed `mcp.started` can also be a wrong run.id, incomplete copy, or export loss. Only a complete Splunk copy corroborates. Splunk does not prove prevention.
17. DET-MCP-001 needs DENY then later `mcp.started`. ATTACK was ALLOW — no DENY to pair. 0 rows is CORRECT, not a missed memory attack.
18. RETEST DENY was respected — no later start. DET-MCP-001 looks for execution-after-DENY. 0 rows is CORRECT. 0 rows != SAFE.
19. Policies, runbooks, and notes are full of imperatives. Instruction-like memory text has weak production specificity. AGENT MEMORY NOTE regex is REJECT as a detector.
20. `vulnerable_profile_fail_open:memory_derived_authority` is a **LAB-ONLY VULNERABLE PROFILE MECHANISM**. Copying it into production would fire on any system that reused the string and miss real grants that lack it.
21. INV-003: Untrusted memory cannot silently become trusted instruction. Supporting INV-002: content may influence a request but cannot independently create authority.
22. RAG retrieves external/contextual information in one run. MEMORY persists state that is recalled in a **later** run. Write `run.id` ≠ recall `run.id`.
23. Plane 4 — AUTHORIZATION (CTRL-MCP-001).
24. Plane 5 — EXECUTION (`mcp.*` as corroboration; runtime handler count is authoritative).
25. Writer ≠ reader / agent A write consumed by agent B. Not represented. Do not invent `session.id`.
26. Tenant identity is absent. Cross-tenant recall is a TELEMETRY GAP.
27. An anomaly is a ranking signal for investigation. It is not an incident, not a grant, and not a DENY.
28. No. ML may prioritize investigation. **ML must not grant or deny authority.**
29. No. **Splunk != enforcement.** Splunk is investigation/evidence.
30. At least: an authorization-boundary violation with a **grant snapshot** (`allowed_tools`) plus execution, or execution after explicit DENY (already DET-MCP-001), or forbidden cross-identity/tenant recall with identity telemetry, or a demonstrated integrity policy with specimens. Malicious-looking text, `untrusted_data`, recall, rarity, and ML anomaly are not enough. Until then: TELEMETRY GAP — QUERY NOT DEFENSIBLE.
