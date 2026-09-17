# Knowledge check — LAB-RAG-CONTEXT

## Questions

1. What document was retrieved?
2. What was its provenance?
3. Was provenance equivalent to trust?
4. What was its content classification?
5. Did OBSERVE authorize anything?
6. Did retrieved text directly grant a tool?
7. What follow-on request occurred?
8. Which control decided authorization?
9. Why did ATTACK execute?
10. Why did RETEST not execute?
11. What proves handler non-execution?
12. Why is missing Splunk execution only corroboration?
13. Why is DET-MCP-001 empty?
14. Does DET-MCP-001 silence mean SAFE?
15. Why is instruction-like text not a production detector?
16. What telemetry is missing for a stronger detector?
17. Why are ATTACK and RETEST comparable?
18. What does INV-002 mean here?
19. Where could behavioral analytics help later?
20. Can ML grant or deny authority?

## Answers

1. BASELINE: `doc.lending-policy.normal`. ATTACK and RETEST: `doc.lending-policy.malicious`. Fingerprints: NORMAL `sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e`; MALICIOUS `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`.
2. `rag.local.fixture` on A/B/C. Provenance names the source, not the trust decision.
3. No. Provenance != trust. Source identity is not a grant and not a SAFE verdict.
4. `untrusted_data` via CTRL-RAG-CONTEXT-001. That is the honest default classification, not a malice verdict.
5. No. OBSERVE != ALLOW. Classification does not authorize a tool.
6. No. Retrieved text did not directly grant a tool. REQUEST != GRANT.
7. ATTACK and RETEST: `lookup_customer_tier` at requested scope `customer:read`. BASELINE: none.
8. Hop-1 **CTRL-MCP-001**. CTRL-RAG-CONTEXT-001 only classifies.
9. The **INTENTIONALLY VULNERABLE LAB PROFILE** applied overlay ALLOW `vulnerable_profile_fail_open:retrieved_context_derived_authority`. Then mcp.started and mcp.completed. Handler 1. Retrieved content influenced the request; the overlay granted it.
10. Defended CTRL-MCP-001 **DENY** `tool_not_granted`. Handler 0. Same document, same request, different authorization outcome.
11. Runtime **handler count = 0**. That is authoritative non-execution in this lab.
12. Missing indexed `mcp.started` can also be a wrong run.id, incomplete copy, or export loss. Only a complete Splunk copy corroborates. Splunk does not prove prevention.
13. DET-MCP-001 needs DENY then later `mcp.started`. BASELINE had no DENY. ATTACK was ALLOW. RETEST DENY was respected. 0/0/0 is CORRECT.
14. No. 0 rows != SAFE. DET-MCP-001 silence is not an all-clear.
15. Policies, runbooks, and training docs are full of imperatives. Instruction-like retrieved text has weak production specificity. AGENT NOTE regex is REJECT as a detector.
16. A server-owned **grant snapshot** (`allowed_tools`) and a stable tool-call identity (`gen_ai.tool.call.id`). Tenant identity and behavioral baselines are also missing. Until then: TELEMETRY GAP — QUERY NOT DEFENSIBLE for unauthorized execution after retrieval.
17. They share document.id, content.hash, provenance, follow-on tool, and requested scope. The discriminator is authorization, then execution.
18. INV-002: data cannot grant authority. Retrieved content cannot independently authorize privileged actions.
19. FUTURE — NOT IMPLEMENTED: rare privileged tool after retrieval, new retrieve→tool sequences, novel provenance, retrieval burst before a sensitive operation, per-agent deviation. Statistical SPL, MLTK, or CDTSM may later **rank hunts**. ANOMALY != INCIDENT.
20. No. ML may prioritize investigation. **ML must not grant or deny authority.**
