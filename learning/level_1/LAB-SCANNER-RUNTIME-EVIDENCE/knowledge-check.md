# Knowledge check

Answer from indexed evidence. Full hashes and ids are on LEARN.

1. Did the NORMAL scan run?
2. Does zero findings prove the artifact is safe?
3. What field correlates scanner evidence with runtime metadata?
4. Why is artifact.sha256 not the runtime correlation key?
5. Did the scanner authorize lookup_customer_tier?
6. Why does ATTACK execute?
7. Why does RETEST not execute?
8. Why does DET-MCP-001 return zero for ATTACK?
9. Why does DET-MCP-001 return zero for RETEST?
10. What is the difference between provenance and trust?
11. Which evidence plane proves authorization?
12. Which evidence proves handler non-execution?
13. Why must scanner native HIGH not automatically become incident HIGH?
14. What would a SOC need before promoting this hunt into a production detection?
15. Which AgentSec invariant is being demonstrated?

## Answers

1. Yes, if Q-SCANNER-WHO shows `target_executed` for scan `b3061c4e-7a81-445c-8fd8-3108dd14c419`. Scan executed is not a security verdict.
2. No. Zero findings means this scanner produced zero findings for this artifact under this scan configuration. ZERO FINDINGS != SAFE.
3. `artifact.description_sha256` on scanner events and `agentsec.content.hash` on METADATA-001. Q-SCANNER-RUNTIME-CORRELATION unifies them.
4. `artifact.sha256` hashes the exported `tools.json` file bytes. The runtime observed description bytes, not the file hash. File-hash join MEASURED 0 rows in Phase 9C.
5. No. Scanner evidence does not feed CTRL-MCP-001. SCANNER FINDING != AUTHORIZATION DECISION.
6. The INTENTIONALLY VULNERABLE lab profile independently ALLOWED `lookup_customer_tier` with reason `vulnerable_profile_fail_open:metadata_derived_authority`. Scanner HIGH did not grant the tool.
7. CTRL-MCP-001 DENY `tool_not_granted`. Runtime follow-on handler count = 0. Same malicious hash as ATTACK.
8. DET-MCP-001 looks for DENY then later mcp.started. ATTACK had no DENY (vulnerable ALLOW). Zero rows is correct, not detector failure.
9. RETEST had DENY, but no later mcp.started. DET-MCP-001 correctly stays silent. Runtime handler count 0 is the non-execution proof.
10. Provenance is where the bytes came from. Trust is how they are classified (`untrusted_data`). Neither is a grant.
11. PLANE 3 — CTRL-MCP-001 decision (ALLOW or DENY) plus reason.
12. Runtime handler count. Missing Splunk execution event is corroboration on a complete copy, not independent proof.
13. Native HIGH is the scanner's label for that finding. Incident HIGH needs authorization, execution, impact, and context. SCANNER HIGH != HIGH-SEVERITY INCIDENT.
14. Stable grant snapshots, pin/`list_changed` telemetry, a join stronger than the lab overlay string, and a true-positive class that is not identical scanner HIGH on both ATTACK and RETEST. Phase 9D: DETECTION ANALYZED — NO NEW DETECTOR.
15. INV-002 Data Cannot Grant Authority.

No DET-SCANNER. No DET-MCP-CATALOG. No Agent Scan. No rug-pull. No A2A. Phase 10 not started.
