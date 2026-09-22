# AgentSec v1.0.0-rc1 — learning loop validation

Stages: LESSON → WHY → ATTACKER CONTROLS / NOT → BOUNDARY → PREDICT → LAUNCH → COPY run.id → SEARCH → PATH A → SPL → OBSERVE → INTERPRET → PATH B optional → PDP → EXECUTION → DEFEND → RETEST → COMPARE → PROVE → LIMITATIONS → NEXT.

| Lab | Loop | Notes |
|-----|------|--------|
| PI LIVE | PASS | Studio tabs + Attack Service + Search handoff |
| MCP-001 LIVE | PASS | Tool PDP CTRL-MCP-001; ATTACK handler 1 / RETEST 0 MEASURED |
| RAG LIVE | PASS | OBSERVE then MCP; fingerprints match ATTACK/RETEST |
| Memory LIVE | PASS | Write+recall ids in handoff; correlation via source_run_id (NOT a retrieve-to-write field) |
| Goal LIVE | PASS | Goal DENY ≠ MCP DENY; RETEST handler 1 on in-task lookup_policy MEASURED |
| Identity LIVE | PASS | CTRL-IDENTITY-001 OBSERVE; MCP DENY on RETEST handler 0 |
| Capstone LIVE | PASS | retrieve/write/recall ids; MCP on recall |
| REPLAY workshops | NOT APPLICABLE for LAUNCH/RETEST buttons | Reconstruct historical specimens |

PARTIAL: Path B is visible without a reveal control (Studio). Does not fail the loop if labeled as review key.

FAIL: none on published LIVE labs.
