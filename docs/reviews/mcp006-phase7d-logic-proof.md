# Logic proof — LAB-MCP-006 workshop (`ws_lab_mcp_006`)

**Date:** 2026-09-15  
**Target:** Phase 7D Dashboard Studio workshop and learner docs, not a runtime redesign.  
**Skill:** `.cursor/skills/logic-proof/SKILL.md`

This proof does **not** re-run live OTLP. Runtime facts are Phase 7B/7C. Workshop claims are checked against those facts.

## SECURITY PROPERTY

INV-001: an agent cannot receive more authority than was explicitly delegated. The workshop must teach caller vs deputy and delegated vs ambient without equating execution with authorization.

## ASSUMPTIONS

- Phase 7C LIVE copies remain indexed for the three canonical run IDs.
- Q-MCP files are unchanged except token bind.
- CTRL-DELEGATION-001 runs before CTRL-MCP-001 and before the handler.
- There is no indexed `allowed_tools`.

## ATTACKER-CONTROLLED INPUT

The requested operation a caller asks a deputy to perform (`lookup_customer_tier` on ATTACK/RETEST). Not Splunk. Not the dashboard.

## TRUST BOUNDARY

Caller request → CTRL-DELEGATION-001 → (only if ALLOW) CTRL-MCP-001 → (only if ALLOW) tool handler. The dashboard is observe-only.

## CODE PATH (workshop)

Builder `scripts/build_lab_mcp_006_dashboard.py` → `dashboard.definition.json` + `ws_lab_mcp_006.xml`. Tables bind validated SPL. Markdown states the security claims.

## DECISION POINTS

CTRL-DELEGATION-001 (delegated authority). CTRL-MCP-001 (MCP authorization). Distinct in teaching and in Q-MCP-DELEGATION columns.

## DANGEROUS OPERATION

Tool handler invoke (`lookup_customer_tier` on ATTACK/RETEST; `lookup_policy` on BASELINE).

## WHERE VALIDATION OCCURS

Runtime, before handler. Workshop does not validate. Splunk does not ALLOW or DENY.

## FAILURE PATH

Defended RETEST: DENY `delegated_authority_not_granted`. No downstream MCP. Runtime handler count 0.

## FAIL-OPEN POSSIBILITY

Vulnerable ATTACK: ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority`, `authority.source=ambient_deputy`, then MCP ALLOW and execution. Labeled INTENTIONALLY VULNERABLE.

## TELEMETRY

Indexed: caller, deputy (when hop 1 exists), `authority.source`, both control decisions, mcp.* when begun. Missing: `allowed_tools`, RETEST hop-1 deputy (`deputy_not_on_indexed_hop1`), `gen_ai.tool.call.id`.

## Could the dangerous operation happen before validation?

Runtime: no. Workshop: RETEST teaching does not claim Splunk prevented the handler. ATTACK teaching does not hide that execution followed fail-open ALLOW.

## Could missing context become ALLOW?

Not in canonical A/B/C. Workshop empty states do not treat missing rows as ALLOW or DENY.

## Could one agent silently inherit another agent's authority?

ATTACK yes, labeled `ambient_deputy`. RETEST no. Workshop COMPARE keeps that distinction. BASELINE legitimate `delegated` is not taught as an attack.

## Could telemetry report DENY after the operation already happened?

RETEST control `executed=false` `outcome=prevented`; handler 0. Workshop does not present mcp.failed as prevention. DET-MCP-001 is silent on ATTACK because there is no DENY-then-start.

## Which security assertion currently lacks a test?

Workshop JSON/XML, tokens, bind-only SPL, forbidden claims, no DET-MCP-006, empty-state copy. Playwright token/tab capture is OBSERVED, not a pytest. Runtime handler 0 remains a 7B/7C spy assertion, not a Studio test.

## Workshop semantic checks (this phase)

| Forbidden teaching | Workshop result |
|--------------------|-----------------|
| agent has permission, therefore caller has permission | Rejected. DEPUTY AUTHORITY ≠ CALLER AUTHORITY. |
| tool executed, therefore request was authorized | Rejected. ATTACK execution is not caller grant. |
| Splunk found no start event, therefore prevention is proven | Rejected. Runtime handler count is authoritative. |
| detector did not fire, therefore no confused-deputy attack | Rejected. DETECT: DETECTION ANALYZED — NO NEW DETECTOR. LIVE 0 ≠ attack absent. |

No runtime or schema changes were made to improve presentation.
