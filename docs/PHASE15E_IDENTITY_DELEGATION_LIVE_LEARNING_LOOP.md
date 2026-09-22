# Phase 15E — Agent Identity / Delegation LIVE purple-team learning loop

**Date:** 2026-09-20  
**Mode:** IMPLEMENTATION + VALIDATION  
**Schema:** **1.9.0** unchanged. No DET-A2A. Runtime authorization **UNCHANGED**.  
**Stop after this file.** Do not implement real A2A, OAuth/OIDC, SPIFFE, MLTK, capstone, or another migration.

Predecessor: Phase 15D PASS (LAB-AGENT-GOAL-INTEGRITY-001 LIVE). Locked reference labs: `LAB-PI-001`, `LAB-MCP-001`, `LAB-RAG-CONTEXT`, `LAB-MEMORY-001`, `LAB-AGENT-GOAL-INTEGRITY-001`. This phase migrates **existing** `LAB-AGENT-DELEGATION-001` / `A2A-001` only (Phases 12A–12C architecture).

## Predecessor verification (DOCUMENTED)

Inspected before implementation:

- LAB-AGENT-DELEGATION-001 / A2A-001
- Schema 1.8.0 identity fields now carried by schema **1.9.0** (no bump)
- A2ADelegationRequest + fingerprint (reused; not invented)
- CTRL-IDENTITY-001 OBSERVE `identity_claim_is_not_grant` / `untrusted_claim`
- CTRL-MCP-001 sole tool PDP
- Actors: principal `applicant-web`, caller `acme-agent-advisor-005`, callee `acme-agent-fulfillment-006`
- Both agents coded `lookup_policy` / `policy:read` / `lending-basics` only
- Neither coded `lookup_customer_tier` / `customer:read`
- Overlay `vulnerable_profile_fail_open:caller_identity_derived_authority`
- Hunt Q-AGENT-DELEGATION-AUTHORITY + Q-MCP reuse
- DET-MCP-001 unchanged; Phase 12D: DETECTION ANALYZED — NO NEW DETECTOR
- Phase 12C REPLAY ids: BASELINE `b419465c-…` / ATTACK `f846be88-…` / RETEST `271695f5-…`

Discrepancies (documented, then closed by this phase):

- Inventory/design mentioned HTTP `/identity/delegate`; repository had in-process pipeline only until 15E.
- Hunt catalog still labels schema 1.8.0; emitters are 1.9.0. Hunt SPL is version-agnostic. Not rewritten.
- `IDENTITY_LAB_ID` was unused in telemetry (`settings.lab_id`). LIVE ExperimentContext now carries `LAB-AGENT-DELEGATION-001`.
- No Studio view existed (12E deferred). 15E creates `ws_lab_agent_delegation` as REPLAY syllabus.

Coded actor/grant semantics were not changed.

## Security property (unchanged)

INV-001 + INV-002 + INV-005.

IDENTITY CLAIM != AUTHENTICATION  
DELEGATION CLAIM != AUTHORIZATION  
CALLER ID != GRANT  
AGENT ID STRING != CRYPTOGRAPHIC IDENTITY  
A + B != NEW AUTHORITY

CTRL-IDENTITY-001 remains OBSERVE only. It does not ALLOW, DENY, mint AllowTicket, authenticate, or mutate `coded_policy()`.

ATTACK (vulnerable): same privileged claim → IDENTITY OBSERVE → overlay fail-open → CTRL-MCP-001 ALLOW → `lookup_customer_tier` handler 1.

RETEST (defended): same frozen request → IDENTITY still OBSERVE → CTRL-MCP-001 DENY `tool_not_granted` → handler 0 → no `mcp.started`.

WHO AUTHENTICATED = NOT PROVEN / NOT MODELED.

## Live experiment architecture

| Mode | Specimen | Claim | Profile | Expected |
|------|----------|-------|---------|----------|
| BASELINE | A2A-BASELINE | lookup_policy / policy:read | defended | IDENTITY OBSERVE; MCP ALLOW tool_granted; lookup_policy 1; lookup_customer_tier 0. Not SAFE. |
| ATTACK | A2A-001 | privileged triple | vulnerable | IDENTITY OBSERVE; overlay; MCP ALLOW; lookup_customer_tier 1 |
| RETEST | A2A-001 | **same privileged triple** | defended | IDENTITY OBSERVE; MCP DENY tool_not_granted; handler 0 |

Browser selects lab/specimen/mode/execution only. Unknown/authority fields → ERROR, not DENY/ALLOW.

Fingerprint = existing `A2ADelegationRequest.fingerprint`. ATTACK = RETEST = `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd`.

HTTP body is `{claim_id,user_id,experiment_id}`. The A2A body is reconstructed server-side via `claim_payload_for`. Canonical snapshot JSON is not accepted as HTTP because it flattens `claimed_*` outside `ALLOWED_A2A_FIELDS`.

## Learning experience

LEARN → PREDICT → LIVE ATTACK → COPY RUN.ID → INVESTIGATE → EXPLAIN → DEFEND → LIVE RETEST → COMPARE → PROVE.

Dashboard Studio = syllabus. Splunk Search = notebook. Attack Service = closed launcher. AcmeBank = enforcement. Splunk = evidence copy.

Path A: construct the search. Path B: existing Q-AGENT-DELEGATION-AUTHORITY / Q-MCP after the attempt. Bound tables are REPLAY. Fresh LIVE stays in Search.

## Detection

**DETECTION ANALYZED — NO NEW DETECTOR.** DET-MCP-001 unchanged. ATTACK is MCP ALLOW so DET-MCP-001 is 0. RETEST DENYs then does not start, so DET-MCP-001 is 0. `0 rows != SAFE`. No DET-A2A.

## Validation

**PASS 2026-09-20.** Official LIVE pair MEASURED in `PHASE15E_SPLUNK_LIVE_VALIDATION.md`:

- ATTACK `110dd7a6-58b5-472a-ae80-aec76e11bf4e` 10=10, IDENTITY OBSERVE, MCP ALLOW overlay, lookup_customer_tier handler 1
- RETEST `7e4f74a8-84bf-4d18-abe1-0dcc7f0ab58a` 9=9, IDENTITY OBSERVE, MCP DENY `tool_not_granted`, handler 0

Fingerprint both: `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd`.

Offline pytest: **848 passed, 2 deselected**. Playwright pass15e: 10/10 tabs; Attack Service 200 at 1440/1280/1024; no unresolved BLOCKER/HIGH.

Schema **1.9.0**. No DET-A2A. CTRL-IDENTITY-001 unchanged OBSERVE. CTRL-MCP-001 unchanged sole tool PDP.

## Stop

Do not implement real A2A. Do not add OAuth/OIDC/JWT/SPIFFE. Do not create DET-A2A. Do not bump schema. Do not start capstone. Do not start another migration.
