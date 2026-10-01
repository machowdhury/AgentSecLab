# A2A Authentication and Delegation workshop — independent review

**Date:** 2026-09-30
**Role:** review only. This file is the review artifact. The workshop was not edited.
**Reviewed commit:** `8272c03f91eb6c1e17adf3cd7d3a773f4d8f86b8`
**Authorized design commit:** `7335a540d2259e191fc477b6644e19f578402add`
**Implementation report:** `docs/reviews/AGENTSEC_A2A_AUTHENTICATION_DELEGATION_WORKSHOP_IMPLEMENTATION.md`

Evidence classes: OBSERVED in the committed workshop files, TESTED by the offline suite run during this review, and MEASURED in the browser for layout only. This review did not take a new Splunk export. Historical run counts remain previously measured.

## 1. Repository state

| Ref | SHA | Result |
| --- | --- | --- |
| `HEAD`, `develop`, `origin/develop` | `8272c03f91eb6c1e17adf3cd7d3a773f4d8f86b8` | Matches the implementation commit |
| `main` and `origin/main` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | Unchanged |
| `v1.0.0-rc2^{}` | `1be214b92f840f843aaf27fb2b9536f764dd7126` | Unchanged |
| RC3 | no tag | Not created |

The design commit is an ancestor of HEAD. The implementation diff does not touch `src/agentsec`, `schemas/`, or `savedsearches.conf`.

`SCHEMA_VERSION` is `1.9.0`. `EXTERNAL_CONTRACT_VERSION` is `1.0.0`. The three saved-search stanzas remain `disabled = 1`. DET-MCP-001 also remains `enableSched = 0`. `LAB-A2A-AUTH-DELEGATION` is absent from `known_lab_ids()` and has no lab manifest.

Working tree: no staged or modified tracked files at review start. Unrelated and untracked: `docs/plans/` and the older identity and detection review files. Those are not workshop defects.

Repository integrity: PASS. Remote sync: PASS. The implementation report is tracked. One workshop directory and one Studio view exist.

## 2. Placement and packet

Levels remain L0 through L10. Checkpoint `A2A-AUTH-DELEGATION` is the only checkpoint with lab id `LAB-A2A-AUTH-DELEGATION`. Its placement is `L7 → Identity/NHI Workshop → A2A Authentication & Delegation Workshop → L8`. Mode is `REPLAY`, `live_launcher` is false, and the evidence class is `SIMULATED / REPLAYED`.

Navigation order is Identity/NHI, then this workshop, then Privacy. That is the learner path. No second A2A workshop was found.

The static packet matches the approved case:

| Mode | Request | Grant | Delegation | CTRL-MCP-001 |
| --- | --- | --- | --- | --- |
| ATTACK | `lookup_customer_tier` / `cust-001` | `lookup_policy` / `lending-basics` | MISMATCH | ALLOW `vulnerable_profile_fail_open:caller_identity_derived_authority` |
| RETEST | `lookup_customer_tier` / `cust-001` | `lookup_policy` / `lending-basics` | MISMATCH | DENY `tool_not_granted` |
| BASELINE | `lookup_policy` / `lending-basics` | `lookup_policy` / `lending-basics` | MATCH | ALLOW `tool_granted` |

ATTACK and RETEST are the same request. BASELINE is a different request. Authentication on every simulated row is labeled `SIMULATED AUTHENTICATED`. Tool and resource are separate fields. The workshop states that a same-tool / different-resource case is NOT MODELED.

## 3. Semantic chain

The workshop text keeps the stages apart:

- Caller, callee, and `applicant-web` are claims. `applicant-web` is not proven human, authenticated, or causal.
- Authentication rows are labeled `SIMULATED AUTHENTICATION RESULT`. The result does not authorize a tool and does not mean AgentSec authenticates agents at runtime.
- Delegation rows are labeled `SIMULATED DELEGATION DECISION`. Two agent ids are explicitly rejected as a delegation proof.
- `MATCH` is not ALLOW. `MISMATCH` is not DENY.
- CTRL-IDENTITY-001 observes a claim. CTRL-MCP-001 remains the tool PDP. No `CTRL-A2A-PDP` appears.
- `agentsec.mcp.started` is separate execution-start evidence. A start does not prove completion. Resource impact stays `NOT PROVEN`.
- Splunk is described as downstream evidence. The mission says searching the simulated packet does not make it measured authentication.

The historical search selects `agentsec.workflow.entry=/identity/delegate` and then stamps `HISTORICAL CLAIM-ONLY CORPUS`, `authentication=NOT OBSERVED`, and `delegation=NOT OBSERVED`. Those last two values are search labels, not indexed authentication fields. The prose keeps the 6 / 6 / 1 counts and the zero counts for `who_authenticated` and `LAB-AGENT-DELEGATION-001` as previously measured. This review did not re-measure them.

Credential references are `sim-auth-ref-advisor-001` and `sim-auth-ref-fulfillment-001`. Issued-at, not-before, and expires-at are packet metadata. No issuance, rotation, revocation, replay prevention, OAuth, JWT validation, PKI, mTLS, or SPIFFE implementation is present. No secrets, certificates, or private keys were found in the workshop files.

## 4. Learner path

The mission asks a question and tells the learner to reject “authenticated agent = authorized request.” It does not print the three-mode decision table.

Path A then shows the simulated authentication records, the shared grant, and the three requested tool/resource pairs. It asks the learner to decide MATCH or MISMATCH. The exact per-mode CTRL-MCP-001 decisions and execution flags are printed on Path B.

One Path A sentence states that a MISMATCH can appear beside an ALLOW in the vulnerable case. That preserves the correct separation, and it also reveals the teaching fault before Path B. Learner progression is MIXED: the chain is explicit and advances past the identity workshop, while the vulnerable pairing is no longer something the learner has to discover unaided.

## 5. Browser observation

Observed in Chrome after login at `ws_lab_a2a_auth_delegation`. HTTP status 200. Screen reader: NOT TESTED. No WCAG claim.

| Viewport | Horizontal overflow at 100% | Tabs covered by the favorite toolbar |
| --- | --- | --- |
| 1920 | scrollWidth 1920, clientWidth 1920 | none |
| 1440 | scrollWidth 1440, clientWidth 1440 | CONCLUDE |
| 1280 | scrollWidth 1280, clientWidth 1280 | COMPARE |
| 1024 | scrollWidth 1024, clientWidth 1024 | AUTHORIZE |

At CSS zoom 2 on the 1024 viewport, scrollWidth was 1920 and clientWidth was 1024.

The focused mission label had `role` null, outline style `none`, and no box shadow. ArrowRight did not move focus to another tab. Document title was `undefined | Splunk 10.2.7`.

This is the previously observed Splunk toolbar overlap, now reaching an earlier tab because this workshop has a longer tab strip. The review did not change the UI and did not retest whether a DOM click can still activate a covered tab.

## 6. Tests and hygiene

Executed in this review:

- `tests/splunk/test_a2a_auth_delegation_workshop.py`: `5 passed in 0.02s`
- Full offline suite: `1047 passed, 3 deselected in 9.01s`

The implementation report’s separate `60 passed` selection was not repeated. The full suite includes those academy contracts and passed. These tests do not prove runtime authentication or delegation enforcement.

Secret hygiene: PASS. The review found synthetic references and prohibition text, not credential material. No new cryptography or certificate was added. Codeguard applies because this review only records that absence.

## 7. Findings

BLOCKER: 0. HIGH: 0.

MEDIUM: 1. At 1440, 1280, and 1024, the Splunk favorite toolbar covers CONCLUDE, COMPARE, and AUTHORIZE respectively. At 1920 it covers none. Two-times zoom at 1024 overflows horizontally. This is a learner-access limitation of the existing Splunk shell, not an incorrect security lesson.

LOW: 2.

1. Path A states that the vulnerable case can pair MISMATCH with ALLOW before Path B shows which mode does so.
2. The document title renders as `undefined | Splunk 10.2.7`, and the sampled tab label does not expose a visible focus style or tab semantics.

## 8. Claims that remain unproven

1. `applicant-web` is an authenticated human or caused the call.
2. The historical `/identity/delegate` corpus is authenticated A2A or real delegated authority.
3. An agent id proves authenticated identity.
4. Authentication proves delegation.
5. Delegation MATCH proves CTRL-MCP-001 ALLOW.
6. Delegation MISMATCH proves DENY.
7. CTRL-MCP-001 ALLOW proves execution.
8. `agentsec.mcp.started` proves successful completion.
9. Execution proves downstream resource impact.
10. ATTACK is production A2A authentication.
11. RETEST proves universal delegation enforcement.
12. BASELINE proves universal safety.

## 9. Verdict

The implemented packet, labels, and control split match the approved design. Runtime authentication, delegation enforcement, a new PDP, schema, ExternalEvidence, detectors, and later-phase capabilities were not added. The toolbar finding is real and should remain visible to a later UI pass. It does not make the security lesson incorrect.

GO — A2A WORKSHOP VALIDATED; AUTHORIZE HITL DESIGN

This verdict authorizes a later HITL design prompt. It does not implement HITL, short-lived credentials, RAG authorization, memory isolation, AI-BOM, or supply-chain security.
