# HITL approval design — independent review

**Date:** 2026-10-01
**Role:** review only. This file is the review artifact. The design was not edited.
**Reviewed baseline:** `8272c03f91eb6c1e17adf3cd7d3a773f4d8f86b8`
**Design:** `docs/architecture/AGENTSEC_HITL_APPROVAL_DESIGN.md`

Evidence classes: OBSERVED in source and schema, DOCUMENTED in existing notes, and the design’s proposed packet remains SIMULATED. This review did not run Splunk and did not implement a workshop.

## 1. Repository state

| Ref | SHA | Result |
| --- | --- | --- |
| `HEAD`, `develop`, `origin/develop` | `8272c03f91eb6c1e17adf3cd7d3a773f4d8f86b8` | Matches the named baseline |
| `main` and `origin/main` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | Unchanged |
| `v1.0.0-rc2^{}` | `1be214b92f840f843aaf27fb2b9536f764dd7126` | Unchanged |
| RC3 | no tag | Not created |

The HITL design and its learning note are untracked local files. Unrelated untracked files remain: `docs/plans/` and the older identity, detection, and A2A review files. They were not cleaned.

Repository integrity: PARTIAL, because the design under review is not in git. Remote sync: PASS. No runtime, schema, or control file changed during this review.

## 2. Current HITL reality

Current coverage is **NOT MODELED**.

OBSERVED:

- `schemas/security_event.schema.json` allows control decisions ALLOW, DENY, ERROR, and OBSERVE. `REQUIRE_APPROVAL` is not in that enum.
- `agentsec.principal.type` allows `user`, `agent`, and `system`. It does not allow `human`.
- `src/` has no `REQUIRE_APPROVAL` symbol.
- Identity, goal, and memory fixtures list `approval` and `approved` among authority-like fields that attacker content must not supply. That rejects a claimed approval. It does not record one.
- CTRL-MCP-001 remains `authorize_tool` and `authorize_resource`.
- Execution start remains `agentsec.mcp.started`. Completion is a separate event name, `agentsec.mcp.completed`. No approval-linked resource outcome exists.

DOCUMENTED only:

- `docs/ARCHITECTURE.md`, `docs/ATTACK_CONTROL_MODEL.md`, and `docs/MCP_ARCHITECTURE.md` list `REQUIRE_APPROVAL` as later or reserved vocabulary.
- Threat-model, privacy, memory, and capstone texts set human approval to NOT MODELED.
- `docs/AGENTSEC_CURRICULUM_COVERAGE_MATRIX.md` says the HITL schema vocabulary is IMPLEMENTED. The schema enum does not contain `REQUIRE_APPROVAL`. That matrix sentence overclaims. The HITL design does not repeat it.

`REQUIRE_APPROVAL` classification: DOCUMENTED. It is not a runtime path, not an indexed field, and not a control decision.

## 3. MCP-004 boundary

`authorize_resource` models a resource grant. A known policy id outside `lending-basics` is DENY `resource_not_granted`. On the vulnerable profile, with no identity overlay, the same call can ALLOW with `vulnerable_profile_fail_open:resource_not_granted`. The known ungranted fixture is `executive-restricted`.

That is tool-resource authorization. The function does not read an approver, an approval id, or an approval time. Historical MCP-004 rows are not human approvals. The design says this and forbids relabeling them. The distinction holds.

## 4. Teaching case

The selected case is post-approval parameter mutation. The same tool, `lookup_policy`, is paired with two resources:

- Approved action: `lending-basics`, reference `sim-action-lending-basics`.
- ATTACK and RETEST submission: `executive-restricted`, reference `sim-action-executive-restricted`.
- BASELINE submission: `lending-basics`, the approved action.

ATTACK and RETEST are the same mutated request. They differ in the labeled tool-PDP outcome: ATTACK ALLOW only as `vulnerable_profile_fail_open:stale_approval_accepted`, RETEST DENY `approval_binding_mismatch`. Both reasons are described as packet labels and are not present in `authorize.py`. BASELINE is MATCH and ALLOW `tool_granted`.

Tool and resource stay separate. Binding MISMATCH is not defined as DENY, and MATCH is not defined as ALLOW.

This is a stronger first case than expiry or replay. Expiry would sit too close to the later credential phase. Replay needs a second request before the binding lesson is clear. Mutation uses fixture ids the repository already has, without claiming those historical events are approvals.

The overlap with MCP-004 is real and is disclosed. Implementers must keep the simulated packet off the historical `resource_not_granted` rows. That is a workshop constraint, not a reason to reject the case.

## 5. Security chain

The design keeps these as separate claims:

- `approver-sam` is a claimed label. A row titled SIMULATED APPROVER AUTHENTICATION RESULT does not prove a person clicked approve.
- Authentication does not create approval authority. Authority stays NOT PROVEN.
- APPROVE is not CTRL-MCP-001 ALLOW.
- Binding MATCH is not ALLOW. Binding MISMATCH is not DENY.
- CTRL-MCP-001 remains the only tool PDP.
- `agentsec.mcp.started` is start evidence. Completion is separate. Resource impact stays NOT PROVEN.
- Splunk displays rows and does not authenticate, approve, or authorize.

`CTRL-HITL-001` is an optional name for a future binding row whose results are MATCH, MISMATCH, EXPIRED, or ABSENT. The design says those words are not tool decisions, that the control is not implemented, and that the first packet can omit the id. It is approval-binding evidence, not a second PDP.

Expiry fields are teaching metadata. The submitted time is inside the window in every mode, so expiry is not the attack. No credential issuance, rotation, revocation, or refresh is specified.

Replay is deferred. One optional labeled illustration says a second request id with the same approval id is APPROVAL REPLAY SUSPECTED, not an automatic DENY. That is not the primary exercise. The conceptual scope includes request, action reference, tool, resource, audience, and time. Purpose is reserved for a later phase.

Action references are correlation ids. The design states they are not signatures, digests, or tamper-proof bindings. No cryptographic implementation is proposed.

## 6. Ledger, failures, and later phases

The ledger is a learner artifact. Historical rows leave approval fields NOT OBSERVED. Simulated rows must stay marked SIMULATED HITL PACKET.

The column list names requested tool and requested resource, plus approved and submitted action references. It does not also name approved tool and approved resource as separate columns. Section 10’s table and the exercises do require those values. The omission is in the ledger bullet, not in the case definition.

Failure language includes NO APPROVAL EVIDENCE, APPROVER AUTHENTICATION NOT PROVEN, APPROVAL AUTHORITY NOT PROVEN, APPROVAL EXPIRED, APPROVAL BINDING MISMATCH, APPROVAL REPLAY SUSPECTED, INSUFFICIENT EVIDENCE, CORRELATION NOT ESTABLISHED, and RESOURCE IMPACT NOT PROVEN. The design forbids SAFE, TRUSTED, and HUMAN VERIFIED.

A REPLAY / STATIC packet is sufficient. Runtime HITL, a new LIVE attack, a new LIVE lab, a schema change, and an ExternalEvidence change are not required for that packet. A later emitter would need a schema change. The design says the first workshop must not write the packet through schema 1.9.0.

The lesson follows identity and A2A because a human label and an agent grant are already separate from tool authorization. It leaves room for credential lifetime, retrieval purpose, memory ownership, and inventory keys without building them. The action-reference shape can later describe a deployment, a cloud change, or a customer operation. Those scenarios are not specified as workshops.

Framework text points at existing AgentSec documents and leaves new HITL mappings as **NEEDS_EXTERNAL_VALIDATION**. No technique id and no compliance claim are added.

Secret hygiene: PASS. References are `sim-approval-001`, `sim-action-lending-basics`, `sim-action-executive-restricted`, and `sim-auth-ref-approver-001`. No password, token, key, certificate, or customer identity is required. No new cryptography is introduced. Codeguard applies because this review only confirms that absence.

## 7. Findings

BLOCKER: 0. HIGH: 0. MEDIUM: 0.

LOW: 2.

1. The simulated authentication row may use principal type `human`. The schema enum is `user`, `agent`, and `system`. The design keeps this inside a simulated packet, but an implementer can over-read `human` as proof of a person if the simulated label is dropped.
2. The ledger bullet list does not name approved tool and approved resource separately. The mutation case and the exercises already keep those values apart.

## 8. Claims that remain unproven

1. `approver-sam` or `applicant-web` is an authenticated human.
2. That person approved the action or caused execution.
3. Historical MCP-004 events are HITL approvals.
4. APPROVE, binding MATCH, or binding MISMATCH determines CTRL-MCP-001.
5. CTRL-MCP-001 ALLOW proves execution.
6. `agentsec.mcp.started` or completion proves a resource change.
7. BASELINE proves universal safety.
8. RETEST proves universal resistance to mutated approvals.
9. An approval id proves the approval is current.
10. A simulated credential reference proves possession of a credential.

## 9. Verdict

The design does not invent a runtime approval gate. ATTACK and RETEST share one mutated submission. BASELINE is the approved submission. Human identity, approval authority, binding, tool authorization, execution, and impact stay separate. CTRL-MCP-001 remains the tool PDP. Expiry and replay are bounded and are not pulled forward into credentials.

GO — AUTHORIZE BOUNDED HITL APPROVAL WORKSHOP

This verdict authorizes a later implementation prompt. It does not implement the workshop.
