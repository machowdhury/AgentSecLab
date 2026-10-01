# Human-in-the-loop approval

**Status:** DESIGN ONLY. This document does not implement a workshop, a control, or a schema change.  
**Baseline:** `8272c03f91eb6c1e17adf3cd7d3a773f4d8f86b8`  
**Evidence classes:** OBSERVED in source and schema, DOCUMENTED in existing architecture notes, SIMULATED only for the proposed teaching packet. Nothing here is a new live experiment.

This document recommends a later REPLAY workshop. It does not authorize implementation by itself. An independent design review is still required.

## 1. Executive summary

AgentSec can show a tool decision and a tool start. It cannot show that a human approved the action that was submitted. `REQUIRE_APPROVAL` is a documented vocabulary word. It is not a control, not a schema decision, and not an event.

The first lesson should be a labeled **SIMULATED / REPLAYED** packet about post-approval parameter mutation. An approval names one action. A later submission names another. ATTACK continues anyway under a labeled vulnerable teaching condition. RETEST uses the same mutated submission and the tool PDP denies it. BASELINE submits the action that was approved.

The approval record does not replace CTRL-MCP-001. Expiry and replay are visible concepts. They are not this workshop’s attack, and they are not short-lived credentials.

## 2. Current HITL reality

Current HITL coverage is **NOT MODELED**.

| Question | Today | Class |
| --- | --- | --- |
| Authenticated human approver | No approver principal, method, issuer, or result | NOT MODELED |
| Approval request | No request id, requested action, or requested-at event | NOT MODELED |
| Approval decision | Schema decisions are ALLOW, DENY, ERROR, OBSERVE. `REQUIRE_APPROVAL` is absent from `src/` and from the schema enum | DOCUMENTED vocabulary only |
| Approval expiry | No `approved_at`, `not_before`, or approval `expires_at` | NOT MODELED |
| Approval replay | No approval id bound to one request | NOT MODELED |
| Approval-to-action binding | No approved-action reference and no submitted-action reference | NOT MODELED |
| Post-approval mutation | Not represented as an approval problem | NOT MODELED |
| Approval revocation | Not represented | NOT MODELED |
| Tool authorization | CTRL-MCP-001 in `authorize_tool` and `authorize_resource` | IMPLEMENTED |
| Execution | `event.name=agentsec.mcp.started` | IMPLEMENTED, bounded to start |
| Completion | `agentsec.mcp.completed` exists as an event name | IMPLEMENTED when present. A start does not prove it |
| Resource outcome | No approval-linked resource-change event | NOT MODELED for this lesson |

`applicant-web` remains a principal label with `agentsec.principal.type=user`. That label does not prove a human, an authentication, or an approval click.

`LAB-MCP-004` already has a different fail-open. A vulnerable profile can ALLOW a known ungranted policy id with `vulnerable_profile_fail_open:resource_not_granted`. That is resource authorization. It is not an approval record. This design must not relabel those historical events as HITL.

## 3. Existing evidence inventory

OBSERVED and usable as contrast, not as approval evidence:

- CTRL-MCP-001 ALLOW `tool_granted` and DENY `tool_not_granted`.
- CTRL-MCP-001 resource decisions, including DENY `resource_not_granted` and the MCP-004 fail-open above.
- `agentsec.mcp.started` and, when present, `agentsec.mcp.completed`.
- Identity claims: `applicant-web`, `acme-agent-advisor-005`, `acme-agent-fulfillment-006`.
- Existing fixtures: tool `lookup_policy`, scope `policy:read`, granted resource `lending-basics`, known ungranted resource `executive-restricted`.
- The A2A workshop’s simulated packet, which already says a later approval reference can attach to tool, resource, parameter reference, purpose, and time. That reference was not created.

DOCUMENTED only:

- `docs/ARCHITECTURE.md` lists `REQUIRE_APPROVAL` as later vocabulary.
- Threat-model, privacy, memory, and multi-stage materials set `human_approval` to NOT MODELED.
- INV-006 says privileged workflow transitions need authorized state transitions. No HITL state machine implements it.

SIMULATED, and only after a later workshop is separately authorized:

- The teaching packet in this design.

NOT MODELED:

- Human authentication, approval authority, approval expiry enforcement, replay prevention, revocation, and downstream resource impact.

## 4. Evidence gaps

1. No approval request event.
2. No approval decision event distinct from CTRL-MCP-001.
3. No approver authentication evidence.
4. No proof that a named person was allowed to approve the action.
5. No binding between an approved parameter set and the submitted parameter set.
6. No approval clock.
7. No replay discriminator such as one approval id used for a second request id.
8. No resource-outcome event tied to an approval.
9. No indexed field that can be searched as “human approved this.” An empty search is NO APPROVAL EVIDENCE, not proof that no human exists.

## 5. Core security lesson

Human approval is a security artifact, not a magic boolean.

A human-shaped label is not an authenticated human. An approval request is not an approval. An approval record is not proof that the named approver authenticated or was allowed to approve. An approval is not valid forever. An approval for one action does not cover another action. An approval for one parameter set does not cover mutated parameters. An approval does not replace CTRL-MCP-001. A tool ALLOW does not prove execution. A start does not prove completion. Execution does not prove a downstream resource change.

## 6. HITL security model

The learner keeps these as separate records:

requested action, requested parameters, approval request, approver claim, approver authentication, approval authority, approval decision, approval scope, approval time window, approved action reference, submitted action reference, approval binding, CTRL-MCP-001 decision, execution start, completion, resource outcome.

The first workshop packet is **SIMULATED / REPLAYED**. It is not historical runtime approval and not production workflow software.

Proposed packet identities, all synthetic:

- requesting and executing agent: `acme-agent-fulfillment-006`
- claimed approver: `approver-sam`
- approver type on the simulated authentication row: `human`
- `applicant-web` may remain visible as the existing unauthenticated principal label

`approver-sam` is a label in the packet. The packet may also carry a row labeled **SIMULATED APPROVER AUTHENTICATION RESULT**. That row does not prove a person clicked approve, and it does not authorize the tool.

## 7. Approval lifecycle

Each stage needs its own evidence:

1. Request. The agent proposes `lookup_policy` with parameters P1.
2. Approval request. A record asks for a decision on that exact proposal.
3. Approval decision. APPROVE or REJECT. APPROVE is not CTRL-MCP-001 ALLOW.
4. Approval validity. The decision is inside `not_before` and `expires_at`, and it has not been marked revoked. Revocation stays NOT MODELED as an implemented control.
5. Action binding. The submitted action reference equals the approved action reference.
6. Tool authorization. CTRL-MCP-001 decides the tool and resource.
7. Execution. `agentsec.mcp.started` when a separate row exists.
8. Resource outcome. A later outcome row. The first packet leaves this NOT PROVEN.

## 8. Human identity boundary

`approver.id=approver-sam` does not prove that Sam is a human, that Sam authenticated, that Sam clicked approve, that Sam was allowed to approve, or that Sam was present.

If the packet includes authentication metadata, the label is **SIMULATED APPROVER AUTHENTICATION RESULT**. Fields may be principal id, principal type `human`, method `lab_assertion`, issuer `agentsec-simulated-lab-verifier`, audience, result, credential reference, issued-at, not-before, and expires-at. The credential reference is an id such as `sim-auth-ref-approver-001`. It is not a secret and not proof of possession.

Historical identity events stay claim-only. This design does not rewrite them as authenticated human approval.

## 9. Approval authority boundary

These questions stay separate:

- Who is claimed to have approved?
- Was that principal authenticated?
- Was that principal allowed to approve this action?
- What exactly was approved?
- Is the approval still inside its time window?
- Does the current submission match the approval?
- Did CTRL-MCP-001 authorize the tool?

The first packet sets approval authority to **NOT PROVEN**. A simulated authentication result does not create approval authority. No authority engine is added.

## 10. Approval-to-action binding

Same tool, different parameters. This is the mutation:

| | Approved | Submitted in ATTACK and RETEST | Submitted in BASELINE |
| --- | --- | --- | --- |
| Tool | `lookup_policy` | `lookup_policy` | `lookup_policy` |
| Scope | `policy:read` | `policy:read` | `policy:read` |
| Resource | `lending-basics` | `executive-restricted` | `lending-basics` |
| Action reference | `sim-action-lending-basics` | `sim-action-executive-restricted` | `sim-action-lending-basics` |

Those references are teaching correlation ids. They are not cryptographic digests and not integrity proofs. No hash function is added.

Binding result:

- ATTACK and RETEST: **MISMATCH**
- BASELINE: **MATCH**

MISMATCH is not a tool DENY. MATCH is not a tool ALLOW.

`LAB-MCP-004` already denies or fail-opens `executive-restricted` as a resource-grant question. The HITL packet uses the same fixture ids so the parameter change is recognizable. It must be labeled as a new simulated approval case, not as a replay of MCP-004.

## 11. Temporal and expiry model

The simulated approval carries `requested_at`, `approved_at`, `not_before`, `expires_at`, and `action_submitted_at`. In all three modes the submitted time sits inside the window. The learner can see that the failure is the parameter change, not the clock.

An approval id inside an expired window is **APPROVAL EXPIRED**. Existence of the id does not refresh it. A missing time field is NOT OBSERVED, not an immortal approval.

Approval lifetime is not credential lifetime. This design does not issue, rotate, refresh, or revoke credentials.

## 12. Replay model

Replay means one approval id presented for a different request id or a different action reference. The first workshop does not use that as the attack. The packet has one approval id, `sim-approval-001`, and one request id per mode. ATTACK and RETEST share the mutated submission. They are not two replays of one approval against two business transactions.

A second example may appear as a labeled non-exercise: the same approval id on a new request id is **APPROVAL REPLAY SUSPECTED**, not automatically DENY, until a binding check and CTRL-MCP-001 each have a row. Production anti-replay infrastructure is not in this design.

Replay is deferred as a secondary illustration because the mutation case already teaches “this approval does not cover a different action,” and expiry would collide with the later short-lived credential phase if it became the only attack.

## 13. ATTACK, RETEST, and BASELINE

The same simulated approver authentication and the same approval decision appear in every mode: `approver-sam`, result APPROVE, tool `lookup_policy`, resource `lending-basics`, action reference `sim-action-lending-basics`, audience `acme-agent-fulfillment-006`.

ATTACK:

- submitted tool `lookup_policy`
- submitted resource `executive-restricted`
- submitted action reference `sim-action-executive-restricted`
- binding MISMATCH
- CTRL-MCP-001 ALLOW only as the labeled vulnerable teaching condition
- candidate reason, not implemented: `vulnerable_profile_fail_open:stale_approval_accepted`
- a separate start row may exist in the packet
- resource impact NOT PROVEN

RETEST:

- the same submitted action as ATTACK
- binding MISMATCH
- CTRL-MCP-001 DENY
- candidate reason, not implemented: `approval_binding_mismatch`
- do not infer a start
- resource impact NOT PROVEN

BASELINE:

- submitted resource `lending-basics`
- submitted action reference `sim-action-lending-basics`
- binding MATCH
- CTRL-MCP-001 ALLOW `tool_granted`
- a separate start row is execution evidence
- resource impact NOT PROVEN

ATTACK and RETEST are the same mutated request. BASELINE is the matching request. Do not describe the three modes as one submission.

The candidate reasons are packet labels. They must not be added to `authorize.py` in the first workshop. They are not the MCP-004 reason `vulnerable_profile_fail_open:resource_not_granted`.

## 14. Control model

CTRL-MCP-001 remains the only tool PDP. Do not create a second tool PDP.

A candidate evidence control, `CTRL-HITL-001`, may record the binding evaluation: MATCH, MISMATCH, EXPIRED, or ABSENT. Those words are not ALLOW or DENY. The control is not implemented. The first workshop can represent the same evaluation as a row labeled **SIMULATED APPROVAL BINDING** and omit the control id until a later runtime design.

`REQUIRE_APPROVAL` stays unused. Do not overload OBSERVE to mean “approved.”

Schema 1.9.0 does not need to change for a packet that is clearly SIMULATED and is not written through the emitter. A later runtime that emits approval events would need a schema change. That change is not required for the first workshop.

## 15. Interaction with A2A

The A2A workshop remains as it is. HITL sits after it in the curriculum and does not edit that workshop.

A later policy evaluation may receive three inputs: a simulated agent authentication, a bounded delegation, and a scoped human approval. Each input is evidence. None of them is CTRL-MCP-001 ALLOW. The first HITL packet does not re-teach the A2A customer-tier case. It keeps the delegated tool as `lookup_policy` and changes only the submitted resource after approval.

## 16. Interaction with CTRL-MCP-001

Order, each step with its own row:

identity claim, then simulated approver authentication, then simulated approval decision, then simulated approval binding, then CTRL-MCP-001, then a possible `agentsec.mcp.started`, then a possible completion, then a possible resource outcome.

Disagreement is the lesson. In ATTACK the binding row says MISMATCH and the tool row still ALLOWs. That ALLOW is the vulnerable teaching label. It is not proof the approver authorized `executive-restricted`.

Splunk records rows. Splunk does not authenticate the approver, grant the approval, or authorize the tool.

## 17. Splunk role

Splunk remains downstream. A later workshop may let the learner search the simulated packet and, separately, search historical tool events. Searching the packet does not turn it into measured approval.

Historical searches must not treat MCP-004 `resource_not_granted` events as approval evidence. If no approval field exists, the result is NO APPROVAL EVIDENCE.

## 18. Evidence ledger

The ledger is a learner artifact, not a schema. Each row is marked **SIMULATED HITL PACKET** or **HISTORICAL CORPUS**. Historical rows leave approval id, approver authentication, binding, and approval validity as NOT OBSERVED.

Columns:

mode, run, request id, approval id, requesting agent, executing agent, claimed approver, approver authentication status, approval authority status, requested tool, requested resource, approved action reference, submitted action reference, approval decision, approval binding, approved_at, expires_at, approval validity, CTRL-MCP-001 decision, CTRL-MCP-001 reason, execution observed, completion observed, resource impact, evidence source, claim strength.

Current telemetry does not contain the approval columns. The packet may fill them only on simulated rows.

## 19. Learner exercises

Placement candidate: after the A2A workshop and before L8. Do not renumber L0–L10. Do not add the workshop to the Attack Service allowlist.

The learner is not handed a run id. They start from a question: what was proposed, what was approved, what was submitted, and what did the tool PDP do?

Exercises:

1. Discover the simulated packet without a run id, and keep it apart from historical MCP and identity events.
2. Identify the approval request.
3. Identify the approval decision.
4. Record the approved tool, resource, and action reference.
5. Record the submitted tool, resource, and action reference.
6. Decide MATCH or MISMATCH.
7. Check that the submitted time is inside the approval window, and say what an expired window would mean without making expiry the attack.
8. Record the CTRL-MCP-001 decision and reason.
9. Record whether a separate start exists.
10. State what remains NOT PROVEN, including resource impact and approver authority.

One exercise is a learner-written `stats` or `table` over the simulated packet that keeps approved resource and submitted resource in different fields. Path B may hold the finished search. The mission does not print the mode table.

## 20. Failure-state semantics

Use NO APPROVAL EVIDENCE, APPROVER AUTHENTICATION NOT PROVEN, APPROVAL AUTHORITY NOT PROVEN, APPROVAL EXPIRED, APPROVAL BINDING MISMATCH, APPROVAL REPLAY SUSPECTED, INSUFFICIENT EVIDENCE, CORRELATION NOT ESTABLISHED, and RESOURCE IMPACT NOT PROVEN.

Do not say SAFE, TRUSTED, or HUMAN VERIFIED. Do not say the approver authenticated unless the row is explicitly a simulated authentication result, and then limit the claim to that packet.

## 21. Alternative teaching cases

| Case | Teaching value | Fit to current evidence | Cost |
| --- | --- | --- | --- |
| A. Post-approval parameter mutation | Shows an approval bound to one parameter set | Uses existing `lending-basics` and `executive-restricted` ids without claiming MCP-004 is HITL | No runtime change if the packet stays simulated |
| B. Expired approval | Shows that an id is not a current approval | No approval clock exists | Easy to confuse with the later credential-lifetime phase |
| C. Approval replay | Shows one approval used for a second request | No approval id exists to replay | Needs a second request object before the mutation lesson is clear |

## 22. Selected teaching case

Case A is the primary workshop. Expiry fields are present so the learner can see the window still contains the use. Replay is a labeled non-exercise, not the attack. Cases B and C are not built.

## 23. Schema and runtime impact

Runtime HITL required: NO.  
New LIVE attack required: NO.  
Schema change required for the first workshop: NO.  
ExternalEvidence change required: NO.

A future emitter would need new event fields and a decision vocabulary that does not overload CTRL-MCP-001. That work is outside this design’s implementation scope.

## 24. Security and privacy

No password, token, API key, private key, certificate, customer record, employee directory identity, or approval secret is required. `approver-sam` and the `sim-*` references are synthetic. The packet must not log a credential value. Codeguard applies by keeping this design free of credentials, certificates, and new cryptography.

## 25. Framework context

`docs/FRAMEWORK_MAPPING_MODEL.md` allows educational use of NIST AI RMF, NIST SP 800-53 only where verified, and OWASP agentic guidance. `docs/THREAT_MODEL_FRAMEWORK_VALIDATION.md` leaves specific risk identifiers as **NEEDS_EXTERNAL_VALIDATION**. `docs/AGENTSEC_FRAMEWORK_CLAIM_AUDIT.md` does not certify a HITL control.

This design adds no technique id and no compliance claim. Human oversight, approval binding, and action integrity are candidate educational themes only. Validating them against a current external publication is a separate task.

Do not use NIST SP 800-17.

## 26. Future short-lived credential boundary

HITL may show that an approval has `expires_at`. It must not implement credential expiry, rotation, revocation, token refresh, just-in-time issuance, ephemeral secrets, or certificate lifecycle. Those belong to the short-lived credential phase. An expired approval is not an expired credential.

## 27. Future RAG, memory, and supply-chain compatibility

The same binding shape can later carry a purpose, a document id, a memory object id, or an inventory key. Retrieval purpose, memory ownership, AI-BOM, and supply-chain trust are not this workshop. Software-engineering and IT or cloud operations scenarios can reuse approver, action reference, parameter reference, and time without being bank-specific. The example tool names are existing lab fixtures, not a requirement that every later scenario be a lending lookup.

## 28. Claims that must remain NOT PROVEN

1. `approver-sam` is a real human.
2. `approver-sam` authenticated outside the simulated packet.
3. `approver-sam` personally approved the action.
4. `approver-sam` was allowed to approve it.
5. `applicant-web` approved or caused the call.
6. Historical MCP-004 events are human approvals.
7. Historical identity events are human approvals.
8. An approval id proves the approval is current.
9. APPROVE proves CTRL-MCP-001 will ALLOW.
10. Binding MATCH proves CTRL-MCP-001 will ALLOW.
11. Binding MISMATCH proves CTRL-MCP-001 will DENY.
12. CTRL-MCP-001 ALLOW proves execution.
13. `agentsec.mcp.started` proves completion.
14. Execution proves a resource change.
15. BASELINE proves universal safety.
16. RETEST proves universal resistance to mutated approvals.

## 29. Recommended workshop boundary

One REPLAY / STATIC workshop. One simulated packet. One mutation: `lending-basics` approved, `executive-restricted` submitted, except in BASELINE where the submission matches. No runtime approval gate. No schema bump. No new attack. No detector. No change to CTRL-MCP-001.

## 30. Explicit non-goals

Do not implement the workshop from this file. Do not add human authentication, approval enforcement, OAuth, OIDC, JWT validation, PKI, mTLS, SPIFFE, secrets, a LIVE lab, a LIVE attack, an enabled detector, SOAR, short-lived credentials, RAG authorization, memory isolation, AI-BOM, supply-chain controls, RC3, or a change to RC2.

## 31. Final recommendation

The design is coherent enough for a later bounded workshop: the approval lifecycle is explicit, the human is not assumed, authority is separate from authentication, the approval is bound to an action reference, expiry and replay are defined without becoming the attack, and CTRL-MCP-001 remains the tool PDP.

GO — AUTHORIZE BOUNDED HITL APPROVAL WORKSHOP

That recommendation is for an independent design review. It does not implement the workshop.
