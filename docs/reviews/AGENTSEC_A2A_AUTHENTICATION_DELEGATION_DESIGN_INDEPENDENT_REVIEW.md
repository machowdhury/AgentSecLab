# A2A authentication and delegated authority — independent design review

**Role:** review only. No workshop, runtime, schema, detector, or attack was added.  
**Product baseline:** `6cd51e7ca07441a9fa6ca6d2ebe02161915b92c4`  
**Design reviewed:** `docs/architecture/AGENTSEC_A2A_AUTHENTICATION_DELEGATION_DESIGN.md`  
**That design file is untracked.** It is not in the baseline commit. `HEAD` and `origin/develop` are the baseline. `main` is `e6115b6d1c03a1672b4364e84748c7840671fbfc`. Peeled `v1.0.0-rc2` is `1be214b92f840f843aaf27fb2b9536f764dd7126`. No RC3 tag.

This review did not obtain a new Splunk export. The export command did not run. Corpus figures below are the MEASURED results already recorded in `docs/reviews/AGENTSEC_AGENT_IDENTITY_NON_HUMAN_IAM_WORKSHOP_INDEPENDENT_REVIEW.md` at this same commit. Source was checked again in this review. Those figures are not a new measurement.

## What the repository proves

| Item | Classification |
| --- | --- |
| `acme-agent-advisor-005` | IMPLEMENTED fixture. EMITTED as `agentsec.identity.caller_agent_id`. A claim. Not authenticated. |
| `acme-agent-fulfillment-006` | IMPLEMENTED fixture. EMITTED as the callee and as `gen_ai.agent.id` on hop 0, before tool start. A claim. Not authenticated. |
| `applicant-web` | EMITTED `agentsec.principal.id` from `RunContext.user_id`. Human identity NOT PROVEN. |
| `agentsec.principal.type` | EMITTED as the literal `user` in `_base_event`, including callee events. Schema also allows `agent` and `system`. The emitter does not write those on this path. |
| `gen_ai.agent.id` | EMITTED agent id. Not authentication. Not execution by itself. |
| `agentsec.delegator.agent.id` | Schema text: prior in-process hop when `hop.index >= 1`, not A2A. Prior MEASURED export: advisor id on 59 workflow events, absent on 65, including CTRL-IDENTITY-001. Not a delegation grant. |
| `agentsec.delegation.claimed_scope` | IMPLEMENTED claim field. Schema: not copied into policy. Not a granted scope. |
| CTRL-IDENTITY-001 | IMPLEMENTED. `evaluate_identity_claim` returns OBSERVE / `identity_claim_is_not_grant` and ignores profile. It does not authenticate or authorize. |
| CTRL-MCP-001 | IMPLEMENTED tool PDP. Vulnerable overlay can ALLOW the closed customer-tier triple with `vulnerable_profile_fail_open:caller_identity_derived_authority`. That is a labeled lab fault. |
| `agentsec.mcp.started` | INDEXED execution start when present. Prior measurement: ATTACK 6, BASELINE 1, RETEST 0. Those rows had no `agentsec.control.id`. |
| `/identity/delegate` | INDEXED workflow. Indexed lab id on those rows was `agentsec-local`. |
| `LAB-AGENT-DELEGATION-001` | DOCUMENTED fixture id. Prior search count 0. Not the indexed key. |
| `who_authenticated` | Python result string only. Prior field search count 0. NOT MODELED as telemetry. |
| Authenticated agent principal | NOT MODELED |
| Delegated authority | NOT MODELED |

Caller and callee identifiers are not authenticated identities and not delegated authority. The design says that. The source agrees.

Prior MEASURED mode results, not re-exported here: CTRL-IDENTITY-001 OBSERVE on ATTACK 6, RETEST 6, and BASELINE 1. CTRL-MCP-001 ATTACK ALLOW fail-open 6, RETEST DENY `tool_not_granted` 6, BASELINE ALLOW `tool_granted` 1 for `lookup_policy`. Sequence on that corpus was identity at 3, tool decision at 6, start at 7 when a start existed. Authentication was not in those rows.

## Semantics

The design keeps claim, authentication, delegation, tool authorization, and execution as different records. It forbids treating a Splunk row as authority. It forbids overloading `agentsec.delegator.agent.id`, `agentsec.delegation.claimed_scope`, and `who_authenticated`. Those choices match the schema text and the emitter.

One sentence does not match the mode table. Section 6 says: “What changes is whether the tool PDP honors the delegation mismatch.” That describes ATTACK versus RETEST. BASELINE is a different request, `lookup_policy`, whose delegation decision is MATCH. Authentication is the same. The requested tool and resource are not.

Section 23 says the request under investigation is `lookup_customer_tier` and then says to compare all three modes. A reader can think BASELINE is also a customer-tier call. The table says it is not. The sentence after the table should not say the only change is the PDP’s treatment of one mismatch.

Smallest correction, not applied here: say ATTACK and RETEST share the customer-tier tool, scope, and resource, and differ only in whether CTRL-MCP-001 honors MISMATCH. Say BASELINE is a different request for `lookup_policy` and the policy resource, where the delegation MATCHES. Do not call BASELINE the same mismatch.

The fixtures already split those requests. `adversarial_a2a_payload` is the customer-tier triple for ATTACK and RETEST. `baseline_a2a_payload` is the policy triple. The design’s table matches that split. The following sentence does not.

## Authentication and delegation proposals

The authentication record is enough for a bounded lesson: principal id, type `agent`, a method label, a lab issuer name, audience, result, a reference id, and time. `lab_assertion` does not claim cryptography. The reference is an id, not a secret, if implementers obey the design. Issuer means the lab verifier, not a certificate authority. Audience means who the result is for, the callee in this lesson. `applicant-web` stays unauthenticated. The result is not a tool ALLOW. A separate `CTRL-AUTHN-001` is clearer than stretching CTRL-IDENTITY-001. CTRL-IDENTITY-001 should appear in the packet only as the original claim observation.

The delegation record can teach who delegated, what tool and resource, to whom, and for what window. Claimed scope stays a claim. The decision MATCH or MISMATCH is not CTRL-MCP-001. The design keeps that split, including the useful ATTACK case where the delegation row says MISMATCH and the tool row still ALLOWs.

The mode table omits resource. The customer-tier request and the policy request use different resources in the fixtures. The ledger should show both, or the lesson “tool access is not resource access” stays a slogan. That is smaller than the mode-sentence error. Put resource on the comparison row in the same correction.

## Controls and execution

CTRL-IDENTITY-001 does not authenticate. OBSERVE does not mean authenticated or authorized. The first packet should use it only for the claim. The simulated authentication event should be separate. The design says this. It is sound.

CTRL-MCP-001 remains the tool PDP in the design. Delegation should be a separate decision that CTRL-MCP-001 may consume. Burying it only inside the tool reason hides the mismatch. Replacing CTRL-MCP-001 would break the current boundary. The design picks the separate decision. That is the right tradeoff, and it is not implemented.

An authentication result is not CTRL-MCP-001 ALLOW. A delegation MATCH is not CTRL-MCP-001 ALLOW. The vulnerable profile is the case where they disagree.

`agentsec.mcp.started` is execution evidence only. The design does not treat it as completion, resource change, human cause, or a valid delegation. Downstream impact stays NOT PROVEN. That is correct.

## Time, secrets, and replay

`issued-at`, `not-before`, and `expires-at` are enough for the first lesson because expiry is not the attack. The design does not claim rotation, revocation, replay prevention, short-lived credentials, or session invalidation. Those stay later.

No password, API key, token, JWT, private key, certificate, or session secret is required. Fingerprint, issuer, audience, scope, result, and timestamps are safe if the reference never holds the secret. The design says that. An implementer who puts a bearer token in the reference field would violate the design. The text already forbids it.

REPLAY of a labeled SIMULATED packet is enough. The index has no authentication result to replay as if it were real. A live verifier would add secret-handling and install cost without a sharper lesson. The historical corpus must stay the claim-only contrast.

## Later phases and telemetry

The same delegation shape can later carry an approval reference, a parameter fingerprint, a purpose, and a time window, which is what HITL tests for expiry, replay, mutation, and tool substitution need. It is not an approval engine.

The time and audience fields are a clean place for a later credential workshop to attach issuance, expiry, rotation, revocation, and replay. This design does not issue a credential.

Retrieval versus use-for-purpose stays open because purpose and resource are not collapsed into tool authorization. Memory owner, reader, and tenant are not the acting agent id. Agent id, tool name, and workflow entry can later join imported inventory. None of that is built here.

The simulated packet’s three records are the minimum: authentication, delegation, and the tool decision, plus a start only where the case executes. New runtime fields would need a later schema change. The first workshop does not need one if the packet stays labeled SIMULATED and is not written through schema 1.9.0. Do not write `principal.type=agent` onto the existing identity events.

Framework mentions are **NEEDS_EXTERNAL_VALIDATION**. No technique id is asserted. No compliance claim. `LAB-MCP-006` is correctly left as a different lab.

Placement `L7 → Identity/NHI Workshop → A2A workshop → L8` follows the claim lesson with authentication and delegation before privacy. L0–L10 stay put. The workshop is a checkpoint, not a live attack.

## Claims that stay unproven

- `applicant-web` is an authenticated human or caused the call.
- Historical `/identity/delegate` events are authenticated A2A or a real delegation.
- `gen_ai.agent.id` proves the executing principal.
- Authentication proves a delegation.
- A delegation MATCH proves the tool was authorized.
- A tool decision proves execution.
- A tool start proves a resource change.
- One RETEST deny proves the lab is resistant in general.
- The simulated issuer is a production authority.

## Verdict

The architecture is bounded and the control split is sound. Implementation should wait for one design correction: ATTACK and RETEST share the out-of-scope customer-tier request; BASELINE is a different in-scope policy request; the sentence that says only the PDP’s treatment of the mismatch changes is too broad. Resource belongs on that same comparison. This review does not edit the design.

CONDITIONAL GO — A2A DESIGN REMEDIATION REQUIRED
