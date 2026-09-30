# Agent-to-agent authentication and delegated authority

**Status:** DESIGN ONLY. This document does not implement a workshop, a control, or a schema change.  
**Baseline:** `6cd51e7ca07441a9fa6ca6d2ebe02161915b92c4`  
**Prior workshop review:** `docs/reviews/AGENTSEC_AGENT_IDENTITY_NON_HUMAN_IAM_WORKSHOP_INDEPENDENT_REVIEW.md`  
**Evidence classes:** OBSERVED in source, MEASURED in that review’s Splunk export, DOCUMENTED here. Nothing in this file is a new live experiment.

This document recommends a later REPLAY workshop. It does not authorize implementation by itself. An independent design review is still required.

## 1. What exists today

The identity path is an in-process, A2A-shaped claim. It is not authenticated agent-to-agent trust.

| Object | Today | Class |
| --- | --- | --- |
| Caller `acme-agent-advisor-005` | Fixture constant. Emitted as `agentsec.identity.caller_agent_id` on the identity control. Schema text says attribution, not authentication, not a grant. | IMPLEMENTED, EMITTED, INDEXED as a claim |
| Callee `acme-agent-fulfillment-006` | Fixture constant. Emitted as `agentsec.identity.callee_agent_id`. Hop 0 sets `gen_ai.agent.id` to this callee before any tool start. | IMPLEMENTED, EMITTED, INDEXED as a claim |
| `agentsec.delegator.agent.id` | Schema: prior in-process agent id when `hop.index >= 1`. Not A2A. MEASURED: present as the advisor id on 59 workflow events and absent on 65, including CTRL-IDENTITY-001 rows. | EMITTED hop attribution. Not delegated authority |
| Principal `applicant-web` | `RunContext.user_id` label. `agentsec.principal.type` is hard-coded `user` even on callee and start events. Schema enum also allows `agent` and `system`. The emitter does not write those values on this path. | EMITTED label. Human identity NOT PROVEN |
| `gen_ai.agent.id` | Agent identifier on the event. On this workflow it is the callee, including on CTRL-IDENTITY-001 and on `agentsec.mcp.started`. | EMITTED identifier. Not an authenticated principal. Not execution by itself |
| CTRL-IDENTITY-001 | `evaluate_identity_claim` returns OBSERVE / `identity_claim_is_not_grant` and ignores profile. Parse failures are ERROR. It does not authenticate and does not authorize a tool. | IMPLEMENTED claim observation |
| CTRL-MCP-001 | The only tool PDP. Vulnerable profile can ALLOW `lookup_customer_tier` / `customer:read` / `cust-001` with reason `vulnerable_profile_fail_open:caller_identity_derived_authority`. That overlay does not mutate coded policy. | IMPLEMENTED tool authorization. The reason is a labeled lab fault, not a delegation proof |
| `/identity/delegate` | Workflow entry. Indexed with `agentsec.lab.id=agentsec-local`. | INDEXED |
| `LAB-AGENT-DELEGATION-001` | Repository and fixture id. A Splunk search for that lab id returned count 0. | DOCUMENTED contract. Not the indexed key |
| `agentsec.delegation.claimed_scope` | Scope the caller claimed. Schema: distinct from allowed scope, never copied into policy. | EMITTED claim. Not a grant |
| `who_authenticated` | Result string `NOT PROVEN / NOT MODELED` in Python. Indexed count 0. | NOT an authentication attribute |
| MCP execution | `event.name=agentsec.mcp.started`. MEASURED: ATTACK 6, BASELINE 1, RETEST 0. Start rows omitted `agentsec.control.id`. | INDEXED execution evidence, bounded to observed start |
| Sequence | MEASURED on the identity workflow: identity observation at sequence 3, tool decision at sequence 6, start at sequence 7 when a start exists. | INDEXED order for that corpus |
| Authenticated agent principal | No issuer, method, audience, result, or credential reference. | NOT MODELED |
| Delegated authority | No delegation id, granted scope, audience, expiry, or delegation decision. Caller and callee ids are not a delegation. | NOT MODELED |
| OAuth, PKI, SPIFFE, JWT, mTLS, API keys, certificates | Not in this path. | NOT MODELED. Out of scope for the first workshop |

MEASURED authorization on the existing corpus, which must not be re-labeled as authentication:

- ATTACK: CTRL-MCP-001 ALLOW, fail-open reason above, 6 runs, with a start
- RETEST: CTRL-MCP-001 DENY `tool_not_granted`, 6 runs, no start
- BASELINE: CTRL-MCP-001 ALLOW `tool_granted` for `lookup_policy`, 1 run, with a start
- CTRL-IDENTITY-001 OBSERVE on all 13 runs

Those counts are previously measured. This remediation does not add a new Splunk export. `who_authenticated` was previously measured at count 0. `LAB-AGENT-DELEGATION-001` was previously measured at count 0 and is not the indexed key. This corpus stays claim-only. It is not authenticated A2A and it is not delegated authority.

`LAB-MCP-006` already teaches a different confused deputy: a deputy spending its own ambient tool grant. This design does not replace that lab.

## 2. Core lesson

Knowing another agent’s name is not authentication, and authenticated identity alone does not grant delegated authority.

The learner must keep these apart:

agent identifier, authenticated agent principal, requesting agent, delegating agent, receiving agent, executing agent, human principal, service or workload principal, tool, resource, authorization decision, delegated authority, and execution.

Preserved boundaries:

- identity claim is not authentication
- authentication is not authorization
- authorization is not execution
- a caller id is not delegated authority
- a delegation is not unlimited authority
- tool access is not resource access
- a Splunk row is not authority

## 3. What would count as authentication

The sentence “Agent A authenticated as Agent A to Agent B” needs evidence that a verifier accepted A as A for an audience that includes B. A caller id is not that evidence.

Minimum conceptual record. These are design candidates, not schema fields and not secrets:

| Candidate | Role |
| --- | --- |
| Authenticated principal id | Who the verifier accepted |
| Principal type | `agent` for this lesson. Not a human |
| Authentication method | A label such as `lab_assertion`. Not an algorithm deployment |
| Issuer | Who stood behind the check. A lab issuer name, not a CA |
| Audience | Who the result was for. Here, the callee |
| Authentication result | `AUTHENTICATED` or `AUTHENTICATION_FAILED` |
| Credential reference | An id or fingerprint. Never the secret |
| Issued-at and expires-at | Time bounds of the authentication result |
| Interaction or session id | Binds this check to one exchange |

The verifier in the first lesson is a lab label inside the teaching packet, not Splunk and not CTRL-MCP-001. Splunk only displays the row.

In the first workshop that row is a **SIMULATED AUTHENTICATION RESULT**. It is educational metadata. It is not evidence that AgentSec currently authenticates anyone. Issuer, audience, credential reference, issued-at, expires-at, and result are names in that packet. The credential reference is an id or a fingerprint. It is never a password, token, key, or certificate.

`AUTHENTICATED` in that packet is not a tool decision. `AUTHENTICATION_FAILED`, or a missing result (`AUTHENTICATION NOT OBSERVED`), is not a tool DENY. A simulated success does not ALLOW a tool.

The first workshop must not store passwords, API keys, bearer tokens, private keys, raw certificates, session secrets, or credential material.

## 4. What would count as delegated authority

“Agent A delegated authority X to Agent B” is not `caller_agent_id=A` and `callee_agent_id=B`.

A delegation is a bounded grant from a delegator to a delegate. First-slice elements:

| Element | First slice | Later |
| --- | --- | --- |
| Delegator | Yes. Agent A, named by a SIMULATED AUTHENTICATION RESULT | Human delegator remains NOT PROVEN |
| Delegate | Yes. Agent B, named by a SIMULATED AUTHENTICATION RESULT | Chains of three or more agents |
| Tool and scope | Yes. One tool | Multiple tools |
| Resource | Yes. One resource id, so tool access is not resource access | Resource classes |
| Audience | Yes. The delegate’s agent id | Broader audiences |
| Delegation id | Yes. A reference, not a secret | Parent delegation id |
| Issued-at and expires-at | Yes. The learner reads them | Short-lived credential workshop owns rotation and replay |
| Delegation decision | Yes. A **SIMULATED DELEGATION DECISION** of `MATCH`, `MISMATCH`, or `ABSENT`. None of those words is a tool ALLOW or DENY | `EXPIRED`, `REVOKED`, `WRONG_AUDIENCE` as their own workshops |
| Purpose, approval, revocation, constraints beyond tool/resource | Named, not the attack | HITL and later phases |

`agentsec.delegation.claimed_scope` stays a claim. A future granted scope needs a different field. Do not reuse the claim field as the grant.

## 5. Chain the learner has to prove

```
applicant-web          label only. Human authentication NOT PROVEN
        |
acme-agent-advisor-005 requesting agent and delegator, named by a SIMULATED AUTHENTICATION RESULT in the teaching packet
        |  delegated authority: one tool, one resource, one audience, one time window
acme-agent-fulfillment-006 delegate and receiving agent
        |
tool and resource      requested values may differ from delegated values
        |
agentsec.mcp.started   execution evidence when present
```

| Link | Proven only when | Otherwise |
| --- | --- | --- |
| Human requested the work | Not in the first slice | NOT PROVEN |
| Advisor is the requester | Caller field on the claim, or the authenticated-principal field on a future authentication result | A name alone is a claim |
| Advisor delegated | A delegation record names the advisor as delegator and states tool, resource, audience, and time | Caller id is not enough |
| Fulfillment received it | Audience equals the fulfillment agent id | Wrong audience is a failed delegation, not a later workshop’s attack |
| Fulfillment executed | `agentsec.mcp.started` | `gen_ai.agent.id` is not that proof |
| The resource changed | A resource outcome event | A tool start does not prove it |

## 6. One teaching case: out-of-scope request versus in-scope request

This case lives only in a **SIMULATED / REPLAY** teaching packet. It is not the historical `/identity/delegate` corpus. It is not runtime authentication, production authentication, production delegation, credential issuance, cryptographic proof, production IAM, measured resource authorization, or measured downstream impact.

The same actors and the same simulated authentication model appear in every mode. The packet labels the advisor and the fulfillment agent with a SIMULATED AUTHENTICATION RESULT of `AUTHENTICATED`. That label is not a tool decision.

The simulated delegation is the same grant in every mode:

- delegated tool `lookup_policy`
- delegated scope `policy:read`
- delegated resource `lending-basics`
- audience `acme-agent-fulfillment-006`

Tool and resource are separate bounds. A grant to invoke `lookup_policy` does not authorize every resource that some other tool can reach. The customer-tier request below is outside both the delegated tool and the delegated resource. Those values come from the existing fixtures as the shape of the packet. Using them here does not create a production resource authorizer.

ATTACK and RETEST use the same out-of-scope request:

- requested tool `lookup_customer_tier`
- requested scope `customer:read`
- requested resource `cust-001`
- SIMULATED DELEGATION DECISION `MISMATCH`

BASELINE does not test `lookup_customer_tier`. It uses the in-scope request:

- requested tool `lookup_policy`
- requested scope `policy:read`
- requested resource `lending-basics`
- SIMULATED DELEGATION DECISION `MATCH`

ATTACK versus RETEST isolates the tool PDP’s response to that same mismatch. BASELINE shows a bounded grant for a different, in-scope request. Do not describe the three modes as one request.

| Mode | Simulated authentication | Requested tool | Requested resource | Delegation decision | CTRL-MCP-001 | Execution |
| --- | --- | --- | --- | --- | --- | --- |
| ATTACK | Both agents `AUTHENTICATED` | `lookup_customer_tier` | `cust-001` | `MISMATCH` | ALLOW only because of the labeled fail-open | A separate `agentsec.mcp.started` row may exist. It is not the ALLOW |
| RETEST | Both agents `AUTHENTICATED` | `lookup_customer_tier` | `cust-001` | `MISMATCH` | DENY | Do not infer a start. None unless a separate start row exists |
| BASELINE | Both agents `AUTHENTICATED` | `lookup_policy` | `lending-basics` | `MATCH` | ALLOW `tool_granted` | A separate start row is the execution evidence. It is not the ALLOW |

`MATCH` is not ALLOW. `MISMATCH` is not DENY. CTRL-MCP-001 remains the tool PDP.

The labeled fault is only the vulnerable teaching profile on the customer-tier call: the delegation row says `MISMATCH` and the tool row still ALLOWs. Candidate reason: `vulnerable_profile_fail_open:authenticated_agents_scope_not_enforced`. That string is an authorization fault. It is not authenticated delegation, not a valid grant, and not production IAM.

Expiry is present so the learner can see that the simulated window still contains the use. The ATTACK and RETEST failure is the out-of-scope tool and resource, not the clock. The later short-lived credential workshop can reuse the time fields.

The identity workshop already showed that a name is not a grant. This case starts from a simulated authentication label, then shows that a grant for one tool and one resource does not cover another tool and another resource. `LAB-MCP-006` remains the ambient-authority deputy.

The historical corpus is a different evidence plane. Those rows have no simulated authentication result and no simulated delegation decision. Do not merge the planes.

## 7. CTRL-IDENTITY-001

CTRL-IDENTITY-001 remains claim observation. OBSERVE is not ALLOW. It does not become the authenticator.

Authenticated identity needs a separate future event. Candidate id: `CTRL-AUTHN-001`, decision `AUTHENTICATED` or `AUTHENTICATION_FAILED`. That control is not a PDP. It must not authorize a tool. It must not return ALLOW or DENY for a tool.

Splunk displaying either control does not authenticate anyone.

## 8. CTRL-MCP-001

CTRL-MCP-001 remains the only tool PDP.

Recommended relationship: a separate delegation decision, then CTRL-MCP-001. The delegation decision is an input the tool PDP may honor. It is not itself permission to run the tool.

| Option | What the learner sees | Cost |
| --- | --- | --- |
| Delegation is only an input buried inside CTRL-MCP-001 | One tool row | The mismatch disappears unless the reason text is perfect |
| Delegation replaces CTRL-MCP-001 | A second PDP | Breaks the current boundary |
| Separate delegation decision, CTRL-MCP-001 still decides the tool | Two rows that can disagree in the vulnerable profile | One more event |

Use the third option. In ATTACK and RETEST the simulated delegation row says `MISMATCH` for the same customer-tier request. ATTACK’s tool row still ALLOWs. RETEST’s tool row DENYs. BASELINE is the other request, `lookup_policy` for `lending-basics`, and the tool row ALLOWs that in-scope call. Agreement on BASELINE is not agreement on the customer-tier call.

Do not implement this split now. Do not change `authorize_tool`.

Conceptual order, each step needing its own row:

identity claim, then a SIMULATED AUTHENTICATION RESULT, then a SIMULATED DELEGATION DECISION, then the CTRL-MCP-001 tool decision, then a possible `agentsec.mcp.started`, then a possible completion, then a possible resource outcome.

Splunk records the rows. Splunk does not authenticate, delegate, or authorize.

## 9. Authorization chain

| Question | Evidence | Does not mean |
| --- | --- | --- |
| Did anyone authenticate? | A row labeled SIMULATED AUTHENTICATION RESULT | A tool was allowed, or that AgentSec authenticates in the current runtime |
| Was authority delegated? | A row labeled SIMULATED DELEGATION DECISION for a tool, a resource, an audience, and a time | `MATCH` means the tool PDP allowed it, or that the tool ran |
| Did the tool PDP allow it? | CTRL-MCP-001 decision and reason | The resource changed, or the caller was a human |
| Did execution start? | `agentsec.mcp.started` | Downstream success |
| Did the resource change? | A resource outcome, if one exists | Safe behavior |

Successful authentication is not safe behavior. A tool start is not proof the downstream resource changed.

## 10. Time

The first slice carries `issued-at`, `not-before`, and `expires-at` on the simulated authentication result and on the simulated delegation. The learner checks that the use sits inside the window. On ATTACK and RETEST the failure is still the out-of-scope tool and resource. On BASELINE the request matches the grant. The clock is not the difference between the modes.

Revocation, replay of a spent delegation, and use after expiry are designed as later attachments. They are not this workshop’s attack. No short-lived credential is issued. No clock is implemented.

A missing time field is `NOT OBSERVED`, not proof the grant lives forever.

## 11. Later human approval

A future approval object can constrain agent, tool, action, resource, parameter fingerprint, purpose, and a time window. The delegation record should be able to carry an optional `approval_ref` without requiring one now.

That leaves room for later tests: approval expiry, approval replay, parameter mutation after approval, and an approval for one tool reused for another. No approval engine is in this design.

## 12. Later retrieval authorization

Keep principal, delegation, purpose, and resource as separate ideas. A later phase can say Agent B may retrieve document X without saying Agent B may use document X for purpose Y. Tool authorization and retrieval authorization stay different decisions. This design does not implement retrieval control.

## 13. Later memory ownership

A later memory object needs owner, writer, reader, tenant, session, and the acting agent. The question “whose memory is this?” is the owner. The question “who authorized this agent to read it?” is a delegation or authorization decision, not the agent id. This design does not implement memory isolation.

## 14. Later inventory correlation

Keep these identifiers stable so a future inventory can join them: agent id, tool name, workflow entry, and lab id. Do not build an AI bill of materials, a package inventory, or a supply-chain platform. An agent id in a runtime event is not an inventory record.

## 15. Telemetry

Required for the first lesson, in a labeled SIMULATED replay packet, not in schema 1.9.0:

1. Authentication result for the advisor and the fulfillment agent, including method label, issuer label, audience, result, reference id, issued-at, and expires-at.
2. Delegation record: id, delegator, delegate, tool, scope, resource, audience, issued-at, expires-at, and decision `MATCH` or `MISMATCH`.
3. CTRL-MCP-001 decision and reason, plus `agentsec.mcp.started` when execution occurs.

Future production telemetry, not this workshop:

- credential fingerprint, rotation, revocation, parent delegation
- session, tenant, owner
- human authentication
- approval reference
- purpose
- resource outcome distinct from tool start
- workload-identity documents

Do not overload these current fields:

| Field | Leave it meaning |
| --- | --- |
| `agentsec.identity.caller_agent_id` and callee | Claim |
| `agentsec.delegator.agent.id` | Prior hop in-process. Not a delegation grant |
| `agentsec.delegation.claimed_scope` | Claimed scope, not granted scope |
| `agentsec.principal.type=user` | Current emitter limitation |
| `gen_ai.agent.id` | Agent id on an event, not authentication and not execution |
| `who_authenticated` | Absent from the index. Not a proof |

A future runtime that emits the new records will need a schema change. The schema is not bumped here. `principal.type` already allows `agent`, but writing `agent` onto today’s identity events would rewrite history. New events only, later.

## 16. Secrets

The lab teaches authentication metadata. It does not capture secrets. Safe evidence is a credential reference, a fingerprint, an issuer name, an audience, a scope, an expiry, and a verification result.

No OAuth provider, OIDC provider, PKI, certificate authority, SPIFFE deployment, vault, or live identity provider. No authentication library. No private key. No certificate. Codeguard applies: this design adds none of those, because the lesson is evidence shape, not credential handling.

## 17. Future REPLAY workshop

Placement: after the identity workshop and before L8. Do not renumber L0–L10.

The learner is not handed a run id. They start from: who claimed to call, who authenticated, who delegated, what was delegated, to whom, for which tool and resource, whether it was still in time, what CTRL-MCP-001 decided, whether execution started, and what is still unproven.

They build a learner ledger. It is not a production schema. Each row is marked either **SIMULATED A2A PACKET** or **HISTORICAL CLAIM-ONLY CORPUS**. A historical row leaves authentication, delegation id, delegated tool, delegated resource, and delegation decision as NOT OBSERVED. It must not inherit those values from the simulated packet.

Ledger concepts:

- mode
- run
- caller claim
- callee claim
- simulated authenticated caller
- simulated authenticated callee
- delegator
- delegate
- delegation id
- delegated tool and scope
- delegated resource
- delegation audience
- delegation validity
- requested tool
- requested resource
- simulated delegation decision
- CTRL-MCP-001 decision
- execution evidence
- resource outcome evidence
- claim strength
- evidence plane

Requested tool and requested resource are both required. Delegated tool and delegated resource are both required on simulated rows. Authorizing a tool does not authorize every resource that tool could reach.

Path A makes them write the comparison. Path B may hold finished searches after that work. The mission does not state the mode table.

The historical `/identity/delegate` corpus stays the claim-only contrast. The new packet is SIMULATED and labeled. Mixing them without that label is a false authentication claim.

## 18. Modes

Use the table in section 6. Do not create the events in this phase.

ATTACK and RETEST are the same customer-tier request, the same `MISMATCH`, and different CTRL-MCP-001 outcomes. BASELINE is not that request. It is the in-scope `lookup_policy` request for `lending-basics`, with `MATCH`, and a separate tool ALLOW. None of the three modes means the human authenticated. None of them is the historical corpus.

## 19. Evidence discipline

| Strength | Use |
| --- | --- |
| MEASURED | The existing identity corpus and the independent review export |
| OBSERVED | Source behavior cited above |
| DOCUMENTED | This design |
| SIMULATED | The future teaching packet, until a runtime emits it |
| REPLAYED | The workshop mode |

An authentication result in the simulated packet supports “the packet says the lab verifier accepted this agent id.” It does not prove a human, a production issuer, a lawful delegation, a business approval, or a resource change. Claim strength for those stays NOT PROVEN or NOT MODELED.

## 20. Framework notes

Existing AgentSec documents allow educational use of NIST AI RMF, NIST SP 800-53 only where verified, MITRE ATLAS only with a verified technique id, and OWASP agentic guidance. The identity design already recorded OWASP ASI03 and NIST AI 600-1 as documented and not re-validated.

This design does not re-check those sources and does not add technique ids. Candidate ideas — non-human identity, agent-to-agent trust, delegation, least privilege, confused deputy, credential lifecycle — are **NEEDS_EXTERNAL_VALIDATION**. No compliance claim. `LAB-MCP-006` is the existing ambient confused-deputy lab. It is not an official framework id.

## 21. Runtime authentication

The first workshop does not need real runtime authentication.

REPLAY of a labeled simulated packet is enough. A live authenticator would add secret handling, a clean-room install burden, and a risk of looking like production IAM, without teaching a sharper distinction than the packet can teach. Offline use stays possible. OAuth and PKI are not required for realism.

## 22. Placement

`L7 → Identity/NHI Workshop → A2A Authentication & Delegation Workshop → L8`

The identity workshop has already separated claim, observation, tool decision, and execution. A2A is the next distinction: authentication, then a bounded delegation. L8 privacy should follow, so data questions sit on top of actor questions. L0–L10 stay as they are. The workshop is a checkpoint, not a new level, and it is not added to the Attack Service allowlist.

## 23. First workshop boundary

**Objective.** Show that a simulated authentication label plus a simulated grant for one tool and one resource do not authorize a different tool and resource, and that a tool allow is still not execution or a resource change.

**Scenario.** The simulated packet labels the advisor and the fulfillment agent as authenticated. The simulated grant is `lookup_policy` / `policy:read` / `lending-basics` for the fulfillment audience. ATTACK and RETEST request `lookup_customer_tier` / `customer:read` / `cust-001` and record `MISMATCH`. They differ at CTRL-MCP-001 only. BASELINE requests `lookup_policy` / `policy:read` / `lending-basics` and records `MATCH`. Contrast that packet with the previously measured claim-only corpus. Do not merge the planes.

**SPL.** Discover the simulated packet without a run id. Keep it apart from `/identity/delegate` history. Separate simulated authentication rows, simulated delegation rows, CTRL-IDENTITY-001 if the claim is also present, CTRL-MCP-001, and `agentsec.mcp.started`. Write one stats query by mode that keeps requested tool and requested resource. Build the ledger.

**Conclusion the learner may write.** In the simulated packet, the authentication label is the same in all three modes. ATTACK and RETEST are outside the grant and differ only in the tool decision. BASELINE is inside the grant and is a different request. A start, where present, is execution evidence only.

**Still not proven.**

1. `applicant-web` is an authenticated human.
2. `applicant-web` caused the tool call.
3. The historical `/identity/delegate` corpus is authenticated A2A.
4. The historical corpus is delegated authority.
5. An agent id proves authenticated identity.
6. Authentication proves delegation.
7. A delegation `MATCH` proves CTRL-MCP-001 will ALLOW.
8. CTRL-MCP-001 ALLOW proves execution.
9. `agentsec.mcp.started` proves successful completion.
10. Tool execution proves a downstream resource change.
11. BASELINE proves universal safety.
12. RETEST proves universal resistance.

## 24. Do not build in the first implementation

Production IAM. An OAuth or OIDC provider. PKI or a certificate authority. A SPIFFE or SPIRE deployment. A vault or secrets manager. An enterprise service mesh. Production workload identity. A live external identity provider. SOAR or containment. An enabled detector. A new scanner or evaluation harness. An AI bill of materials or a supply-chain platform. A human-approval engine. Retrieval authorization. Memory isolation. A certification engine. A schema bump. A change to ExternalEvidence 1.0.0. A new live attack. A change to RC2. An RC3 tag.

## 25. Design answers

1. An agent identity in AgentSec today is an identifier in fixtures and telemetry. It is a claim until a verifier records an authentication result.
2. The change to an authenticated principal is a separate authentication result for that id, with issuer, audience, method, time, and a credential reference. A caller field does not do this.
3. A future lab verifier performs authentication. Not Splunk. Not CTRL-IDENTITY-001. Not CTRL-MCP-001.
4. Delegation is proved by a delegation record with delegator, delegate, tool, scope, resource, audience, time, and a decision. Two agent ids are not that record.
5. What is delegated in the first slice is one tool and one resource, not “the agent’s authority.”
6. The receiver is the audience, the fulfillment agent, not every agent that knows the advisor’s name.
7. Bounds are tool, scope, resource, audience, and the time window.
8. Expiry is an `expires-at` the learner reads. This workshop does not make expiry the failure. A missing expiry is not an immortal grant.
9. CTRL-MCP-001 stays the tool PDP. It may consume the delegation decision. It does not become the authenticator. The delegation decision does not replace it.
10. Execution is `agentsec.mcp.started`.
11. Downstream impact is a resource outcome. A start does not prove it. The first slice leaves impact NOT PROVEN.
12. The twelve sentences in section 23 stay NOT PROVEN. Human identity, production authority, business approval, and resource change are in that list. The historical corpus remains unauthenticated.
13. The three simulated records in section 15, plus the existing claim and tool events as contrast.
14. A future schema change is likely before runtime emission. It is not required for a REPLAY packet that is clearly SIMULATED and is not written through schema 1.9.0.
15. Yes. The first workshop can stay REPLAY-only.
16. Yes, if a later approval reference can attach to the same tool, resource, parameter fingerprint, purpose, and time window.
17. Yes, if issued-at, not-before, and expires-at already exist and expiry is not spent as this workshop’s only attack.
18. Yes, if purpose and resource stay distinct from tool authorization.
19. Yes, if owner and reader stay distinct from the acting agent id.
20. Yes, as correlation keys only. An agent id is not an inventory.

## 26. Recommendation

This file is ready for an independent re-review. It does not authorize implementation. Do not build the workshop from this file.

## 27. Remediation record

Independent review: `docs/reviews/AGENTSEC_A2A_AUTHENTICATION_DELEGATION_DESIGN_INDEPENDENT_REVIEW.md`. Verdict was CONDITIONAL GO. This section records the wording change. It does not change the control split.

| Original statement | Finding | Correction |
| --- | --- | --- |
| “What changes is whether the tool PDP honors the delegation mismatch,” after a table that already gave BASELINE a different tool. Section 23 also said the request under investigation is `lookup_customer_tier` and then said to compare all three modes. | MEDIUM. ATTACK and RETEST share the mismatch. BASELINE is a different in-scope request. The sentence treated all three modes as one mismatch. | Section 6 now says ATTACK and RETEST request `lookup_customer_tier` / `cust-001` with `MISMATCH`, and BASELINE requests `lookup_policy` / `lending-basics` with `MATCH`. Those are not the same request. |
| The mode table named the tool and not the resource. | LOW. Tool scope and resource scope were easy to collapse. | The same table and the learner ledger now carry requested resource and delegated resource. A tool grant is not a grant for every resource. |

No new Splunk export was run for this correction. Historical counts stay previously measured. The simulated packet stays labeled and separate from that corpus.
