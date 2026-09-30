# Agent identity and non-human IAM — design

Design only. This document does not authorize implementation.

Reviewed baseline: `develop` at `b566ecd53b2cbfd997b8f441bc960388eddbe854`, which contains the Detection Engineering workshop. `origin/develop` matches that commit. `main` is `e6115b6d1c03a1672b4364e84748c7840671fbfc`. `v1.0.0-rc2` is `bd8c2c02729497018b4e28b582fe6c9a9e052638`. Schema remains `1.9.0`. ExternalEvidence remains `1.0.0`. CTRL-MCP-001 remains the tool PDP. DET-MCP-001 stays disabled.

Evidence classes below: OBSERVED in source, DOCUMENTED in existing notes, NOT RE-MEASURED for the local Splunk index in this design pass. No new attack was run.

## 1. What this phase is

AgentSec should teach non-human identity before it teaches A2A authentication, human approval, or short-lived credentials.

The lesson is:

- an identity claim is not an authenticated principal
- authentication is not authorization
- an agent identity is not a human identity
- the actor that requests is not always the actor that executes
- a known name is not permission to act

L3 already has a LIVE lab, `LAB-AGENT-DELEGATION-001`, whose control `CTRL-IDENTITY-001` records claims and does not authorize tools. This design does not replace that lab and does not add a second LIVE identity attack.

## 2. What AgentSec models today

OBSERVED in `src/agentsec/events.py`, `src/agentsec/identity/`, and `src/agentsec/request_contract.py`.

| Idea | What the code does | What it does not do |
|---|---|---|
| Identity claim | Closed A2A-shaped body: `principal`, `caller_agent`, `callee_agent`, requested tool/scope/resource, `delegation_claim`. Trust label `untrusted_claim`. | Verify the name. |
| Authenticated identity | Result field `who_authenticated` is the literal `NOT PROVEN / NOT MODELED`. It is not an OpenTelemetry attribute. | Passwords, OAuth, OIDC, SAML, JWT checks, mTLS, PKI, SPIFFE, cloud IAM. |
| Principal | `agentsec.principal.id` is `RunContext.user_id`. `agentsec.principal.type` is hardcoded `"user"` on every base event. HTTP `user_id` is a label (`applicant-web` by default), not a login. | `principal.authenticated`, issuer, session, owner. |
| Executing actor | `gen_ai.agent.id` on the hop that emits the event. Callee follow-on uses `acme-agent-fulfillment-006`. | Prove a workload identity. |
| Requesting actor | On the identity control event: `agentsec.identity.caller_agent_id` (`acme-agent-advisor-005`). | Prove the caller sent the bytes. |
| Delegated actor | `agentsec.delegator.agent.id` only when `hop.index >= 1`. Claimed scope may be `agentsec.delegation.claimed_scope`. | A validated, attenuated, expiring grant. |
| Human user | Principal type string `"user"`. | A human action, an employee, or a customer authentication. |
| Agent | Coded ids and display names for caller and callee. | An agent registry or Agent Card. |
| Service | `service.name` is the lab service label. | A service account. |
| Tool | `gen_ai.tool.name` and CTRL-MCP-001. | An identity for the tool. |
| Workload | Not emitted. | SPIFFE ID or SVID. |
| Downstream resource | Requested resource id on the MCP call, such as a policy or customer id. | A resource owner. |

`CTRL-IDENTITY-001` returns `OBSERVE` / `identity_claim_is_not_grant` for a well-formed claim, or `ERROR` for a bad claim. The module states that this control never authorizes a tool. A vulnerable-profile overlay, `vulnerable_profile_fail_open:caller_identity_derived_authority`, can be consumed only by CTRL-MCP-001 inside one run. `coded_policy()` is not mutated. Identity OBSERVE is not that overlay.

`user_id` on `POST /process` is parsed as a label. Authority-like keys such as `authenticated`, `identity_verified`, and token fields are rejected on the identity request. That rejection is schema hygiene, not an identity provider.

DOCUMENTED limitation in the identity pipeline: schema 1.9.0 has no `session.id`, `tenant.id`, `gen_ai.tool.call.id`, or token fields. This design does not add them.

`docs/learning-notes/agent-identity-delegation-101.md` still says the runtime is absent. That note is stale. The pipeline and L3 lab exist. Do not treat that note as current behavior.

## 3. Conceptual model

No new authenticator. Names below are teaching roles, not schema fields.

| Kind | Can be requester | Principal | Delegate | Executor | Resource | Policy subject | Evidence source |
|---|---|---|---|---|---|---|---|
| Human | Yes, as a claim | Only if a later phase authenticates one | No in this phase | No | As a data subject, later | Later | Not today |
| Agent | Yes | Claim only | Claim only | Yes, as `gen_ai.agent.id` | No | The coded MCP policy names an agent id | The event names the agent id |
| Service | The lab process emits `service.name` | No | No | The process runs the pipeline | No | No | `service.name` is a label |
| Tool | No | No | No | The handler runs after CTRL-MCP-001 ALLOW | No | Tool name is an authorization input | `gen_ai.tool.name`, `mcp.started` |
| Workload | Not modeled | Not modeled | Not modeled | Not modeled | No | No | Not observed |
| Orchestrator | The pipeline orders hops | No | No | It invokes the next hop | No | No | `agentsec.hop.index` |
| Model | Not an actor in this lab (`llm_call_count` 0 on the identity slice) | No | No | No | No | No | Absence is not proof no model ran elsewhere |
| MCP server | No | No | No | It applies coded policy and calls the handler | No | Server-owned allowlist | Control decision |
| Downstream system | No | No | No | Handler outcome after ALLOW | Yes | Resource id is an input | Tool result metadata, not a full payload proof |

Relationships the workshop may draw:

```text
claimed principal (label)
    |
    +-- is not --> authenticated principal
    |
requesting agent (caller id)
    |
    +-- is not --> executing agent (callee id / gen_ai.agent.id)
    |
CTRL-IDENTITY-001 OBSERVE
    |
    +-- is not --> CTRL-MCP-001 ALLOW or DENY
    |
known agent id
    |
    +-- is not --> permitted tool
```

## 4. Lifecycle honesty

| Stage | Status in AgentSec today |
|---|---|
| CREATE | NOT MODELED. Ids are constants in fixtures. |
| ESTABLISH | PARTIAL. A run copies `user_id` onto `agentsec.principal.id` and sets type `user`. That establishes a label, not a principal. |
| AUTHENTICATE | NOT MODELED. |
| AUTHORIZE | MODELED for tools by CTRL-MCP-001. Not modeled as identity verification. |
| USE | MODELED as MCP start after ALLOW, on labs that execute a tool. |
| ROTATE | NOT MODELED. |
| EXPIRE | NOT MODELED. |
| REVOKE | NOT MODELED. |
| AUDIT | PARTIAL. Events can be reconstructed. They do not prove who authenticated. |
| DELETE | NOT MODELED for identities. |

## 5. Trust chain to ask, not to build

```text
Human label
  -> Agent (caller)
    -> Orchestrator (pipeline hop)
      -> MCP / tool
        -> Downstream resource
```

At each hop the learner records:

| Question | Honest answer from current evidence |
|---|---|
| Who is requesting? | Caller agent id on the identity control event, if that event is present. |
| How was identity established? | A string was accepted by the closed parser. |
| Who authenticated it? | NOT PROVEN / NOT MODELED. |
| What principal is represented? | `agentsec.principal.id` plus type `user`. That is a label. |
| What authority is requested? | Requested tool, scope, resource, and claimed scope. |
| Who authorizes it? | CTRL-MCP-001. CTRL-IDENTITY-001 does not. |
| What executes? | `gen_ai.agent.id` on the follow-on hop, then the tool handler only after ALLOW. |
| What evidence proves each statement? | The event fields above, or an explicit gap. |

There is no reverse path from Splunk to CTRL-MCP-001.

Future flow, not current behavior:

```text
identity claim
  -> identity verification     NOT MODELED
  -> principal                 LABEL ONLY
  -> authorization request
  -> CTRL-MCP-001
  -> ALLOW / DENY
  -> execution
  -> telemetry
```

## 6. Human versus agent

Teach these as separate sentences:

- a human-initiated request would require evidence that a person authenticated and caused this run
- an agent-initiated request is what the caller id claims
- an agent acting for a human is a claim until both the human authentication and the delegation are evidenced
- an agent acting from its own coded policy is still not a human action
- a service acting for an agent is the lab process, not a service account
- a tool executing for a service is the handler after CTRL-MCP-001

`USER CONTEXT != PROOF OF USER ACTION`

`AGENT CLAIMS USER X != USER X AUTHENTICATED THE ACTION`

`applicant-web` must not be narrated as an employee or a customer who logged in. `agentsec.principal.type=user` is a constant, so it cannot by itself separate humans from agents.

## 7. Principal candidates, not schema fields

Do not add these to schema 1.9.0.

| Candidate | Needed later | Usable now without a schema change |
|---|---|---|
| `principal.id` | Yes | Reuse `agentsec.principal.id`. Teach it as a label. |
| `principal.type` | Yes | Reuse `agentsec.principal.type`. Teach that `"user"` is hardcoded. |
| `principal.authenticated` | Yes | Absent. The gap is the lesson. |
| `principal.issuer` | Yes | Absent. |
| `principal.session` | Yes | Absent. Correlate with `agentsec.run.id` and say a run id is not a session. |
| `principal.scope` | Yes | Do not invent it. Use requested scope versus coded allowed scope already on MCP decisions. |
| `principal.owner` | Yes | Absent. |

The first workshop must reuse `agentsec.principal.id`, `agentsec.principal.type`, `gen_ai.agent.id`, `agentsec.identity.caller_agent_id`, `agentsec.identity.callee_agent_id`, `agentsec.identity.claim.trust`, `agentsec.delegator.agent.id`, `agentsec.delegation.claimed_scope`, `agentsec.control.id`, `agentsec.control.decision`, and `agentsec.run.id`.

## 8. Risks

| Risk | Class |
|---|---|
| Shared identity: many events carry the same `applicant-web` label and type `user` | DEMONSTRATED as labeling. Not proof of a shared production account. |
| Caller id treated as authority in the vulnerable overlay | DEMONSTRATED only inside that lab profile, as `caller_identity_derived_authority`. |
| Confused deputy: a deputy spends its own ambient tool grant | DEMONSTRATED in LAB-MCP-006, a different lab. Not this workshop's attack. |
| Principal substitution inside the closed identity parser | The parser rejects an unknown principal string. A successful substitution of an authenticated user is NOT MODELED. |
| Identity spoofing of a real employee | POSSIBLE in enterprise settings. NOT MODELED here. |
| Long-lived credentials, reuse, leakage, stale credentials | NOT MODELED. No credential is issued. |
| Over-privileged agent | The coded identity-lab agents are granted `lookup_policy` only. Over-privilege is not the identity-lab result unless a separate lab's policy says so. Do not generalize. |
| Orphaned or unowned non-human identity | NOT MODELED. Fixtures have no owner and no expiry, which is an absence, not an observed orphan incident. |
| Human-to-agent attribution ambiguity | DEMONSTRATED by the user label on agent hops without an authentication event. |
| Agent-to-tool attribution ambiguity | PARTIAL. Tool start events carry `gen_ai.agent.id` and do not carry `agentsec.control.id`. That was already taught. It does not identify a human. |

## 9. Evidence the investigation may use

Do not log secrets, tokens, or raw credentials. A later fingerprint, if any, must be a hash the lab already computes for a request, not a secret.

| Question | Field or gap |
|---|---|
| Claimed identity | `agentsec.principal.id`, caller id, callee id, claim trust |
| Authenticated principal | No event. Result text says not modeled. |
| Issuer | NOT OBSERVED |
| Authentication method | NOT OBSERVED |
| Session | NOT OBSERVED. `agentsec.run.id` correlates a run only. |
| Requesting actor | `agentsec.identity.caller_agent_id` |
| Executing actor | `gen_ai.agent.id` on the follow-on hop; tool name on `mcp.started` |
| Delegated actor | `agentsec.delegator.agent.id` when hop index is at least 1 |
| Resource | Requested resource on the MCP decision |
| Authorization | `agentsec.control.id=CTRL-MCP-001` and its decision |
| Claim classification | `agentsec.control.id=CTRL-IDENTITY-001` and `OBSERVE` |
| Time order | `agentsec.sequence` |
| Credential id | NOT MODELED. Do not add one in this workshop. |

Indexed presence of a historical identity run in the local Splunk index was NOT RE-MEASURED in this design pass. The workshop must allow `NOT OBSERVED` when a field or run is missing. Absence is not "no identity attack" and not "safe."

## 10. Workshop shape

One REPLAY checkpoint. No LIVE launcher. No new attack. No detector. No edit to `savedsearches.conf`. No schema bump.

Working name: Agent Identity and Non-Human IAM. Lab id, if implementation is later authorized: `LAB-AGENT-IDENTITY-NHI`. View name is an implementation choice. Do not create it in this phase.

Path A does not start from a run id and does not hand the ledger answers. Path B may cite previously measured `LAB-AGENT-DELEGATION-001` specimens after the learner has written the ledger.

The learner fills one ledger row:

| Column | Meaning |
|---|---|
| Claim | The sentence under test |
| Claimed actor | The string |
| Authenticated principal | What evidence of authentication exists |
| Executing actor | Agent id and tool, if a start exists |
| Evidence | Field, control id, sequence |
| Evidence state | OBSERVED CLAIM, NOT OBSERVED, NOT PROVEN, CORRELATION NOT ESTABLISHED |
| Correlation | `agentsec.run.id` plus actor ids. A run id alone is not attribution. |
| Alternative explanation | The label was copied from `user_id` |
| Missing evidence | Authentication, issuer, session, owner, expiry |
| Confidence | Claim strength, not a probability product |

Example, to be derived by the learner from fields, not memorized as a verdict:

- "`acme-agent-advisor-005` is named as caller on a CTRL-IDENTITY-001 event" can be an OBSERVED CLAIM when that field is present.
- "`applicant-web` authenticated and caused the tool call" stays NOT PROVEN.
- "CTRL-IDENTITY-001 OBSERVE authorized the tool" is a false reading. OBSERVE is not ALLOW.

Failure language stays: NO EVIDENCE FOUND, CORRELATION NOT ESTABLISHED, INSUFFICIENT EVIDENCE, NO MATCH, NOT OBSERVED, NOT PROVEN. Not SAFE, SECURE, PROTECTED, or NO ATTACK.

## 11. The one teaching case

Use the existing identity lab, not a new attack.

**Case:** claimed user principal versus unauthenticated agent execution.

Actors already coded:

- principal label `applicant-web`, type string `user`
- caller `acme-agent-advisor-005`
- callee `acme-agent-fulfillment-006`
- claim trust `untrusted_claim`
- CTRL-IDENTITY-001 `OBSERVE` / `identity_claim_is_not_grant`
- CTRL-MCP-001 as the separate tool decision
- `who_authenticated` documented as not modeled

What the learner should be able to say:

The lab recorded a user-shaped label and two agent ids. It did not record an authenticated human. A caller id is not a grant. If the vulnerable profile's overlay is present, that overlay is a labeled lab fault consumed by CTRL-MCP-001. It is not evidence that authentication succeeded.

Do not teach, in this first workshop, a second implemented case for spoofing, stale credentials, orphaned non-human identities, or principal substitution. Those remain future or already live in other labs (confused deputy is LAB-MCP-006).

## 12. Later phases, not this one

Mark only:

- SHORT-LIVED CREDENTIALS — FUTURE PHASE. Later teaching may cover issuance, scope, audience, TTL, expiry, rotation, revocation, and replay resistance. No cryptography now.
- A2A AUTHENTICATION & DELEGATION — FUTURE PHASE. Later evidence should separate delegator, delegate, principal, requested scope, granted scope, resource, expiry, and execution. The current hop fields are the hooks. They are not that phase.
- HITL APPROVAL — FUTURE PHASE. Later questions: who requested, who approved, the exact action and parameters, when, for how long, whether the approval was replayed, whether parameters changed, and whether the same principal executed. No approval object now.
- RAG authorization stays future. An authenticated principal would still not mean "allowed to retrieve this data for this purpose." Retrieval eligibility, purpose, tool authorization, and downstream authorization stay separate. CTRL-RAG-CONTEXT-001 remains OBSERVE of context, not a grant.
- Memory ownership stays future. Later questions: owner, writer, reader, recalling agent, tenant or user context, expiry, cross-agent reuse, deletion. `memory.writer.agent.id` is a writer label where that lab emits it. It is not an owner.
- AI-BOM / SUPPLY CHAIN — FUTURE PHASE. A later asset may point at an owner, a workload identity, a model, tools, dependencies, and permissions. No custom AI-BOM. An external inventory artifact, if imported later, stays non-authoritative evidence.

Explicitly out of this design's implementation scope: OAuth, OIDC, SAML, PKI, mTLS, JWT validation, SPIFFE/SPIRE, Vault, cloud IAM, Kubernetes service accounts, production secrets, certificates, credential brokers, PAM, HITL, A2A authentication, short-lived credentials, RAG authorization, memory isolation, AI-BOM, and supply-chain controls.

## 13. Enterprise transfer

The same distinctions move without a second scenario.

Banking. The question is which non-human actor touched customer data, and whether a customer or employee actually authenticated. A agent id on a lookup is not customer consent and not employee action.

Software engineering. The question is which agent or automation may change a repository, a pipeline, a package, or a deployment. A bot name in a log is not a bound workload identity and not a release approval.

Cloud operations. The question is which workload may call a cloud API and how large the blast radius is. A shared lab label is the teaching analogue of a shared cloud principal. AgentSec does not call a cloud API.

What transfers from ordinary IAM: service accounts, workload identity, least privilege, authentication separate from authorization, credential lifetime, and audit logs. What is specific to agents: the same run can carry a human-shaped label, a caller agent, a callee agent, and a tool, and a model or a document can suggest an identity that the server never checked.

## 14. Framework context

Educational only. Not a compliance claim.

Existing AgentSec notes cite OWASP ASI03 for identity and privilege abuse, and they cite NIST AI 600-1 as a related risk profile rather than a technique map. This design does not re-verify those documents. Any new mapping is **NEEDS_EXTERNAL_VALIDATION**.

Useful classroom parallels, without new identifiers: a service account is not a person; a workload identity is not an application role; zero trust refuses to treat a name as a grant; RBAC and ABAC bind a principal to an action and a resource after authentication. AgentSec's CTRL-MCP-001 is the lab's tool binding. It is not an enterprise IAM product.

## 15. Placement

Do not renumber L0–L10.

L3 already teaches "an identity claim is not authentication" with LIVE `LAB-AGENT-DELEGATION-001`. Detection Engineering sits between L6 and L7 and stays there.

Recommend one new REPLAY checkpoint:

`L7 → Agent Identity & Non-Human IAM Workshop → L8`

L7 already asks the learner to name actors, boundaries, and authority. The workshop then forces an evidence ledger: which of those actors are claims, which executed, and which authentications are missing. L8 privacy should not start until the learner can avoid treating a data subject as the actor who authenticated. Placing the workshop before L7 would stack a second checkpoint on the detection-engineering boundary and would ask for an identity ledger before the architecture level has named the actors.

## 16. Learners and audiences

Beginner. Claim versus authenticated identity. Identity versus authorization. Human label versus agent versus service name.

Practitioner. Fill the ledger: requesting actor, executing actor, principal label, CTRL-IDENTITY-001, CTRL-MCP-001, and missing evidence. Compare ATTACK, RETEST, and BASELINE only when those modes exist for the reused lab. Do not invent a mode result.

Expert. Say what a non-human lifecycle would need later, what must stay least privilege, and what residual risk remains because authentication, expiry, and ownership are absent. Propose no implementation.

Engineering output. Name the missing checks and the fields that are labels.

SOC output. State attribution limits and evidence states. A name in a log is not an incident owner.

IAM architecture output. Separate principal, authentication, authorization, and delegation. Mark every unbuilt stage NOT MODELED.

Leadership output. Bounded risk: the lab can show an agent id and a user-shaped label; it cannot say which person caused the action. Do not convert that gap into "no misuse" or into a customer-impact claim.

## 17. Decision

The identity foundation is strong enough to teach, because the runtime already separates an untrusted claim from tool authorization and already refuses to claim authentication.

It is not strong enough to pretend non-human IAM exists. The workshop's job is the gap.

GO — AUTHORIZE BOUNDED IDENTITY & NON-HUMAN IAM WORKSHOP

That authorization is not granted by this file. Implementation waits for an independent design review and a later prompt. The workshop, if built, stays REPLAY, reuses `LAB-AGENT-DELEGATION-001` evidence, adds no authentication, and does not change CTRL-MCP-001, schema 1.9.0, or ExternalEvidence 1.0.0.
