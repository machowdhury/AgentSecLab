# Agent identity and non-human IAM — independent design review

**Historical Review Record.** This document records an intermediate AgentSec development/review state prior to the final v1.0.0 release. It is retained for engineering traceability and should not be interpreted as the current product state.

Read-only review. Product code, runtime, schema, ExternalEvidence, detectors, and tags were not modified. This file is the review artifact.

Design under review: `docs/architecture/AGENTSEC_AGENT_IDENTITY_NON_HUMAN_IAM_DESIGN.md` at `ff63f1f77bcc195b5b3c86c4458c3889d0e39fe7`. The prompt's baseline `b566ecd53b2cbfd997b8f441bc960388eddbe854` is the parent of that commit and contains the Detection Engineering workshop. The design text itself is only on `ff63f1f`. `HEAD` and `origin/develop` are `ff63f1f`. `main` and `origin/main` are `e6115b6d1c03a1672b4364e84748c7840671fbfc`. `v1.0.0-rc2` is `bd8c2c02729497018b4e28b582fe6c9a9e052638`. No `v1.0.0-rc3` tag was found. The design file is tracked, committed, and pushed. Untracked `docs/plans/` and the earlier detection-engineering review were left untouched.

Evidence classes: OBSERVED in source, MEASURED in Splunk on 2026-09-29, DOCUMENTED in existing lab text. No new attack was launched.

## What the controls actually do

`evaluate_identity_claim` in `src/agentsec/identity/trust.py` returns `CTRL-IDENTITY-001`, decision `OBSERVE`, reason `identity_claim_is_not_grant`, claim trust `untrusted_claim`. The function ignores profile. It does not validate a credential, authenticate a principal, establish a human, authorize a tool, or mint an overlay. Parse failures become `ERROR`. The module text says this control never authorizes a tool.

A different function, `mint_identity_overlay`, runs only when the profile is `vulnerable` and the request is the closed triple `lookup_customer_tier` / `customer:read` / `cust-001`. The identity pipeline calls that function after a non-ERROR identity decision and passes the overlay into MCP authorization. `authorize_tool` in `src/agentsec/mcp/authorize.py` remains the tool PDP (`CTRL-MCP-001`). If the tool is not in the coded grant and that overlay matches, CTRL-MCP-001 returns `ALLOW` with reason `vulnerable_profile_fail_open:caller_identity_derived_authority`. That is a labeled lab fault on the tool decision. It is not `OBSERVE` being stored as `ALLOW`, and it is not authentication.

No Python source under `src/` implements OAuth, JWT validation, SPIFFE, mTLS, or an authentication provider. `who_authenticated` is set only in `identity_result_to_dict` to the literal `NOT PROVEN / NOT MODELED`, then copied into the launch response allowlist. `limitations.json` for a specimen pack uses the key `authenticated` with the same sentence. A Splunk search for `who_authenticated` returned count 0. It is not indexed authentication evidence.

`agentsec.principal.id` is `RunContext.user_id`. For this lab, that value is the fixture `applicant-web`. `agentsec.principal.type` is the constant `"user"` in `_base_event`, so it is stamped on agent-originated events. The schema enum also allows `agent` and `system`. Those values are not emitted by this path. Changing the constant is not required for a bounded workshop. The workshop must say the constant is a label. HTTP `user_id` is parsed as a label. Authority-like keys, including `authenticated` and `identity_verified`, are rejected on the identity request. That rejection is not an identity provider.

Hop 0 of the identity pipeline sets `gen_ai.agent.id` to the callee, `acme-agent-fulfillment-006`, on the CTRL-IDENTITY-001 event, before any tool start. The caller is a separate field, `agentsec.identity.caller_agent_id`. `agentsec.delegator.agent.id` is set only when `hop.index >= 1`. On the measured MCP decisions, the delegator is `acme-agent-advisor-005` and the agent id is the callee.

## Five lessons

The existing lab text in `learning/level_1/LAB-AGENT-DELEGATION-001/README.md` already states that an identity claim is not authentication, a delegation claim is not authorization, a caller id is not a grant, an agent id string is not cryptographic identity, and OBSERVE is not ALLOW. Those sentences match the code.

The standing ambiguity is `agentsec.principal.type=user` on events whose `gen_ai.agent.id` is an agent. A learner who reads only that field can invent a human. The design tells them not to. The lesson is teachable. The field does not, by itself, prove the distinction.

## Teaching-case identifiers

| Identifier | Source | What was measured or read | What it is not |
|---|---|---|---|
| `applicant-web` | Fixture `PRINCIPAL_ID`, copied to `user_id` and `agentsec.principal.id` | MEASURED on the identity workflow, type `user`. Also MEASURED on 199 runs and 1592 events in this index, not only this workflow. | Not shown to be a human, not authenticated, not the cause of the tool call. |
| `acme-agent-advisor-005` | Fixture caller | MEASURED as `agentsec.identity.caller_agent_id` and, on hop index at least 1, as `agentsec.delegator.agent.id` | Not authenticated. Not proof it sent the request. Not a grant. |
| `acme-agent-fulfillment-006` | Fixture callee; also hop-0 `gen_ai.agent.id` | MEASURED as callee, as `gen_ai.agent.id`, and as the agent on CTRL-MCP-001 and on `mcp.started` | Not authenticated. Presence of the id is not execution. Execution is the start event. |

Human-attribution claims:

| Claim | Result | Missing evidence |
|---|---|---|
| `applicant-web` represents a human | NOT PROVEN | No human record. Type `user` is hardcoded. |
| `applicant-web` was authenticated | NOT MODELED | No credential, token, signature, issuer, or session check. |
| `applicant-web` caused the operation | NOT PROVEN | The label is copied onto the run. Correlation is not causation. |
| Advisor acted on behalf of `applicant-web` | NOT PROVEN | Caller and principal are co-present labels. No authenticated delegation. |
| Advisor was authenticated | NOT MODELED | No credential binding for the agent id. |
| Callee received authenticated delegation | NOT MODELED | Delegator id is attribution for hop index >= 1, which the schema calls deterministic and not A2A. |
| The tool executed under `applicant-web`'s authority | REFUTED as authority, OBSERVED as a label | ATTACK execution follows CTRL-MCP-001 `ALLOW` with the caller-identity fail-open reason. The principal field is still the label. Coded policy does not grant `lookup_customer_tier` to either agent. |

Non-human principal: **CLAIM ONLY**. The repository has agent id strings, caller, callee, and delegator fields. It does not have a non-human principal type in the emitted events, an authenticated agent subject, an owner, or a workload proof. The design headline `PARTIAL` is looser than the code. The design body already says the agent principal role is claim only. A named agent is not a security principal.

## Splunk

MEASURED. Filter `agentsec.lab.id=LAB-AGENT-DELEGATION-001` returned no events. The same activity is indexed with `agentsec.lab.id=agentsec-local` and `agentsec.workflow.entry=/identity/delegate` (13 runs, 124 events).

CTRL-IDENTITY-001 on that workflow: ATTACK 6 runs, RETEST 6 runs, BASELINE 1 run. Every measured identity decision was `OBSERVE` / `identity_claim_is_not_grant`. Caller `acme-agent-advisor-005`, callee `acme-agent-fulfillment-006`, claim trust `untrusted_claim`, principal `applicant-web`, type `user`.

CTRL-MCP-001 on that workflow:

| Mode | Decision | Reason | Tool | Runs | `mcp.started` |
|---|---|---|---|---|---|
| ATTACK | ALLOW | `vulnerable_profile_fail_open:caller_identity_derived_authority` | `lookup_customer_tier` | 6 | 6 runs, agent `acme-agent-fulfillment-006` |
| RETEST | DENY | `tool_not_granted` | `lookup_customer_tier` | 6 | no start row in the start query |
| BASELINE | ALLOW | `tool_granted` | `lookup_policy` | 1 | 1 run, same callee agent |

Example ATTACK run `110dd7a6-58b5-472a-ae80-aec76e11bf4e` has both control ids and `mcp.started`, sequences from 3 through 7. Delegator on those aggregated rows is the advisor id. This review did not re-print every event in order, so it does not claim a specific sequence number for each control.

`who_authenticated` was not found in the index.

This is enough for a REPLAY workshop if the search key is the workflow entry or the caller id. It is not enough if the only key is `LAB-AGENT-DELEGATION-001`. An empty result on that lab id is `NO EVIDENCE FOUND` for that key. It is not proof the behavior did not occur, and it is not `SAFE`.

Roles that telemetry can support:

| Role | Class |
|---|---|
| Claimed user | OBSERVED as `applicant-web` / type `user` |
| Requesting agent | OBSERVED as caller id. Not proof of who sent the bytes. |
| Caller agent | OBSERVED |
| Delegating agent | OBSERVED as `agentsec.delegator.agent.id` on the follow-on hop. Not an authenticated delegation. |
| Receiving agent | OBSERVED as callee id |
| Executing agent | INFERRED if taken from `gen_ai.agent.id` on hop 0. OBSERVED as the agent on `mcp.started` after ALLOW. |
| MCP server | NOT MODELED as an identity. The control id is the decision. |
| Tool | OBSERVED as `gen_ai.tool.name` |
| Downstream resource | Not re-measured as its own field in this pass. The tool name is not the resource. |

## Telemetry and workshop boundary

For teaching claim versus authentication, agent label versus human, requester versus executor, and CTRL-IDENTITY-001 versus CTRL-MCP-001, current telemetry is sufficient when the workflow key above is used. The missing authentication fields are the lesson.

For production identity forensics, telemetry is insufficient. There is no authenticated subject, issuer, session, credential binding, owner, or expiry.

One REPLAY workshop can teach those distinctions and require unsupported attribution to stay `NOT PROVEN`. It must not require real authentication, a schema change, a new attack, or a new LIVE lab. It must not treat hop-0 `gen_ai.agent.id` as execution, and it must not treat `OBSERVE` or the fail-open reason as authentication.

## Placement and later phases

`L7 → Agent Identity & Non-Human IAM Workshop → L8` does not renumber L0–L10. L3 already has LIVE `LAB-AGENT-DELEGATION-001`. This checkpoint would investigate evidence the learner has already produced, after L7 has named actors and before L8 privacy. That order fits. The new page must not be a second LIVE attack.

Later A2A authentication, short-lived credentials, HITL, RAG authorization, memory ownership, and supply-chain ownership can attach to the existing claim, hop, and control split. No dead end was found that would force CTRL-MCP-001 to become an identity provider. `principal.type` is a later migration nuisance because the emitter writes only `user` while the schema allows `agent` and `system`. That does not block this workshop, and this review does not change the schema.

OWASP ASI03 and NIST AI 600-1 appear in existing AgentSec notes. This review did not re-read those publications. Classification: **DOCUMENTED BUT NOT REVALIDATED**. The design already marks new mappings `NEEDS_EXTERNAL_VALIDATION`. No compliance claim follows.

## Findings

No BLOCKER or HIGH findings. The five core distinctions are true of the code. CTRL-MCP-001 remains the tool PDP. The proposed actors exist as fixtures and as indexed claims.

MEDIUM-01. Indexed evidence for this case is not stored under `agentsec.lab.id=LAB-AGENT-DELEGATION-001`. It is stored as lab id `agentsec-local` with workflow entry `/identity/delegate`. The design left that presence `NOT RE-MEASURED`. A workshop search that uses only the curriculum lab id will return no rows. That empty result must not be taught as absence of the case.

LOW-01. The design summary says a non-human principal is `PARTIAL`. Emitted events support `CLAIM ONLY`.

LOW-02. Section 2 calls `gen_ai.agent.id` the executing actor on the hop that emits the event. Hop 0 emits the callee id on CTRL-IDENTITY-001 before `mcp.started`. Execution has to be tied to the start event.

LOW-03. `agentsec.principal.type=user` is on the callee's events, including `mcp.started`. The schema allows other types that this emitter does not write. The workshop should teach the constant. It should not change schema 1.9.0 to do so.

## Verdict

The teaching case is real, and authentication is honestly absent. The design should name the measured Splunk key, and it should not call the hop-0 agent id execution, before a workshop is built from it.

CONDITIONAL GO — DESIGN REMEDIATION REQUIRED

Remediation is limited to the design text: correlation key, hop-0 agent id, and the `CLAIM ONLY` classification. No implementation, no authentication, and no change to CTRL-MCP-001.
