# A2A authentication and delegated authority — independent design re-review

**Date:** 2026-09-30
**Role:** review only. This file is the review artifact. It does not implement a workshop, a control, a schema change, or a runtime change.
**Reviewed commit:** `7335a540d2259e191fc477b6644e19f578402add`
**Remediation range:** `1de4f6e6045beb59a18e5dc9ca3951d45b4a4d67` .. `7335a540d2259e191fc477b6644e19f578402add`
**Original review:** `docs/reviews/AGENTSEC_A2A_AUTHENTICATION_DELEGATION_DESIGN_INDEPENDENT_REVIEW.md`
**Design:** `docs/architecture/AGENTSEC_A2A_AUTHENTICATION_DELEGATION_DESIGN.md`
**Remediation report:** `docs/reviews/AGENTSEC_A2A_AUTHENTICATION_DELEGATION_DESIGN_REMEDIATION.md`

Evidence classes: OBSERVED in source, DOCUMENTED in the design, previously MEASURED where a prior export is cited. This re-review did not run a new Splunk export and did not re-run the offline suite. The remediation report’s `1042 passed, 3 deselected` figure is DOCUMENTED from that report. It is not proof of authentication or delegation.

## 1. Repository state

Measured at the start of this re-review:

| Ref | SHA | Result |
| --- | --- | --- |
| `HEAD` | `7335a540d2259e191fc477b6644e19f578402add` | Matches the named remediation commit |
| `develop` | same | Current branch |
| `origin/develop` | same | In sync |
| `main` and `origin/main` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | Unchanged |
| `v1.0.0-rc2^{}` | `1be214b92f840f843aaf27fb2b9536f764dd7126` | Unchanged. Ancestor of HEAD |
| Tags | `v1.0.0-rc1`, `v1.0.0-rc2` | No RC3 |

The remediation commit changes two files: the design and the remediation report. The parent commit tracks the original independent review. No application, schema, ExternalEvidence, detector, or attack file is in `6cd51e7..7335a54`.

Working tree: clean for tracked files. Untracked and unrelated to this remediation: `docs/plans/`, the identity design review, the identity design re-review, the identity workshop review, and the detection-engineering workshop review. Those are not A2A failures.

Repository integrity: PASS. Remote sync: PASS. Design, original review, and remediation report: TRACKED. This re-review file is new.

The remediation report says the ending hash is in the completion message rather than inside the file. This review checked `git rev-parse` and records `7335a540d2259e191fc477b6644e19f578402add` here.

## 2. Original MEDIUM — closed

The original review quoted section 6: “What changes is whether the tool PDP honors the delegation mismatch,” and section 23 treating `lookup_customer_tier` as the request under all three modes.

That sentence is gone. Current section 6, section 8, section 18, and section 23 say:

- ATTACK and RETEST request `lookup_customer_tier` / `customer:read` / `cust-001`, with a SIMULATED DELEGATION DECISION of `MISMATCH`.
- ATTACK’s CTRL-MCP-001 is ALLOW only because of the labeled fail-open.
- RETEST’s CTRL-MCP-001 is DENY, and a start is not inferred.
- BASELINE requests `lookup_policy` / `policy:read` / `lending-basics`, with `MATCH`, and CTRL-MCP-001 ALLOW `tool_granted`.
- The three modes are not one request.

OBSERVED in `src/agentsec/identity/fixtures.py` and `src/agentsec/experiment_context.py`: ATTACK and RETEST both use `adversarial_a2a_payload()` (`lookup_customer_tier`, `customer:read`, `cust-001`). BASELINE uses `baseline_a2a_payload()` (`lookup_policy`, `policy:read`, `lending-basics`). The design’s split matches those fixtures. It does not invent a third request.

MEDIUM closed: 1/1.

## 3. Original LOW — closed

The mode table now has requested tool and requested resource. The learner ledger lists delegated tool and scope, delegated resource, requested tool, and requested resource. Section 6 and section 17 say a tool grant does not authorize every resource that tool could reach. Resource scope stays a simulated delegation attribute. No production resource authorizer is specified.

The teaching case still changes tool and resource together. That is the existing fixture pair. The ledger can still show the two dimensions apart. Holding the tool constant and varying only the resource is a later lesson, not a reopening of this finding.

LOW closed: 1/1.

## 4. Semantic chain

The design keeps separate records:

| Step | Design label | Boundary that holds |
| --- | --- | --- |
| Identity claim | Caller and callee fields, CTRL-IDENTITY-001 | A name is not authentication |
| Authentication | SIMULATED AUTHENTICATION RESULT | `AUTHENTICATED` is not a tool decision and is not current runtime behavior |
| Delegation | SIMULATED DELEGATION DECISION | `MATCH` is not ALLOW. `MISMATCH` is not DENY |
| Tool authorization | CTRL-MCP-001 | The only tool PDP |
| Execution | `agentsec.mcp.started` when a separate row exists | Not the ALLOW, and not completion |
| Completion | A possible later completion row | Not specified as proven by a start |
| Resource outcome | A possible resource-outcome row | Left NOT PROVEN in the first slice |

Section 8 says Splunk records rows and does not authenticate, delegate, or authorize. Section 2 says a Splunk row is not authority.

CTRL-IDENTITY-001 stays claim observation. OBSERVE is not ALLOW. Candidate `CTRL-AUTHN-001` may return `AUTHENTICATED` or `AUTHENTICATION_FAILED` and must not return a tool ALLOW or DENY. It is not implemented.

CTRL-MCP-001 stays the tool PDP. The design says not to change `authorize_tool`.

## 5. Simulated packet versus historical corpus

Section 1 keeps the previously measured claim-only corpus: ATTACK 6, RETEST 6, BASELINE 1, CTRL-IDENTITY-001 OBSERVE on those runs, `who_authenticated` count 0, `LAB-AGENT-DELEGATION-001` count 0. It says this remediation adds no new Splunk export and that the corpus is not authenticated A2A and not delegated authority.

Section 6 puts the teaching case in a SIMULATED / REPLAY packet and says not to merge it with `/identity/delegate`. Section 17 marks each ledger row SIMULATED A2A PACKET or HISTORICAL CLAIM-ONLY CORPUS, and historical rows must leave authentication and delegation NOT OBSERVED.

That separation is clear enough for a learner if the workshop keeps those labels on the rows. The mission question “who authenticated” in section 17 is safe only because the same section requires the simulated label. An implementer should print SIMULATED AUTHENTICATION RESULT on the row, not a bare “authenticated.”

## 6. Authentication and delegation models

The simulated authentication record is educational metadata: principal id, type `agent`, method label `lab_assertion`, lab issuer name, audience, result, credential reference, issued-at, expires-at. Section 3 says the reference is an id or fingerprint and is never a password, token, key, or certificate. Section 16 forbids storing secrets and forbids OAuth, OIDC, PKI, SPIFFE, a vault, and an authentication library. A search of the design found no credential material, certificate, or private key.

A reader of section 3 cannot reasonably treat the packet as evidence that AgentSec currently authenticates agents. The sentence is explicit.

The delegation record names delegator, delegate, delegation id, tool, scope, resource, audience, time, and MATCH / MISMATCH / ABSENT. Two agent ids are not that record. Authentication does not create the grant. The tool decision stays with CTRL-MCP-001.

`issued-at`, `not-before`, and `expires-at` are fields the learner reads. Section 10 says no short-lived credential is issued and no clock is implemented. Rotation, revocation, and replay stay later.

## 7. Claims that stay unproven

The design’s section 23 list, plus the surrounding prohibitions, leave these unproven:

1. `applicant-web` is an authenticated human.
2. `applicant-web` caused the tool call.
3. The historical `/identity/delegate` corpus is authenticated A2A.
4. The historical corpus is delegated authority.
5. An agent id proves authenticated identity.
6. Authentication proves delegation.
7. A delegation MATCH proves CTRL-MCP-001 will ALLOW.
8. CTRL-MCP-001 ALLOW proves execution.
9. `agentsec.mcp.started` proves successful completion.
10. Tool execution proves a downstream resource change.
11. ATTACK demonstrates production A2A authentication. Section 6 states the packet is not production authentication.
12. RETEST proves universal delegation enforcement. Section 23 item 12 says RETEST does not prove universal resistance.
13. BASELINE proves universal safety.

## 8. Workshop feasibility and later phases

One REPLAY workshop can teach the chain with a labeled packet: claim, simulated authentication, simulated delegation evaluation, CTRL-MCP-001, possible start, bounded conclusion. It does not need a runtime authenticator, production IAM, a schema bump, an ExternalEvidence change, a new LIVE attack, a new LIVE lab, an enabled detector, a second PDP, OAuth, OIDC, JWT, PKI, mTLS, SPIFFE, secrets, or certificates.

`SCHEMA_VERSION` remains `1.9.0`. `EXTERNAL_CONTRACT_VERSION` remains `1.0.0`. The design says a later runtime emission would likely need a schema change. The first workshop does not.

Later phases have a place to attach without being built: an optional approval reference (HITL), the same time fields (short-lived credentials), purpose distinct from tool and resource (retrieval), owner and reader distinct from the acting agent id (memory), and stable agent, tool, and workflow identifiers (inventory). Software-engineering and cloud or IT operations scenarios are not named. The same identifiers leave room for them. None of those phases are authorized by this review.

Framework notes stay NEEDS_EXTERNAL_VALIDATION. No technique id. No compliance claim.

Current runtime A2A coverage remains WEAK: caller and callee claims exist; authentication and delegated authority are NOT MODELED. Teaching evidence for one bounded REPLAY workshop is sufficient. Production A2A forensics from the historical corpus is insufficient.

## 9. Validation discipline

`git diff --stat 1de4f6e..7335a54` is documentation only. This review did not re-execute pytest. The reported offline result does not validate authentication or delegation. No new MEASURED Splunk export was taken. Historical 6 / 6 / 1 counts stay previously measured.

Secret hygiene of the design text: PASS. This review adds no credentials, certificates, or cryptographic algorithms. Codeguard applied because the only new file is this assessment.

## 10. Findings

BLOCKER: 0. HIGH: 0. MEDIUM: 0. LOW: 0.

The original MEDIUM and LOW are closed in the design text, not merely in the remediation report.

## 11. Verdict

GO — AUTHORIZE BOUNDED A2A AUTHENTICATION & DELEGATION WORKSHOP

This verdict authorizes a later implementation prompt. It does not implement the workshop. Do not begin HITL, short-lived credentials, RAG authorization, memory isolation, AI-BOM, or supply-chain security from this file.
