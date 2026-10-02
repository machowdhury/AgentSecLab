# Agent Identity and Non-Human IAM workshop — independent review

**Historical Review Record.** This document records an intermediate AgentSec development/review state prior to the final v1.0.0 release. It is retained for engineering traceability and should not be interpreted as the current product state.

Reviewed commit: `6cd51e7ca07441a9fa6ca6d2ebe02161915b92c4`

This review re-measured the index and opened the Studio view. It did not change application code, runtime behavior, schema, ExternalEvidence, detectors, or tags. Temporary measurement scripts were removed after the checks. They are not part of the reviewed commit.

Evidence below is MEASURED when a Splunk export or a browser session produced it, and OBSERVED when it comes from the files at that commit.

## Repository integrity

| Check | Result |
| --- | --- |
| HEAD | `6cd51e7ca07441a9fa6ca6d2ebe02161915b92c4` |
| origin/develop | same commit |
| main and origin/main | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| v1.0.0-rc2 peeled commit | `1be214b92f840f843aaf27fb2b9536f764dd7126` |
| v1.0.0-rc3 | no tag |
| Commit range `91f3e08..6cd51e7` | academy, Studio view, searches, tests, inventory, learning note, implementation report. No `src/` change. |

`SCHEMA_VERSION` is `1.9.0`. `EXTERNAL_CONTRACT_VERSION` is `1.0.0`. `savedsearches.conf` is not in the commit. Its existing stanzas remain `disabled = 1`. `LAB-AGENT-IDENTITY-NHI` is not in `known_lab_ids()` and has no `lab-manifest.json`. No runtime authentication was added.

Untracked files that should be preserved before a final 1.0, and that this commit did not include:

- `docs/plans/`
- `docs/reviews/AGENTSEC_DETECTION_ENGINEERING_WORKSHOP_INDEPENDENT_REVIEW.md`
- `docs/reviews/AGENTSEC_AGENT_IDENTITY_NON_HUMAN_IAM_DESIGN_INDEPENDENT_REVIEW.md`
- `docs/reviews/AGENTSEC_AGENT_IDENTITY_NON_HUMAN_IAM_DESIGN_RE_REVIEW.md`
- this review, once kept

## Curriculum

Levels remain L0 through L10. Checkpoint `AGENT-IDENTITY-NHI` is `L7 → Identity/NHI Workshop → L8`, mode `REPLAY`, `live_launcher` false. The nav collection sits after Security Architecture and before Privacy. L8 prerequisites name the workshop. It is not an Attack Service lab and not a new attack level.

## Discovery

The mission starts from the question “Who or what requested the delegated operation, what identity evidence exists, what authorized the tool, and what actually executed?” It does not contain a run identifier or an ATTACK/RETEST/BASELINE decision.

MEASURED: `agentsec.lab.id=LAB-AGENT-DELEGATION-001` returned count 0. The workflow `agentsec.workflow.entry=/identity/delegate` returns `agentsec.lab.id=agentsec-local`. A learner can discover the candidate runs from that workflow without a run id.

## Corpus, with the multivalue check

On the workflow events, `agentsec.run.id` and `agentsec.testbed.mode` have a raw multivalue count up to 3. After `mvdedup`, every one of the 124 events has exactly one distinct run id and one distinct mode. The extra copies are duplicates, not conflicting runs. The workshop searches take `mvindex(mvdedup(...),0)` and then `dc(run_id)`. That count is a run count.

MEASURED run counts: ATTACK 6, RETEST 6, BASELINE 1.

Event counts on the same filter are higher and must not be reported as runs: ATTACK 60 events, BASELINE 10 events, RETEST 54 events.

## Identity claims

On CTRL-IDENTITY-001, all three modes:

- `agentsec.principal.id=applicant-web`
- `agentsec.principal.type=user`
- caller `acme-agent-advisor-005`
- callee `acme-agent-fulfillment-006`
- `gen_ai.agent.id=acme-agent-fulfillment-006` (the callee, on the observation event)
- decision OBSERVE
- no delegator value on those rows

`agentsec.delegator.agent.id=acme-agent-advisor-005` is present on 59 workflow events and absent on 65. The page treats absence as no evidence of a delegator, which matches the identity-control rows.

The workshop does not say applicant-web is a human, that anyone authenticated, or that a name caused the tool call. Those sentences are marked NOT PROVEN or NOT MODELED. No learner-facing sentence upgrades them.

## principal.type and who_authenticated

MEASURED: workflow events that carry `gen_ai.agent.id` use `acme-agent-fulfillment-006` with `principal.type=user`, including `agentsec.mcp.started` and `agentsec.mcp.completed`. The identity tab says `user` does not mean an authenticated human and that this workshop does not change the emitter or schema 1.9.0.

`who_authenticated` as a field and as raw text both returned count 0. The page says authentication is NOT MODELED and an empty search is AUTHENTICATION NOT OBSERVED. The explanatory words on the page are not indexed events.

## Controls, modes, and execution

MEASURED CTRL-MCP-001, and the run count matches the event count for each decision:

- ATTACK: ALLOW, `vulnerable_profile_fail_open:caller_identity_derived_authority`, 6 runs
- RETEST: DENY, `tool_not_granted`, 6 runs
- BASELINE: ALLOW, `tool_granted`, 1 run

CTRL-IDENTITY-001 is OBSERVE / `identity_claim_is_not_grant` on all 13 runs. The page says OBSERVE is not ALLOW, and that this control does not authenticate or authorize.

Sequence is stable. For every run in a mode, minimum and maximum sequence match:

- CTRL-IDENTITY-001 at sequence 3
- CTRL-MCP-001 at sequence 6
- `agentsec.mcp.started` at sequence 7 for ATTACK (6) and BASELINE (1)
- RETEST has the two control events and no start

Start rows: `has_control=no`, principal `applicant-web`, type `user`, agent `acme-agent-fulfillment-006`. The page says a start can omit `agentsec.control.id` and that the agent id is not an authenticated executing principal. Changing ALLOW versus DENY is not described as authentication.

`caller_identity_derived_authority` is called a labeled authorization fault on the authority tab and again on Path B. It is explicitly not authenticated delegation, legitimate delegation, verified identity, valid agent authority, or production IAM.

## Ledger, progression, and failure language

The ledger requires the six subjects the review asked for and separates claim, observed value, evidence event, and what the evidence does not prove. Unsupported human, authentication, and delegation sentences are marked NOT PROVEN. The CTRL-MCP-001 row still tells the learner to name the decision they observed rather than copy it from a run count.

Path A gives a partial discover search and asks the learner to add `stats`, write a control query, write a start query, and order one run. The mission does not state the mode result. Path B contains the finished searches. That is an answer key, labeled not policy.

The identity tab does print the observed principal, caller, and callee, and the ledger prints the boundary for each claim. Those steps are guided. The authorization comparison is not. Progression is useful and guided: MIXED, not weak.

Empty results use NO EVIDENCE FOUND, INSUFFICIENT EVIDENCE, AUTHENTICATION NOT OBSERVED, ATTRIBUTION NOT PROVEN, and CORRELATION NOT ESTABLISHED. SAFE, AUTHENTICATED, TRUSTED, and AUTHORIZED HUMAN appear as sentences the learner must not write. The empty-table message says an empty result is not those things.

## Production gaps and later phases

The gaps tab lists authenticated principal, issuer, method, workload identity, session, tenant, owner, lifetime, issuance, expiry, rotation, revocation, delegation proof, audience, and scope as NOT MODELED. None of those were implemented.

Authenticated agent-to-agent, delegated authority, short-lived credentials, human approval, retrieval authorization, memory ownership, an AI bill of materials, and supply-chain trust are labeled FUTURE / NOT MODELED. The workshop leaves those as later designs. It does not teach them as present behavior. Teaching evidence for this lab is sufficient for the claim boundaries. Production identity forensics from this corpus is insufficient, and the page says so.

## UI and accessibility

Observed in Chrome at `http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agent_identity_nhi` after login. The view was not a 404. Discover showed ATTACK. The ledger showed NOT PROVEN. Path B showed CTRL-MCP-001 and the authorization-fault sentence. The Path B table at 1440 was 1380 by 1380 pixels, with no table or code overflow on the measured tabs.

Document horizontal overflow was absent at 1920, 1440, 1280, and 1024 (`scrollWidth` equaled `clientWidth`).

The right-hand tabs collide with Splunk toolbar controls as the viewport narrows. Tab rectangles were not covered at 1920. At 1440, Path B intersects the toolbar. At 1280, the evidence ledger, Gaps, and Path B do. At 1024, Execution, Compare, the ledger, Gaps, and Path B do. A pointer click on Compare at 1024 was intercepted by the Add favorite button. DOM activation could still change tabs in this session. That is a reachability defect for pointer users at 1280 and 1024, not an identity-semantics defect.

CSS zoom 2 at a 1024 CSS-pixel viewport produced `scrollWidth` 1920 against `clientWidth` 1024. Compare through Path B were off screen. A 512 CSS-pixel viewport produced `scrollWidth` 960 against `clientWidth` 512. That is geometric zoom, not a reflow.

Keyboard: after focusing the mission tab, Tab moved into the mission text (`outline` auto) and then to the Search link, which had a visible blue box shadow (`rgb(0, 110, 170) 0px 0px 1px 3px`) and `outline` none. ArrowRight did not move off that link and did not switch tabs. The focused nodes were not `role=tab`. Path B was not reached from the keyboard in this pass. Screen reader was not available and was not tested. No WCAG claim. The document title was `undefined | Splunk 10.2.7` while the page body showed the workshop name.

## Tests and secrets

`tests/splunk/test_agent_identity_nhi_workshop.py` plus the academy view contracts: 42 passed.

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`: 1042 passed, 3 deselected, 10.55s.

The reviewed commit contains no passwords, tokens, private keys, certificates, or customer data. The only `SPLUNK_PASSWORD` string is a sentence in the implementation report stating that the local lab password was not committed. No credential-like fixture was added to the workshop.

## Findings

MEDIUM. At 1280 and 1024, Splunk toolbar controls cover the later workshop tabs, including the evidence ledger and Path B. At 1024 a pointer click on Compare was intercepted by Add favorite. At 1920 the nine tabs were uncovered, and the page did not overflow horizontally at the four required widths.

LOW. The browser title is `undefined | Splunk 10.2.7`.

LOW. Path A prints the identity labels and the ledger boundaries. The learner still has to write the mode comparison. That is guided practice, not a false conclusion.

No BLOCKER. No HIGH. Identity, authorization, and execution stay separate. The vulnerable reason stays an authorization fault. Run counts were checked against duplicate multivalue copies before they were accepted.

## Verdict

GO — IDENTITY/NHI WORKSHOP VALIDATED; AUTHORIZE A2A AUTHENTICATION & DELEGATION DESIGN

The medium finding is a Splunk chrome overlap. It does not invent an authenticated human, an authenticated agent, or an authorization result. A2A authentication and delegation remain a later design. This review does not start that design.
