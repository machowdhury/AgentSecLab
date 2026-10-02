# Agent identity and non-human IAM — independent re-review

**Historical Review Record.** This document records an intermediate AgentSec development/review state prior to the final v1.0.0 release. It is retained for engineering traceability and should not be interpreted as the current product state.

Review only. Application code, runtime, schema, ExternalEvidence, detectors, attacks, and tags were not modified. This file is the review artifact.

Reviewed commit: `91f3e089b99a85a631c25aade311ba9d483990bb`. `HEAD` and `origin/develop` are that commit. `main` and `origin/main` are `e6115b6d1c03a1672b4364e84748c7840671fbfc`. `v1.0.0-rc2` is an annotated tag whose object is `bd8c2c02729497018b4e28b582fe6c9a9e052638` and whose peeled commit is `1be214b92f840f843aaf27fb2b9536f764dd7126`. No `v1.0.0-rc3` tag was found. The design and the remediation report are tracked in `91f3e08`. The diff from `ff63f1f` to `91f3e08` does not touch `src/`, `schemas/`, or `splunk_app/`. Working tree leftovers are untracked `docs/plans/` and two earlier review files. They were not part of this re-review's edits.

Evidence in this file is MEASURED on the existing index, or OBSERVED in source. No new attack was launched.

## MEDIUM-01

`agentsec.lab.id=LAB-AGENT-DELEGATION-001` returned count 0. That repository contract is still not an indexed key.

The identity workflow is `agentsec.workflow.entry=/identity/delegate` with `agentsec.lab.id=agentsec-local`.

Distinct runs, not identical authorization outcomes:

| Mode | Runs | CTRL-IDENTITY-001 | CTRL-MCP-001 | `agentsec.mcp.started` |
|---|---|---|---|---|
| ATTACK | 6 | OBSERVE, 6 runs | ALLOW `vulnerable_profile_fail_open:caller_identity_derived_authority`, 6 runs | 6 runs |
| RETEST | 6 | OBSERVE, 6 runs | DENY `tool_not_granted`, 6 runs | no start rows |
| BASELINE | 1 | OBSERVE, 1 run | ALLOW `tool_granted`, 1 run | 1 run |

The design now tells Path A to discover those indexed fields and forbids using the curriculum lab id as the search key. It also says the 6/6/1 counts are not one shared authorization result. MEDIUM-01 is closed.

## Claims

On every measured CTRL-IDENTITY-001 event in that workflow: principal `applicant-web`, type `user`, caller `acme-agent-advisor-005`, callee `acme-agent-fulfillment-006`, `gen_ai.agent.id` `acme-agent-fulfillment-006`, decision `OBSERVE`.

`_base_event` still sets `agentsec.principal.type` to the constant `user`. Events on this workflow that carry `gen_ai.agent.id` are type `user` (98 events, 13 runs, agent `acme-agent-fulfillment-006`). The design calls this a known telemetry semantic limitation and says `principal.type=user` is not an authenticated human and not proof a human caused the action. The emitter and schema were not changed.

`who_authenticated` indexed count is 0. The result string `NOT PROVEN / NOT MODELED` is not authentication evidence. Authentication remains NOT MODELED.

Caller and callee ids are claims. They are not authenticated principals. A named agent is not a security principal. Non-human principal maturity is CLAIM ONLY. Human attribution is NOT PROVEN. The design's NOT PROVEN list matches the eight sentences in the re-review prompt. No remaining sentence upgrades those labels into authentication, principal establishment, human attribution, or delegated authority.

## Execution and controls

OBSERVED in `src/agentsec/identity/pipeline.py`: hop 0 sets `gen_ai.agent.id` to the callee before the tool call.

MEASURED on ATTACK run `110dd7a6-58b5-472a-ae80-aec76e11bf4e`: sequence 3 is CTRL-IDENTITY-001 `OBSERVE` with agent `acme-agent-fulfillment-006`; sequence 6 is CTRL-MCP-001 `ALLOW` with the same agent id; sequence 7 is `agentsec.mcp.started` with the same agent id and no `agentsec.control.id` in that row. One run does not prove every run's sequence numbers. It does show an agent id before execution.

The seven `mcp.started` rows (ATTACK 6, BASELINE 1) did not return `agentsec.control.id`. The design says the start event can carry an agent id and still omit the control id, and that the id does not prove which agent caused the handler to run. Actor-to-execution binding stays NOT PROVEN unless the learner establishes it. That is the conservative reading.

CTRL-IDENTITY-001 records the claim (`OBSERVE` or `ERROR`). It is not ALLOW. CTRL-MCP-001 remains the tool PDP. `agentsec.mcp.started` is the execution event. Splunk stays downstream. The vulnerable reason `caller_identity_derived_authority` is described as a labeled authorization fault, not authenticated delegation or legitimate authority.

## Workshop

One REPLAY checkpoint, `L7 → Agent Identity & Non-Human IAM Workshop → L8`, with no initial run id. The written order is discover, narrow, read claims, read CTRL-IDENTITY-001, read CTRL-MCP-001, order by sequence, read `mcp.started`, compare the three modes, fill the ledger, and state what stays NOT PROVEN. It does not depend on `LAB-AGENT-DELEGATION-001` as an indexed identifier.

Teaching evidence is partial and sufficient for that exercise. Production identity forensics stays insufficient: no authenticated subject, issuer, session, credential binding, owner, or expiry.

Later A2A authentication, delegation, short-lived credentials, HITL, RAG authorization, memory isolation, and supply-chain ownership can attach to the claim-versus-decision-versus-start split. This re-review does not design those phases. The hardcoded `principal.type` is a later migration note, not a dead end: the schema enum already allows `agent` and `system`, and this workshop is told not to treat `user` as a human.

OWASP ASI03 and NIST AI 600-1 remain **DOCUMENTED BUT NOT REVALIDATED**. No compliance claim.

## Tests

No test asserts the design file. Full offline command `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`: 1037 passed, 3 deselected, in 9.56s. Those tests do not execute the workshop.

## Findings

No BLOCKER, HIGH, or MEDIUM findings remain. The original MEDIUM finding is closed.

LOW findings: none that misstate the evidence. The remaining limits are already written into the design: corpus counts are not one outcome, `principal.type=user` is still emitted, and a start event's agent id is not attribution.

## Verdict

The workshop can be built from indexed claims and control events without treating those claims as authentication, human attribution, or delegated authority.

GO — AUTHORIZE BOUNDED IDENTITY & NON-HUMAN IAM WORKSHOP

This file does not implement that workshop.
