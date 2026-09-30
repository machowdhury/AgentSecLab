# Agent identity and non-human IAM — design remediation

Design text only. Runtime, schema, ExternalEvidence, detectors, attacks, and release tags were not changed.

Starting commit: `ff63f1f77bcc195b5b3c86c4458c3889d0e39fe7`. Independent review: `docs/reviews/AGENTSEC_AGENT_IDENTITY_NON_HUMAN_IAM_DESIGN_INDEPENDENT_REVIEW.md`. Corrected design: `docs/architecture/AGENTSEC_AGENT_IDENTITY_NON_HUMAN_IAM_DESIGN.md`, section 18.

Splunk facts below were reconfirmed in this pass against the existing index. No new attack was launched. Classification: MEASURED.

## MEDIUM-01. Indexed lab id

Finding. The review measured that `agentsec.lab.id=LAB-AGENT-DELEGATION-001` matches no events.

Evidence. Reconfirmed: that search returned count 0. `agentsec.workflow.entry=/identity/delegate` returned ATTACK 6 runs, RETEST 6 runs, and BASELINE 1 run, all with `agentsec.lab.id=agentsec-local`.

Correction. The curriculum lab id stays a repository contract. The workshop discovers evidence from the workflow entry and `agentsec-local`. An empty search on the curriculum lab id is `NO EVIDENCE FOUND` for that key, not proof the workflow is missing, and not a safety verdict.

Remaining limitation. Run counts are a corpus size. They are not a claim that every run has the same authorization result. A later implementation must measure sequence and fields again.

Workshop implication. Path A must not use `LAB-AGENT-DELEGATION-001` as the indexed search key. No initial run id is supplied.

## LOW-01. Non-human principal

Finding. The design summary said a non-human principal was PARTIAL.

Evidence. Emitted fields are caller id, callee id, `gen_ai.agent.id`, and `agentsec.delegator.agent.id`. No authenticated agent subject, owner, or workload proof is emitted. `agentsec.principal.type` on this workflow is `user`, not `agent`.

Correction. Maturity is CLAIM ONLY. A named agent is not a security principal. Those ids do not establish authentication, credential binding, principal establishment, delegated authority, or human attribution. The word principal is reserved for the principal-label field, and even that field is a label.

Remaining limitation. The schema enum allows `agent` and `system`. This emitter does not write them for this case.

Workshop implication. Ledger roles are "caller claim" and "callee claim," not "principal" for those agents.

## LOW-02. Agent id is not execution

Finding. `gen_ai.agent.id=acme-agent-fulfillment-006` is present on CTRL-IDENTITY-001 before `mcp.started`, because hop 0 stamps the callee.

Evidence. OBSERVED in `src/agentsec/identity/pipeline.py`: hop 0 agent is `CALLEE_AGENT_ID`. The review measured that id on the identity control event.

Correction. Identity claim, CTRL-MCP-001 authorization, `agentsec.mcp.started`, completion, and outcome stay separate. An agent id does not fill the execution column. If the start event does not bind an actor, that binding stays NOT PROVEN.

Remaining limitation. A start event can still carry an agent id without `agentsec.control.id`. Correlation of that id to the handler is not attribution.

Workshop implication. Learners must answer that an agent id does not prove that agent executed the operation.

## LOW-03. principal.type

Finding. `agentsec.principal.type` is hardcoded `user` on the measured identity workflow, including agent events. The schema also allows `agent` and `system`.

Evidence. OBSERVED in `_base_event`. MEASURED type `user` on the identity workflow. This remediation does not change the emitter or schema 1.9.0.

Correction. Classified as a known telemetry semantic limitation. `principal.type=user` is not an authenticated human and not proof a human caused the action.

Remaining limitation. The constant will keep misleading readers who stop at the field name until the workshop says so.

Workshop implication. The limitation is taught. It is not "fixed" by a schema bump.

## who_authenticated

Finding. The review found the value only as a result string, `NOT PROVEN / NOT MODELED`.

Evidence. Reconfirmed: an indexed search for `who_authenticated` returned count 0. The string is set in `identity_result_to_dict`.

Correction. The workshop must not treat it as authentication proof. Authentication remains NOT MODELED.

Remaining limitation. A launch response can still show the sentence. That response is not an indexed event.

Workshop implication. Authentication evidence stays a missing-evidence cell.

## Claims that stay NOT PROVEN

`applicant-web` is a human. `applicant-web` authenticated. `applicant-web` caused the tool call. The advisor id authenticated or held delegated authority. The fulfillment id authenticated or received authenticated delegation. The tool executed under `applicant-web`'s authority.

The vulnerable overlay `caller_identity_derived_authority` remains a labeled lab fault on CTRL-MCP-001. It is not authenticated identity and not proof of legitimate authority.

## Telemetry

Bounded REPLAY teaching: partial, and sufficient for the exercise, because claim fields, both control ids, sequence, and `mcp.started` are present when the workflow key is used.

Production identity forensics: insufficient. There is no authenticated subject, issuer, session, credential binding, owner, or expiry. This phase does not add them.

## Tests

No unit test asserts this design file. Offline command `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`: 1037 passed, 3 deselected, in 10.87s. Those tests do not validate a workshop, because the workshop was not built. Live workshop validation was not claimed.
