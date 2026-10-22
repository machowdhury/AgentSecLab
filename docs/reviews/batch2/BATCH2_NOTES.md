# Batch 2 — Interactive AcmeBank Loan Desk (notes, limits, rollback)

## What exists
- `GET /loan-desk` (AcmeBank, port 5000): validated synthetic application form -> background agent run -> live progress -> execution timeline -> result -> evidence panel.
- API: `POST /api/v1/loan-desk/applications` (202 + run view), `GET .../runs/<id>`, `GET .../runs/<id>/events.ndjson`, `GET .../status`.
- Loop (`src/agentsec/loan_desk/`): model proposes (Ollama `/api/chat`, schema-constrained JSON) -> `policy.decide()` (pure function of server-owned grants, the applicant bound to the run, and budgets; it never sees prompt, notes or model text) -> handler begins only on ALLOW (`agentsec.mcp.started` is emitted before the handler body) -> result returns to the model as untrusted data. Bounds: 6 model steps, 4 tool executions, 3 unusable replies, 120 s.
- Events: new closed family `schemas/loan_desk_event.schema.json` (`agentsec.loan_desk_event` 1.0.0). **`security_event.schema.json` 1.9.0 is untouched** (46 existing tests freeze it). `validate_event` dispatches on `agentsec.schema.name`. A global schema bump needs your decision.
- C2 timeline: `proposed=true` and `proposal_source="model"` only when an `agentsec.agent.action.proposed` event from a real model client precedes the decision. Test doubles are reported as `proposal_client="test_double"` and never as `model`; the page prints "SCRIPTED TEST DOUBLE (not model-driven)".
- Academy duplicate header: the masthead no longer repeats the mark and name that the shared bar shows.

## Model selection (measured, not assumed)
- Single-call benchmark (`model_benchmark.json`, 8 trials x 6 scenarios): grammar-constrained `format` beat native `tools` on all three models. mistral looked best (48/48).
- Whole-loop benchmark (`agent_loop_benchmark.json`, 10 real runs per model/scenario) contradicted that: mistral often fails to finish (2-6/10 completed, 10-13 s) while llama3.2:latest (3B) completed 10/10 benign runs in about 2.4 s. **Recommended: `LOANDESK_MODEL=llama3.2:latest`.** Unset, the Loan Desk uses the configured `OLLAMA_MODEL` (container default llama3.2:1b: 9-10/10 benign, weaker when manipulated).
- Real denials: with a note asking for APP-2002's data, llama3.2:latest proposed cross-customer reads in every run and policy denied each (`resource_not_bound_to_run`, handler never began). No model ever proposed `issue_loan_offer`, so that denial (`scope_not_granted`) is proven only with a test double.

## Not done / limits
- Telemetry was **not** sent to Splunk: the stack was not touched and the REST probe stays off. Events are validated and downloadable; the page says "NOT VERIFIED" for indexing. Indexing needs a rebuild of the Attack/AcmeBank image and your approval.
- The Loan Desk is not linked from the Academy or the Attack Service yet, and no workshop wraps it.
- The model's final text is unverified prose; it can state numbers no tool returned (seen: a "38.5% debt service ratio"). It is labelled advisory.
- Model output is non-deterministic: numbers above are samples (n=10), not guarantees.
- State is in memory (lost on restart); 500-application cap.
- Single-process worker threads: fine for one learner, not sized for 30 concurrent learners.
- `agentsec.outcome=completed_denied` here means "at least one proposed action was denied", while the run still finished.

## Rollback
Revert the Batch 2 commits. Files: `src/agentsec/loan_desk/`, `bank_app.py` (routes + `loan_desk_model` field), `schema.py` (dispatch), `timeline.py` + `run_timeline.schema.json` (additive keys), `academy/base.html`, templates/static/tests/scripts listed in the commit. The running Docker stack was never modified.
