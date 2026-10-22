# Batch 3 notes: Docker/Splunk integration, correctness, Academy mission

## Model identity (approved default)
llama3.2:latest, digest a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72, 3.2B Q4_K_M, family llama (Ollama host install).
Runtime: temperature 0.2, num_predict 300, schema-constrained JSON (`format`), 10 steps / 5 tool executions / 3 unusable replies / 120 s.
Reported by `/api/v1/loan-desk/status` and stored on every run. Limits: samples are n=5 to n=20, model output is non-deterministic, one model, one host.

## Gate 1: real stack
Docker (project agentseclab): only `agentsec_acmebank` was recreated, twice (see DEPLOYMENT_PLAN.md). Browser -> model -> policy -> handlers -> OTLP -> collector -> HEC -> Splunk all exercised.
`gate1/reconcile.json`, `docker_before_after.json`: every run reconciled (local events == indexed events, == distinct sequences, same per-event-name counts, same sequence sets).
Splunk keeps every field twice (indexed + search-time extraction): `agentsec.sequence` is multivalue on all events, so `count(field)` is exactly 2x the events (68 vs 34). Reconciliation counts events and dedupes values (`mvdedup`).
My first reconcile attempt returned 0 because the Splunk CLI already prepends `search`; that was a query bug of mine (kept in gate1/reconcile_first_attempt.json), not a delivery fault.
Local vs Splunk-verified: AcmeBank cannot reach Splunk (REST probe stays disabled). Status is NOT_VERIFIED until a host-side record `artifacts/loan_desk/<run_id>.splunk.json` (written by scripts/loan_desk_verify.py) matches the run; then SPLUNK_VERIFIED / SPLUNK_MISMATCH / STALE.

## Gate 2: correctness
`facts.py` computes loan facts from handler results; model prose is a separate, labelled, unverified block; figures in it that no tool/computation supports are flagged. `outcomes` separates Security (BLOCKED / nothing blocked) from Business workflow (COMPLETE / INCOMPLETE / FAILED) and counts proposed/authorized/denied/executed.

## Gate 3: mission and defense
New control (not the existing denial): argument-level authorization of the review note. BASELINE = free text (deliberate lab weakness); HARDENED = one of 4 reason codes else DENY `argument_not_allowed:note`. Per run, closed set, recorded as `agentsec.defense.posture`, reversible.
The cross-customer denial (`resource_not_bound_to_run`) is unchanged and is not presented as a remediation.
Real-model before/after (host Ollama, 20 runs per cell): defense_before_after.json. Docker (5 per cell, all Splunk-reconciled): docker_before_after.json.
Mission journey with the real model and real Splunk: mission/mission_run.json and mission/screenshots/.

## Limits
- Mission is served by the HOST Attack Service in the E2E; the attack_service container was not rebuilt (needs approval). The mission is therefore not yet in the running container.
- The mission is not a curriculum.json entry (adding one needs a Splunk view, manifest and launch-catalog changes); it is linked from the Academy home and sidebar.
- Hardened + attack: sometimes INCOMPLETE (model keeps retrying the planted note until the step budget): host 19/20 completed, Docker 3/5.
- The hardened control also rejects the model's own harmless prose; the model recovers via the hint (extra denied step on most normal runs).
- Learner Splunk count is learner-reported; automatic verification needs the host script.
- Model checklist scaffolding (system prompt + step hints) is what makes a 3B model finish; it is guidance, not a control.
