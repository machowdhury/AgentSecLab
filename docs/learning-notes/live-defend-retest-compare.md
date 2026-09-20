# LIVE DEFEND / RETEST / COMPARE (LAB-PI-001)

## WHAT IS IT?

A per-request experiment configuration so you can run ATTACK and RETEST as two independent live experiments with the same malicious input and different server-owned defenses.

## WHY DOES IT EXIST?

If security profile lives only in process environment, RETEST cannot be honest. Changing env for one learner would change every concurrent run. The closed loop needs: same input, different defense, different outcome, two fresh `run.ids`.

## HOW DOES IT WORK?

The learner picks LAB-PI-001 ATTACK or RETEST. Attack Service maps that to a server-owned `ExperimentDefinition`, creates an immutable `ExperimentContext`, and posts catalog payload plus `experiment_id` to AcmeBank. AcmeBank copies Settings for that request (`security_profile` from the context) and does not mutate `AGENTSEC_SECURITY_PROFILE`.

- BASELINE: normal input, defended
- ATTACK: ATK-002, intentionally vulnerable
- RETEST: same ATK-002 bytes, defended

Input fingerprint is `sha256` of the payload (`agentsec.content.hash` on hop 0). Fixture names are not proof of equivalence.

## WHERE DOES IT SIT IN AGENTSEC?

After 14C guided investigation. Studio still has ten tabs. DEFEND explains CTRL-INPUT-001. RETEST launches live. COMPARE asks “What changed?” PROVE classifies evidence. Splunk Search remains the workbench.

## WHAT IS THE TRUST BOUNDARY?

Untrusted loan text still meets CTRL-INPUT-001 at `acmebank.http_api` before `acmebank.llm_call`. The new boundary is: the browser must not submit security configuration. Experiment selection is not a grant.

## WHAT COULD AN ATTACKER CONTROL?

The allowlisted catalog string already chosen by the specimen. Not profile, tools, scope, grants, policy, SPL, Python, shell, or environment variables.

## WHAT CAN GO WRONG?

Treating RETEST DENY as SAFE. Treating missing Splunk `llm.*` as blocked without completeness. Sending `profile` from the browser (ERROR, not DENY). Using a canonical REPLAY UUID as if it were the fresh RETEST. Believing Splunk caused the different outcome.

## WHAT TELEMETRY SHOULD EXIST?

Same schema 1.9.0 events. ATTACK (vulnerable, Ollama up): hop-0 ALLOW fail-open plus `llm.*`. RETEST (defended): hop-0 DENY, `pipeline.stopped`, no `llm.started` on a complete copy. Distinct `run.id`. Matching `agentsec.content.hash` on hop 0.

## HOW WILL SPLUNK SHOW IT?

Reuse Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-EXECUTED, Q-LLM-AFTER-DENY. Path A uses the fresh ids. Path B uses canonical REPLAY tables. A compare Search URL may include both ids; it is server-built.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001 with server-owned `profile=defended` vs labeled `vulnerable`. The regex rules themselves do not change. Splunk does not change the result.

## WHAT TEST PROVES THE LOGIC?

Concurrent ATTACK + RETEST launches: profiles stay vulnerable vs defended, fingerprints match, `run.ids` differ, process env unchanged. Unknown `experiment_id` is ERROR, not fail-open.

## Lab limitation

CTRL-INPUT-001 is regex. Paraphrases may ALLOW. That is a teaching control, not a product IPS.

## What I should now be able to explain

1. Why process-global `AGENTSEC_SECURITY_PROFILE` blocked honest RETEST.
2. Why the browser must not submit `security.profile`.
3. What an `ExperimentContext` is, and who constructs it.
4. How ATTACK and RETEST can share a payload fingerprint and still differ in outcome.
5. Where CTRL-INPUT-001 runs, and what Splunk does not do.
6. The difference between authoritative runtime hops, control evidence, and corroborative Splunk rows.
7. Why DENY is not automatic prevention proof.
8. Why RETEST is not automatically SAFE.
9. What evidence would falsify a defended RETEST prediction.
10. Why this lab does not prove universal prompt-injection resistance.
