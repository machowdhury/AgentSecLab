# Phase 2A runtime validation

**Date:** 2026-09-10  
**AgentSec version:** 0.3.0  
**Schema:** `agentsec.security_event` 1.0.0  
**Command:** `.venv/bin/python -m pytest tests/unit tests/integration tests/security tests/telemetry -v --tb=line`  
**Result (2026-09-10 pytest):** 46 passed, 1 skipped, 0 failed  
**Later live run (2026-09-11):** local Ollama `llama3.2:1b` reachable. HTTP `POST /process` BASELINE completed four real generates. Live pytest re-run: **1 passed**.

This document records **executed** tests and one OBSERVED live HTTP run. A row is PASS only when that test or HTTP call ran and asserted the security property. Code existing is not PASS.

Evidence packs written during pytest live under pytest `tmp_path` and are deleted after the test. The **evidence location** column names the test that asserted the bundle contract. On a real `/process` run the runtime writes `artifacts/<run-id>/`.

Splunk export was **not attempted** and is **NOT VERIFIED**.

---

## TEST 1 — Benign BASELINE

| Field | Content |
|-------|---------|
| TEST | `tests/unit/test_pipeline.py::test_benign_pipeline_runs_four_agents` and `tests/integration/test_acmebank_api.py::test_process_benign_loan_returns_run_id` |
| SECURITY PROPERTY | Explicit benign `/process` is BASELINE / LIVE / OBSERVED; CTRL-INPUT-001 ALLOW; four hops invoke the LLM |
| EXPECTED RESULT | Four ALLOW hops; `llm_call_count==4`; `testbed.mode=BASELINE`; no `pipeline.stopped` |
| ACTUAL RESULT | Stub: four hops ALLOW; spy call count 4; HTTP 200; `incident.id==run.id`. Live HTTP (2026-09-11): `run.id=3367455f-e69a-4d60-bbe0-3de207aefcd9`, four real Ollama completions, `completed_allowed`. |
| PASS/FAIL | **PASS** (stub). **PASS** (live HTTP `/process` + live pytest, 2026-09-11) |
| EVIDENCE LOCATION | Stub: `tests/unit/test_evidence.py::test_evidence_bundle_has_required_files_and_honest_export`. Live: `artifacts/3367455f-e69a-4d60-bbe0-3de207aefcd9/` |
| LIMITATIONS | CTRL-INPUT-001 is a reference regex, not production prompt-injection protection. Live model wording is nondeterministic. |

---

## TEST 2 — ATK-002 + VULNERABLE

| Field | Content |
|-------|---------|
| TEST | `tests/security/test_untrusted_json_cannot_bypass.py::test_vulnerable_profile_fail_open_is_labeled` |
| SECURITY PROPERTY | Same ATK-002 payload in `vulnerable` is labeled fail-open ALLOW; LLM may run (INV-008 demonstration) |
| EXPECTED RESULT | `profile=vulnerable`; `testbed.mode=ATTACK`; four LLM calls; reason contains `vulnerable_profile_fail_open:` and identifies the lab reference-control fail-open |
| ACTUAL RESULT | `blocked=false`; `llm_call_count==4`; spy call count 4; reasons include reference-control fail-open text |
| PASS/FAIL | **PASS** (stub LLM) |
| EVIDENCE LOCATION | HTTP runtime memory events in that test; local bundle contract covered by evidence tests |
| LIMITATIONS | Fail-open is intentional and labeled. It is not a silent bypass and not a product control. |

---

## TEST 3 — ATK-002 + DEFENDED RETEST (critical negative)

| Field | Content |
|-------|---------|
| TEST | `tests/security/test_input_control_before_llm.py::test_defended_atk002_negative_contract` and `tests/security/test_untrusted_json_cannot_bypass.py::test_retest_label_is_server_owned` |
| SECURITY PROPERTY | CTRL-INPUT-001 DENY before invocation. Runtime is authoritative: LLM client is never called. |
| EXPECTED RESULT | decision DENY; attempted=false; executed=false; outcome=prevented; zero `llm.started` / `llm.completed` / `llm.failed`; spy call count 0; RETEST when `AGENTSEC_TESTBED_MODE=RETEST` |
| ACTUAL RESULT | All of the above held. CountingLLM spy `calls==[]`. RETEST env produced `testbed.mode=RETEST` with DENY. |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | `tests/unit/test_evidence.py::test_denied_evidence_agrees_with_runtime` |
| LIMITATIONS | Regex may miss paraphrases. That would be ALLOW with LLM calls, not a fake DENY. |

---

## TEST 4 — Empty input

| Field | Content |
|-------|---------|
| TEST | `tests/unit/test_controls.py::test_empty_input_is_error_in_both_profiles` and `tests/integration/test_acmebank_api.py::test_empty_input_is_400_control_error` |
| SECURITY PROPERTY | Empty input is ERROR in **both** profiles. Not a labeled vulnerability. No LLM. |
| EXPECTED RESULT | ERROR; attempted=false; executed=false; outcome=prevented; spy call count 0 |
| ACTUAL RESULT | Both profiles ERROR `empty_input`; HTTP 400; zero LLM calls |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Pipeline events in `test_empty_input_errors_without_llm` |
| LIMITATIONS | Empty is schema/control ERROR, not DENY. |

---

## TEST 5 — Malformed input

| Field | Content |
|-------|---------|
| TEST | `tests/unit/test_controls.py::test_malformed_input_is_error_in_both_profiles`, `tests/integration/test_acmebank_api.py::test_missing_input_is_400_schema_failure`, `test_malformed_non_object_is_400` |
| SECURITY PROPERTY | Malformed / missing / extra policy fields → ERROR before hops or before LLM. Unknown JSON is not merged into policy. |
| EXPECTED RESULT | `run.failed`; `error.stage=schema_validation` for HTTP contract failures; spy call count 0 |
| ACTUAL RESULT | Non-string inspect → ERROR; `{}` and JSON list → HTTP 400 `run_failed`; zero LLM calls |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | `tests/security/test_untrusted_json_cannot_bypass.py::test_http_cannot_skip_control_or_set_closed_fields` |
| LIMITATIONS | Malformed is not the vulnerable-profile demonstration. |

---

## TEST 6 — Control evaluation failure

| Field | Content |
|-------|---------|
| TEST | `tests/security/test_control_evaluation_failure.py::test_control_evaluation_failure_fail_closed` |
| SECURITY PROPERTY | INV-008 fail-closed: if CTRL-INPUT-001 raises, ERROR before invocation. Ollama must not execute. |
| EXPECTED RESULT | control.decision ERROR; attempted=false; executed=false; outcome=prevented; `error.stage=control_evaluation`; spy call count 0; not labeled DENY |
| ACTUAL RESULT | All of the above held. RuntimeError injected into inspect; CountingLLM not called. |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Events in that test (`run.failed` + control.decision ERROR) |
| LIMITATIONS | Injection is a test double. Production operators still need process supervision. |

---

## TEST 7 — Ollama unavailable (invocation started, then failed)

| Field | Content |
|-------|---------|
| TEST | `tests/integration/test_ollama_failure.py::test_ollama_unavailable_is_error_after_invocation` (real `OllamaClient` against `http://127.0.0.1:1`) |
| SECURITY PROPERTY | After ALLOW, a started generate that fails is ERROR, not DENY, not prevented. `executed=true` means the call began. |
| EXPECTED RESULT | `llm.started` and `llm.failed`; attempted=true; executed=true; outcome=error; spy call count 1; no `llm.completed` |
| ACTUAL RESULT | Real client was invoked once and returned `connection_error`. Events matched the contract. Control decision remained ALLOW. |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Events in that test |
| LIMITATIONS | Uses an unreachable URL, not a hanging live daemon. Timeout path is unit-covered via stub `error_type`. |

### TEST 7b — Live Ollama success

| Field | Content |
|-------|---------|
| TEST | `tests/integration/test_ollama_live.py::test_live_ollama_benign_baseline_when_available` |
| SECURITY PROPERTY | LIVE execution uses the configured Ollama client. Success must not be faked. |
| EXPECTED RESULT | If Ollama is healthy: four live generates and `completed_allowed`. If not: skip (not pass). |
| ACTUAL RESULT | 2026-09-10: SKIPPED (Ollama not reachable). 2026-09-11: **PASSED** — `.venv/bin/python -m pytest tests/integration/test_ollama_live.py -v` (1 passed). Separate HTTP `/process` BASELINE also completed four live hops. |
| PASS/FAIL | **PASS** (2026-09-11 live). Prior skip is historical, not the current claim. |
| EVIDENCE LOCATION | HTTP pack `artifacts/3367455f-e69a-4d60-bbe0-3de207aefcd9/` |
| LIMITATIONS | Live wording is nondeterministic. This still does not validate Splunk. |

---

## TEST 8 — `run.id` server ownership

| Field | Content |
|-------|---------|
| TEST | `tests/security/test_untrusted_json_cannot_bypass.py::test_http_cannot_skip_control_or_set_closed_fields` |
| SECURITY PROPERTY | Client `run.id` / `agentsec.run.id` cannot become the run identifier. |
| EXPECTED RESULT | Extra fields ERROR; minted UUID ≠ client UUID |
| ACTUAL RESULT | HTTP 400; `run_id != 00000000-0000-0000-0000-000000000099` |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Events for the minted run in that test |
| LIMITATIONS | Extra closed fields are rejected (ERROR), not silently ignored. |

---

## TEST 9 — `security.profile` server ownership

| Field | Content |
|-------|---------|
| TEST | `tests/security/test_untrusted_json_cannot_bypass.py::test_client_cannot_set_security_profile_via_valid_body` and extra-field test |
| SECURITY PROPERTY | Profile comes from lab config. Attacker JSON cannot set it. |
| EXPECTED RESULT | Events `security.profile=defended` when config is defended; `security.profile` in JSON is unknown field → ERROR |
| ACTUAL RESULT | Clean ATK-002 body still defended. Extra profile fields rejected. |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Stored `/api/v1/runs/<id>` events |
| LIMITATIONS | Operators switch profile with `AGENTSEC_SECURITY_PROFILE`. |

---

## TEST 10 — Experiment-label server ownership

| Field | Content |
|-------|---------|
| TEST | Extra-field test; `test_benign_http_is_baseline_and_server_mints_run_id`; `test_retest_label_is_server_owned` |
| SECURITY PROPERTY | Client cannot set `testbed.mode`, `execution.mode`, or `telemetry.fidelity`. First-lab emissions are LIVE / OBSERVED. |
| EXPECTED RESULT | Client BASELINE/SIMULATED/SYNTHETIC ignored (rejected). Server emits BASELINE for benign, ATTACK for catalog ATK-002, RETEST when env override is set. Always LIVE + OBSERVED. |
| ACTUAL RESULT | Extra dimension fields → ERROR. Benign HTTP → BASELINE. ATK-002 HTTP → ATTACK. Env RETEST → RETEST. All events LIVE/OBSERVED. |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Event fields in those tests |
| LIMITATIONS | Auto ATTACK vs BASELINE is catalog-payload classification, not a client field. RETEST requires operator env (or an in-process pipeline argument). |

---

## TEST 11 — Sequence ordering

| Field | Content |
|-------|---------|
| TEST | `tests/telemetry/test_sequence_and_correlation.py::test_sequence_is_unique_and_increasing` |
| SECURITY PROPERTY | `agentsec.sequence` unique and increasing within a run (V-SEQ) |
| EXPECTED RESULT | sequences == `1..n` |
| ACTUAL RESULT | Held for ATK-002 deny sequence |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Events in that test |
| LIMITATIONS | Ordering is per-process emitter, not a distributed clock. |

---

## TEST 12 — `incident.id` = `run.id`

| Field | Content |
|-------|---------|
| TEST | `tests/telemetry/test_sequence_and_correlation.py::test_incident_id_equals_run_id_on_every_event` |
| SECURITY PROPERTY | First lab: investigation id equals run id on every event (V-INC) |
| EXPECTED RESULT | Every event `incident.id == run.id` |
| ACTUAL RESULT | Held for four-hop BASELINE |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Events in that test |
| LIMITATIONS | No multi-stage kill-chain incident in this slice. |

---

## TEST 13 — Delegator attribution

| Field | Content |
|-------|---------|
| TEST | `tests/telemetry/test_sequence_and_correlation.py::test_delegator_absent_on_hop_zero_required_later` |
| SECURITY PROPERTY | Hop 0 has no delegator. Hop index ≥ 1 requires prior coded agent id. In-process attribution, not A2A. |
| EXPECTED RESULT | Hop 0 events omit `delegator.agent.id`. Hops 1–3 include it. |
| ACTUAL RESULT | Held |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | Events in that test |
| LIMITATIONS | String handoff remains untrusted data. This field is not a cryptographic passport. |

---

## TEST 14 — Schema validation for every emitted event

| Field | Content |
|-------|---------|
| TEST | `tests/telemetry/test_security_event_schema.py::test_every_emitted_event_matches_schema` (emitter also validates before sink) |
| SECURITY PROPERTY | V-SCHEMA: name/version 1.0.0; closed additionalProperties; no predecessor event names |
| EXPECTED RESULT | All emitted events validate; `prompt_attack` name rejected by schema |
| ACTUAL RESULT | BASELINE and RETEST streams validated. Predecessor name mutation failed schema. |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | In-memory events; schema file `schemas/security_event.schema.json` |
| LIMITATIONS | Schema was not weakened to make tests pass. |

---

## TEST 15 — Evidence bundle creation

| Field | Content |
|-------|---------|
| TEST | `tests/unit/test_evidence.py::test_evidence_bundle_has_required_files_and_honest_export` |
| SECURITY PROPERTY | INV-007 local pack exists even without Splunk. Export file must not fabricate HEC/Splunk success. |
| EXPECTED RESULT | `manifest.json`, `events.jsonl`, `request.json`, `result.json`, `export.json`, `limitations.json`; `splunk.validated=false`; export note NOT VERIFIED |
| ACTUAL RESULT | All six files written. Export recorded `splunk.attempted=false`, `splunk.verified=false`. |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | pytest tmp artifacts asserted by that test |
| LIMITATIONS | Pytest deletes tmp_path after the test. Lab operators see durable files under `artifacts/<run-id>/` when they call `/process` outside pytest. |

---

## TEST 16 — No full prompt stored by default

| Field | Content |
|-------|---------|
| TEST | `tests/unit/test_evidence.py::test_evidence_does_not_store_full_prompt_by_default` |
| SECURITY PROPERTY | Default content is preview ≤200 + SHA-256 hash. No `gen_ai.input.messages`. |
| EXPECTED RESULT | Input longer than 200 chars is not stored whole in `request.json` or `events.jsonl` |
| ACTUAL RESULT | Full long input absent; preview length ≤200; hash matches full text |
| PASS/FAIL | **PASS** |
| EVIDENCE LOCATION | That test’s tmp bundle |
| LIMITATIONS | Payloads ≤200 characters appear in full in the preview by definition. |

---

## Additional executed checks

| Check | Result |
|-------|--------|
| Attack Service posts only `input` + `user_id` to `/process` | PASS (`test_attack_service_posts_atk002_into_acmebank`) |
| Schema rejects DENY + `operation.executed=true` | PASS |
| Investigation question fields map to schema properties | PASS |
| `python3 -m compileall -q src tests` | PASS (via `.venv/bin/python -m compileall`) |

No ruff/mypy configuration exists in this repository. None was installed.

---

## Live HTTP observation (2026-09-11)

AcmeBank `POST /process` on `127.0.0.1:5000` with `OllamaClient` → `http://127.0.0.1:11434` model `llama3.2:1b`. OTEL off. Splunk not started.

| Experiment | run.id | terminal | llm.invoked | Evidence |
|------------|--------|----------|-------------|----------|
| BASELINE ATK-001 defended | `3367455f-e69a-4d60-bbe0-3de207aefcd9` | `completed_allowed` | 4 | `artifacts/3367455f-e69a-4d60-bbe0-3de207aefcd9/` |
| ATTACK ATK-002 defended | `9bdb542c-65ed-4c12-bf08-071a5275385d` | `completed_denied` | 0 | `artifacts/9bdb542c-65ed-4c12-bf08-071a5275385d/` |

BASELINE events (22): `run.started` → four× (`hop.started` → ALLOW control attempted=false/executed=false → `llm.started` executed=true → `llm.completed` outcome=success → `hop.completed`) → `run.completed`. `incident.id=run.id`. Hop 0 has no delegator; hops 1–3 do.

ATTACK events (6): DENY attempted=false executed=false outcome=prevented → `pipeline.stopped` → `run.completed` `completed_denied`. Zero `llm.*`.

`export.json` on both packs: `splunk.attempted=false`, `splunk.verified=false`.

---

## Overall

Stub/security proofs passed. Live `/process` → real Ollama → events → `artifacts/<run-id>/` was **observed** on 2026-09-11. Splunk was **not started**.
