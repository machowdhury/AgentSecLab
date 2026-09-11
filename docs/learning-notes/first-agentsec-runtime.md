# First AgentSec runtime

**Status:** Phase 2A slice IMPLEMENTED in code and stub/security tests. Live Ollama success SKIPPED in this validation run. Splunk export NOT ATTEMPTED.

## WHAT IS IT?

The smallest trustworthy AcmeBank runtime: `POST /process` runs four sequential in-process agents (intake → credit → risk → compliance). Before each Ollama call, **CTRL-INPUT-001** returns ALLOW, DENY, or ERROR. Telemetry is schema **1.0.0**. Each run writes `artifacts/<run-id>/`.

It is a learning range, not a production AI-security product.

## WHY DOES IT EXIST?

Architecture documents cannot prove INV-008. You need a path where malicious text is DENY **before** the model, with a server-minted `run.id` equal to `incident.id`, and where DENY is proven by a **spy on the LLM client**, not by “Splunk shows no llm events.”

## HOW DOES IT WORK?

1. A learner (or test) POSTs `{"input": "..."}` to AcmeBank `/process`. Optional `user_id` is a label only.
2. AcmeBank **rejects** unknown JSON fields (ERROR). Attackers cannot set `run.id`, profile, `testbed.mode`, control decisions, or operation flags.
3. The server mints `run.id` and sets `incident.id = run.id`, one `trace_id`, and experiment dimensions (`BASELINE` / `ATTACK` / `RETEST`, always `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED`).
4. For each hop: emit `hop.started` → evaluate CTRL-INPUT-001 → emit `control.decision`.
5. DENY or pre-invoke ERROR: `attempted=false`, `executed=false`, `outcome=prevented`. **No** `llm.*` child. Pipeline stops.
6. ALLOW: emit `llm.started` (`attempted=true`, `executed=true`), then call Ollama. Success → `llm.completed` outcome=success. Failure after the call began → `llm.failed` outcome=error (**not** DENY).
7. Write the evidence pack. `export.json` currently records that Splunk was not attempted.

Attack Service is a second Flask process that only POSTs the ATK-002 catalog string. It does not import the Ollama client.

## WHERE DOES IT SIT IN AGENTSEC?

This is LEARN → BASELINE → ATTACK → OBSERVE for the first slice. DEFEND is switching `AGENTSEC_SECURITY_PROFILE`. RETEST is the same payload after that change (`AGENTSEC_TESTBED_MODE=RETEST` or an in-process argument). HUNT/DETECT in Splunk is later.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.http_api` is where untrusted HTTP becomes a pipeline request. Authorization happens on the AcmeBank side **before** `acmebank.llm_call`. Ollama output is data. Splunk cannot ALLOW a loan. Four agents are one process — not A2A.

## WHAT COULD AN ATTACKER CONTROL?

The `input` string and optional `user_id` label. Catalog ATK-002 text is just input. They cannot set profile, ids, dimensions, or skip CTRL-INPUT-001.

## WHAT CAN GO WRONG?

- Regex gaps: a novel jailbreak may ALLOW. That is a real limitation of a reference control.
- `vulnerable` fail-open: labeled on purpose so learners can see INV-008 broken.
- Ollama down after ALLOW: `llm.failed`, outcome=error. That is not prevention.
- Control code throws: fail-closed ERROR, no LLM.
- Splunk down or unused: local artifacts still exist; do not treat missing Splunk `llm.*` as DENY.

## WHAT TELEMETRY SHOULD EXIST?

Only schema 1.0.0 names:

`run.started` / `run.completed` / `run.failed`  
`hop.started` / `hop.completed`  
`control.decision`  
`llm.started` / `llm.completed` / `llm.failed`  
`pipeline.stopped`

Do not emit `normal_request` or `prompt_attack`.

ALLOW on `control.decision` has attempted=false, executed=false, and **omits** outcome. That ALLOW is not proof the model ran.

## HOW WILL SPLUNK SHOW IT?

Not in Phase 2A. `export.json` says Splunk export has **not** been attempted / **NOT VERIFIED**. When ingest exists later, Splunk is corroboration only unless completeness for that `run.id` is established.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001 in `defended` DENYs ATK-002 before Ollama. The same payload in `vulnerable` ALLOWs with an explicit fail-open reason that names the lab reference control. Empty/malformed input is ERROR in both profiles.

## WHAT TEST PROVES THE LOGIC?

Critical negative: `tests/security/test_input_control_before_llm.py::test_defended_atk002_negative_contract` — DENY flags plus CountingLLM spy `calls == []`. Full table: `docs/PHASE2A_RUNTIME_VALIDATION.md`.

## What I should now be able to explain

1. Why DENY must happen before `llm.generate`, and why a spy is required in addition to missing `llm.*` events.
2. Why `operation.executed=true` means the governed call **began**, not that it succeeded.
3. Why Ollama failure after ALLOW is ERROR, not DENY, and not `outcome=prevented`.
4. Why `incident.id` equals `run.id` on every first-lab event.
5. Why hop 0 has no delegator and later hops must name the prior coded agent — without calling that A2A.
6. Why empty input is ERROR in `vulnerable` too (it is not the INV-008 demonstration).
7. Why unknown JSON fields are ERROR rather than ignored.
8. Why Splunk absence of `llm.*` is not prevention proof.
9. What CTRL-INPUT-001 is allowed to claim (lab reference) and what it must not claim (production IPS).
10. How BASELINE, ATTACK, and RETEST differ from `execution.mode=LIVE`.
