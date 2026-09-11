# Reference input control (CTRL-INPUT-001)

**Event/operation/dimension semantics:** `SECURITY_EVENT_MODEL.md` (Phase 1B) is authoritative. Existing `src/agentsec/` emitters are EXPERIMENTAL and may still use withdrawn event names.

## WHAT IS IT?

A small, lab-owned pattern check on untrusted text **before** the LLM is called. It is a teaching control, not a product IPS.

## WHY DOES IT EXIST?

INV-008: missing or hostile input must not fail-open in `defended`. Prompt injection is an input problem at the AcmeBank API, not a Splunk problem.

## HOW DOES IT WORK?

`inspect_input()` in `src/agentsec/controls.py` runs first in `run_loan_pipeline()`. Matches include “ignore previous instructions”, persona override, and “override the credit decision”. Decisions: ALLOW, DENY, ERROR. DENY never calls `llm.generate()`.

## WHERE DOES IT SIT IN AGENTSEC?

Enforcement zone, inside AcmeBank, ahead of Ollama. Attack Service cannot turn it off.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.http_api` for Intake; later hops also inspect handed-off text so prior-agent output cannot silently become a new instruction without a check.

## WHAT COULD AN ATTACKER CONTROL?

The payload string. Not `agentsec.control.decision`.

## WHAT CAN GO WRONG?

Regex gaps (a novel jailbreak may ALLOW — that is a real limitation). Vulnerable profile fail-open. Treating this regex as “Cisco” or “production AI security.”

## WHAT TELEMETRY SHOULD EXIST?

`agentsec.control.id=CTRL-INPUT-001`, `decision`, `reason`, `operation.attempted` / `executed` / `outcome`, `technique.id=AML.T0054` on ATK-002, `event.name=agentsec.control.decision`. Do not emit withdrawn names such as `agentsec.prompt_attack`.

## HOW WILL SPLUNK SHOW IT?

Hunt `testbed.mode=ATTACK` DENY with attempted=false, executed=false, outcome=prevented. Splunk absence of `llm.*` is corroboration only. Do not call that hunt validated until it is run in Splunk.

## WHAT CONTROL COULD CHANGE THE RESULT?

Switching `AGENTSEC_SECURITY_PROFILE` to `vulnerable` (labeled ALLOW). Output inspection is **not** in Phase 2 and must not be reported as DENY.

## WHAT TEST PROVES THE LOGIC?

Unit: `tests/unit/test_controls.py`. Security: `tests/security/test_input_control_before_llm.py` and `test_untrusted_json_cannot_bypass.py`.

## What I should now be able to explain

1. Why the check is before Ollama, not after.
2. Why DENY before invoke requires attempted=false, executed=false, outcome=prevented — and why a started LLM failure is executed=true, outcome=error.
3. Why a stub LLM is the right proof, not a live 1B model.
4. What `input_pattern_matched` means.
5. How fail-open is labeled in telemetry.
6. Why skip_control in JSON does nothing.
7. Why this is not MCP or A2A security.
8. What ATK-002 is for.
9. How evidence packs record expected vs actual.
10. What a regex control cannot promise.
