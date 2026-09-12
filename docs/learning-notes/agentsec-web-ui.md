# AgentSec Web UI (AcmeBank and Attack Service)

## WHAT IS IT?

The two Flask pages learners actually click: AcmeBank (home loan application) and the Attack Service (ATK-002 console). They now share one CSS file and one small JS helper so they look like the same product as the LAB-PI-001 Splunk workshop.

## WHY DOES IT EXIST?

A workshop that teaches Direct Prompt Injection fails if the bank looks like a CTF and the attack page is a single red button. The UI has to make **request vs control vs execution** obvious without changing those mechanics.

## HOW DOES IT WORK?

Simple picture:

1. AcmeBank collects loan text and POSTs `{input}` to `/process`.
2. Attack Service POSTs ATK-002 `{input, user_id}` to the same AcmeBank route.
3. The page maps `terminal` to READY / RUNNING / COMPLETED / DENIED / ERROR.
4. Extra Attack facts (`CONTROL DENIED`, `GOVERNED LLM EXECUTED`) are shown **only** when those fields exist on the JSON.

Shared files: `src/agentsec/static/agentsec.css`, `agentsec-ui.js`.

## WHERE DOES IT SIT IN AGENTSEC?

In front of the Phase 2A runtime. Splunk remains observe-only. These pages do not authorize.

## WHAT IS THE TRUST BOUNDARY?

Still `acmebank.http_api`. The Attack UI is an untrusted client. CSS cannot DENY a loan.

## WHAT COULD AN ATTACKER CONTROL?

Still `input` and `user_id` on `/process`. Not profile, not `run.id`, not tokens in the stylesheet.

## WHAT CAN GO WRONG?

Reading `llm_invocation` ERROR as DENY. Treating HTTP 200 from Attack as “the injection worked.” Treating `llm_call_count=0` in Splunk as prevention without local completeness. Restyling Splunk chrome and calling it this phase.

## WHAT TELEMETRY SHOULD EXIST?

Unchanged schema 1.0.0. The UI only displays `result_to_dict` fields.

## HOW WILL SPLUNK SHOW IT?

Unchanged LAB-PI-001. Hunt the `run.id` the page shows.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001 / `AGENTSEC_SECURITY_PROFILE` on AcmeBank. Not a button color.

## WHAT TEST PROVES THE LOGIC?

`tests/unit/test_web_ui.py` and `tests/unit/test_design_system.py` prove HTML/CSS contracts. `tests/integration/test_attack_service.py` still proves ATK-002 DENY semantics. Playwright screenshots prove what was on screen when captured.

## What I should now be able to explain

1. Why AcmeBank must not look intentionally vulnerable.
2. Why Attack Service is a console, not a red-button toy.
3. Why RUNNING must disable the primary action.
4. Why ALLOW is not execution on either page.
5. Why `llm_invocation` ERROR is not prevention.
6. Why Attack facts are omitted when the JSON lacks them.
7. Why the Attack target URL may be `http://acmebank:5000` in Docker.
8. Why shared CSS exists instead of two palettes.
9. Why this phase did not add attacks or detections.
10. What would still be missing if Ollama never returns COMPLETED.

COMPLETED was later OBSERVED with host Ollama (`fc7c5e9a-9078-459c-8a1b-488b740176aa`). Keyboard navigation was MEASURED in Playwright, not certified WCAG.
