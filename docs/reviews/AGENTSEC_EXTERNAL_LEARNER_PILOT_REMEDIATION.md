# External learner pilot remediation

External evaluator: Claude, acting as a learner against a remote AgentSec deployment.

External verdict recorded here: **CONDITIONAL PASS**.

This note records that one tested path. It is not universal correctness, not production security, not complete attack coverage, not WCAG compliance, and not a resource-impact proof.

## Observed LIVE path

The evaluator reported a genuine LIVE ATTACK / RETEST pair. The run identifiers below are the prefixes supplied with that report. The full UUID strings were not included in the remediation request, so they are not reconstructed.

ATTACK prefix `ad9673e9-`:

- 22 events
- `security.profile=vulnerable`
- `outcome=completed_allowed`
- `control.decision=ALLOW`
- `attempted=false` and `executed=false` on the control-decision event
- separate `llm.started` / `llm.completed` events
- `attempted=true` / `executed=true` on execution events

RETEST prefix `2f2c81ee-`:

- exactly 6 events
- `testbed.mode=RETEST`
- hop-0 DENY
- `reason=input_pattern_matched`
- `attempted=false` and `executed=false`
- no LLM execution events
- terminal `completed_denied`

The evaluator reported that this matched the documented ATTACK/RETEST contract. That contract was not changed in this remediation.

The teaching distinction under test is: authorization is not execution.

## What this remediation changed

- Learner-facing Splunk links no longer use `http://127.0.0.1:8000`. Search links are relative Academy paths. Attack Service links go through `open_attack`, which uses the browser hostname and port 5001.
- Attack Service search handoff uses the hostname from the browser request, on port 8000.
- Precheck reports free disk, memory when the host exposes it, and Docker storage when `docker system df` works. It does not delete Docker data.
- The Attack Service launcher labels run start, acceptance, progress, completion, denial, failure, timeout, and backend unavailability. Timeout is not a DENY.

## Accessibility recheck

| Check | Result |
|-------|--------|
| 1920, 1440, 1280, 1024 | NOT TESTED in this session. Splunk was not driven at those widths. |
| 200% zoom at 1024 | NOT TESTED |
| Keyboard on Attack Service buttons | Native `button` elements. Enter and Space activate a focused button in a normal browser. Arrow-key tab behavior inside Splunk Studio was NOT TESTED. |
| Visible focus | `src/agentsec/static/agentsec.css` defines `:focus-visible` for buttons, links, and inputs. A live focus check was NOT TESTED. |
| Screen reader | NOT TESTED |
| WCAG | No claim |

## Automation click finding

The report said a simulated automation mouse click did not register while a direct `.click()` did. Attack Service launch controls use a normal `click` listener and do not check `isTrusted`. A DOM `.click()` activates them. A mouse event that is not dispatched as `click` would not. That is classified **AUTOMATION-SPECIFIC / NOT REPRODUCED AS LEARNER DEFECT**. The UI was not redesigned for one automation framework.
