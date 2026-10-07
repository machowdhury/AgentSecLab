# P1 Guided Academy Experience (LAB-MCP-001)

## Simple version

Before P1 the lab showed you everything at once: scope rules, SPL, run ids and
ten navigation words. P1 shows **one screen, one learning objective, one next
button**. You predict first, run the experiment, investigate the evidence, read
the defense, retest the same attack, then compare.

## What changed, and what did not

| Layer | Changed | Not changed |
| --- | --- | --- |
| Web app (`attack_mcp.html`, `agentsec-academy.css`) | Nine-step wizard; two independent prediction questions; short ATTACK screen; no outcome shown on completion | `POST /api/launch` closed body, CTRL-MCP-001 semantics, telemetry schema 1.9.0 |
| Splunk Studio (`ws_lab_mcp_001`) | START, INVESTIGATE (notebook), REFERENCE tabs | The exact validated SPL; visible SPL still equals executed SPL |
| Evidence | Baseline is shown as **REPLAY**; the notebook says **LIVE** or **REPLAY** | No new events or fields; the lab still has zero LLM events |

## Why each decision exists

* **Baseline is REPLAY only (D-1).** A live baseline would be new runtime
  evidence for no learning gain. The page states plainly that it is recorded.
* **Dropdowns, not radio buttons (D-2).** On the deployed Splunk 10.2 we observed
  that `input.radio` is not supported but `input.dropdown` is. We did not inject
  JavaScript or CSS to fake a control.
* **One journey (D-3).** Two competing navigations teach nothing. HUNT, DETECT and
  raw SPL moved to REFERENCE rather than being deleted.
* **Darker DENY text (D-4).** The old DENY text was 3.08:1 against its fill. The new
  value is 6.03:1. DENY is not green and not "secure"; ALLOW is not "safe".

## Trust boundary and attacker control

The browser holds only the learner's prediction (sessionStorage). It cannot grant
authority: the control decision comes from CTRL-MCP-001 in the attack service, and
the evidence comes from Splunk. The attacker-controlled input in the lab is the
requested tool name; nothing in the UI lets a learner change what the control
decides. A stale or forged run.id in a deep link only changes which indexed run the
notebook *reads*; it does not run anything.

## Telemetry and Splunk

No telemetry was added. The notebook reads existing indexed events:

* decision: `agentsec.control.decision`
* execution: `agentsec.mcp.started` / `agentsec.mcp.completed` (cell 2 never reads the decision)
* RETEST: `agentsec.pipeline.stopped`

## What each answer does and does not prove

ALLOW does not prove execution. DENY does not prove the system is secure. One
RETEST proves one retest, not universal security. An empty search result is
"not proven", not "safe".

## Tests that prove the logic

* `tests/unit/test_p1_web_experience.py`: wizard order, gating, no outcome leak, baseline REPLAY, locale-safe links.
* `tests/splunk/test_p1_studio_experience.py`: tabs, dropdown defaults, closed CHECK tables, visible equals executed SPL, REFERENCE keeps HUNT/DETECT.
* P0 assertions that changed carry a `CONTRACT CHANGE: P1 learner-experience redesign` block with old contract, new contract and why.

## What I should now be able to explain

1. Why is "ATTACK complete" a state transition and not a ninth navigation destination?
2. Why does the Studio notebook say LIVE or REPLAY, and which token decides it?
3. Why can ALLOW and "downstream execution" disagree, and which cell reads each?
4. Why were radio buttons not used, and what is the supported fallback?
5. Why is the sentinel value `none` used instead of an empty token?
6. What does the CHECK table compute, and why is it not a grade?
7. Why did the DENY text colour change, and how was the ratio measured?
8. What is the difference between a REPLAY baseline and a LIVE experiment as evidence?
9. Where did HUNT, DETECT and the raw SPL go, and why were they not deleted?
10. What does one successful RETEST not prove?
