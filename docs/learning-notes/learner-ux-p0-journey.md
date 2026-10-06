# Learning note: Phase 1 learner-UX P0 (journey, deep link, evidence source)

## Simple version

A lab teaches only if the screen does not give away the answer and does not
teach a false idea. P0 made the LAB-MCP-001 screens say three things clearly:
where you are, which evidence you are reading (your LIVE run or a recorded
REPLAY), and that a decision is not the same as an action.

## Technical depth

- **Deep link.** The Workbench builds a Dashboard Studio URL with
  `form.live_run_id=<run.id>` so the notebook opens on the learner's run. The
  value ends up in a Studio token that is substituted into SPL, so only a
  canonical lowercase UUID is accepted. The token name and tab come from fixed
  tables; no caller input is forwarded. The `form.` prefix was observed to work
  and the unprefixed form was observed to be ignored. It is not in Splunk's
  documentation, so it is classed SUPPORTED WITH CONSTRAINTS and the manual paste
  stays as a fallback.
- **LIVE vs REPLAY.** Selecting evidence does not run an experiment. REPLAY is
  recorded evidence from earlier validation and must never be presented as a new
  measurement.
- **Spoiler control (O1).** After ATTACK the page says "experiment complete" and
  points to the evidence. The launcher's decision and execution fields are
  collapsed, because reading them first turns an investigation into a lookup.
- **Prediction.** Two questions, because the control decision and downstream
  execution are different facts: ALLOW / DENY / ERROR / UNSURE, and YES / NO / UNSURE.
- **Diagram.** CTRL-MCP-001 sits before the handler; a DENY or ERROR stops the
  path. Splunk is drawn dashed because it observes and does not decide.
- **Trust boundary and attacker control.** The browser can influence only the
  run.id it carries in a link, which is validated. The profile, grants and policy
  stay server-owned.

## Telemetry and Splunk

No telemetry was added. Schema 1.9.0 and ExternalEvidence 1.0.0 are unchanged.
The notebook still reads the same indexed events; what changed is how the
learner is guided to them.

## What could still go wrong

Studio panel heights were not measured on a deployed page, so text may clip.
The deployed deep link behavior of this build was not tested.

## What I should now be able to explain

1. Why must the deep link accept only a UUID before it reaches a Studio token?
2. Why is `form.live_run_id` "supported with constraints" and not "supported"?
3. What is the difference between LIVE and REPLAY evidence, and why must REPLAY never be called a new measurement?
4. Why is the launcher result collapsed after ATTACK?
5. Why are control decision and execution predicted as two separate questions?
6. Why does a DENY in the diagram end the path, and what does the dashed Splunk node mean?
7. Why can the journey strip not mark INVESTIGATE as done?
8. Why did the app build go from 4 to 5 when only a diagram changed?
