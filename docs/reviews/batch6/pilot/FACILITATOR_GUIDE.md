# Facilitator guide

## Participants (5)
2 security analysts or SOC engineers; 2 developers or platform engineers; 1 keyboard-only or screen-reader user if one
can be recruited (otherwise record "accessibility participant NOT RECRUITED"). None may have seen AgentSecLab. Record
role and two familiarity scores (Splunk 0-3, AI agents 0-3). Participants are P1 to P5; never record names.

## Before each session (facilitator, 15 minutes)
1. `./scripts/lab-up.sh`, wait for READY. 2. `./scripts/loan_desk_verifier.sh status` must say running.
3. Open `http://127.0.0.1:5001/academy` in a fresh browser profile at 1280x800.
4. **Model readiness is part of the test:** with `llama3.2:latest` installed the first-run check must show both rows "Ready".
   If it does not, record it as a finding and fix it before the participant arrives; do not run the participant through your repair.
5. Reset the mission with the page's reset control, or use a new profile, so no earlier run is visible.
6. Recording only with written consent; otherwise notes only.

## What you say
Read the consent paragraph, then: "We are testing the lab, not you. Please think aloud. I will read each task; I
cannot help with how the lab works, but I can answer safety questions. You can stop at any time." Hand over the browser.

**Consent paragraph:** "This is a test of a security training lab. We record how you use it and what you say. We do not
record your name. You may stop at any point and ask for your data to be deleted."

## What you do not do
Explain terms, point at controls, or react to answers. After 3 silent minutes on one task offer one neutral prompt
("What would you try next?"). A second prompt is a logged hint. Mark any task completed after a hint as Pass-with-hint.

## Safety and data
Everything runs on synthetic data on localhost. If a participant types something that looks like real personal data,
stop, ask them to remove it, and note it (the page refuses real names, emails and ID numbers by design). Store sheets by
participant id only, delete recordings after scoring, and keep the consent record separate from results.

## Success thresholds (agreed before running)
At least 4 of 5 reach task 11 within 45 minutes; median total time within 30-45 minutes; no task blocks 2 or more
participants; at least 4 of 5 score 2 on the "blocked vs unfinished" prompt; mean ease >= 5 of 7 on every task, and any
task below 4 is redesigned; the accessibility participant completes every task or the barrier is logged as a P1 defect.
After a failed threshold: fix, then rerun with 3 new participants.
