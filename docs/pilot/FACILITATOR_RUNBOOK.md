# Facilitator runbook (one page): Loan Desk pilot

Status: NOT CONDUCTED. Allow about 60 minutes per participant: 10 setup, 25 to 40 mission (author estimate, unmeasured), 10 feedback. One participant at a time, at the lab Mac.

**Before the day:** read `README.md` (success criteria are fixed). Print or open `OBSERVATION_LOG.md`, `SCORING_SHEET.md`, `FEEDBACK_QUESTIONNAIRE.md` per participant. Get consent for any recording.

**Before EVERY participant (10 min)** run `docs/PILOT_LAUNCH_CHECKLIST.md`, all 8 steps: `learner_ready.py` 28/28, model warm-up (within 5 min of hand-over: `ollama run llama3.2:latest "Reply with OK"`, then `ollama ps`), Splunk login (`SPLUNK_LOGIN_PROCEDURE.md`), verifier `running`, browser reset (close tab, new tab, `/academy/path`, Reset browser progress). Any failure = NO-GO.

**Read aloud (disclosures):** a small 3B model drives the agent and results vary; the hardened run sometimes does not finish; SPLUNK-VERIFIED means recorded events equal indexed events, not that they are true; older labs are labelled REPLAY (September recordings); the time estimate is unmeasured; synthetic data only; you are testing the lab, not the participant.

**During (you observe, you do not teach):**
1. Start the log (`OBSERVATION_LOG.md`): participant code P1 to P5 (no names), date, start time.
2. Say only: "Work through the mission on the page. Think aloud. I will only step in if you are stuck or something breaks."
3. Note the time each step (Understand, Explore, Predict, Attack, Observe, Investigate, Defend, Retest, Compare, Explain) is reached.
4. **Intervene only when stuck 3 minutes or something breaks, and log every intervention** (tier 0 environment, 1 wording, 2 hint, 3 answer or you did it). Never name the proposal / policy-decision / executed-action answer.
5. Environment faults: use the table in the checklist ("While the session runs"). Do not restart AcmeBank mid-session.

**After the mission (do not teach first):** score `SCORING_SHEET.md` Q1 to Q6 from what they say, then hand over the questionnaire. After that you may explain the answers.

**After EVERY participant (5 min):**
1. Write the attack and retest run ids from the page into the log.
2. Evidence check (S4): in Splunk run `index=agentsec_telemetry "agentsec.run.id"="<run id>" | stats count` for both ids. Count must be greater than 0 and equal what the page showed. Any SPLUNK-VERIFIED badge without events is a stop-the-pilot finding.
3. Close the participant tab; do not stop the lab between sessions. Delete recordings per consent.
4. Fill the participant row in `RESULTS_TEMPLATE.md`.

**Stop the pilot if:** the page shows evidence that Splunk does not contain (S4); a participant is blocked by accessibility (S3) and no workaround exists; the lab needs a restart from `develop` (recover with `python3 scripts/deploy_acmebank_attack.py deploy` between participants, not during).
