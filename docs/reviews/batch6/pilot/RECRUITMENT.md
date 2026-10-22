# Pilot recruitment package (Gate C)

**Status: NOT CONDUCTED. No participant has been contacted, recruited or observed.** Everything below is ready to use; none of it records a result.

## Participant mix (five)
| Slot | Who | Why |
|---|---|---|
| B1, B2 | **Beginners**: little or no knowledge of AI agents or security (for example a developer, analyst or product person from another area) | tests whether the page teaches the idea from zero |
| X1, X2 | **Experienced security practitioners** (appsec, SOC, red team, detection engineering) | tests whether the content is credible and whether the claims survive scrutiny |
| S1 | **Splunk practitioner** (admin, engineer or content author) | tests the evidence and investigation steps and the verification states |
If a slot cannot be filled, record it as NOT RECRUITED rather than substituting silently. If someone uses a keyboard only or a screen reader, prefer them for one slot and say so; otherwise record "accessibility participant NOT RECRUITED".
Exclude anyone who has seen AgentSecLab, worked on it or read its review notes.

## Invitation (send individually; do not mass-mail)
> Subject: 45 minutes to test a security training lab
>
> We are testing a hands-on lab that teaches how an AI agent can be tricked into filing attacker-written text, and how to stop it. It runs on a laptop with synthetic data only. You would work through it while thinking aloud; we are testing the lab, not you. It takes about 45 minutes plus a 5-minute debrief. We record your screen and voice only if you agree; we never record your name. You can stop at any time and ask for your data to be deleted.
> Reply with your availability. If you are happy to take part, we will send a two-question screening form first.

## Screener (answer is used only to assign a slot)
1. Which best describes your day job? (developer / security analyst or engineer / Splunk or observability / other: ____)
2. How familiar are you with AI agents (tools, function calling)? 0 never heard, 1 read about, 2 used, 3 built
3. How familiar are you with Splunk searching? 0 none, 1 have seen it, 2 write searches, 3 build dashboards or detections
4. Have you seen or worked on AgentSecLab? (yes disqualifies)
5. Do you use assistive technology we should prepare for? (optional)
Assignment: B = agents 0-1 and security not your job; X = security job and agents 1-3; S = Splunk 2-3.

## Consent (read aloud; keep the signed or recorded agreement apart from the results)
- Purpose: to improve a training lab; no assessment of you.
- What is recorded: screen and voice (optional), your answers, timings. No name, no employer, no real data.
- Data: stored under a participant id, deleted after scoring unless you agree to a quote; you may withdraw any time.
- Everything runs locally on synthetic data.

## Logistics
60 minutes per session, one participant at a time, facilitator and one observer. Sessions follow `FACILITATOR_GUIDE.md`; the stack is started and model-checked beforehand; a fresh browser profile each time.
Do not run two participants on the same lab state; reset the mission between sessions.

## Added measure (requested at Gate C): can the participant explain the independent enforcement boundary?
See prompt C6 in `COMPREHENSION_AND_RUBRIC.md`. It is asked last, after the participant has finished the mission and has not yet seen the feedback form.
