# Instructor guide

This is not a hidden privileged learner mode. Instructors use the same Attack Service and Academy.

## Before a workshop

1. `./scripts/lab-preflight.sh`
2. `cp .env.example .env` if needed (do not share real secrets; lab defaults are localhost-only)
3. `./scripts/lab-up.sh` (or `--build` if images may be stale)
4. `./scripts/lab-ready.sh`
5. Browser: the React Academy at http://127.0.0.1:5001/learn (start here); the original Splunk Academy Home is the legacy path. Attack Service http://127.0.0.1:5001, Splunk Search
6. Confirm ATLAS qualifier **REQUIRES REVALIDATION** on Attack Service (proves current UI)
7. Explain LIVE vs REPLAY ([LIVE_VS_REPLAY.md](LIVE_VS_REPLAY.md))
8. Recommended first lab: Direct Prompt Injection LIVE ATTACK, copy run.id, Path A
9. L5 Capstone (Lending Assistant Investigation) only after L1–L3 LIVE. It is the last LIVE launcher. Then the Splunk Defender Bridge (REPLAY / static, not a new level and not an eighth LIVE lab), then L6–L10. L10 is the Advanced Capstone (MASTER-2026-001), a REPLAY investigation. Mastery Check is the optional unscored self-check, not L5 and not L10.
10. Debrief limitations ([KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md))

## Reset between demos

- Soft: `./scripts/lab-down.sh` (pauses; nothing is removed) then `./scripts/lab-up.sh` if services wedged
- Runtime memory: recreate AcmeBank
- Do not FULL RESET (`down -v`) unless you accept wiping Splunk history used for REPLAY teaching on that volume

## Teaching points

- Path A is Search; Path B is a review key (Studio may show Path B without a click — known limitation)
- Splunk is not the PDP
- ATTACK overlay must not be described as RETEST
- Missing evidence ≠ blocked
- Historical official run.ids are REPLAY/historical, not this student’s LIVE launch

## Remaining instructor-only assumptions (honest)

- Docker resource sliders on Docker Desktop are not documented as a product setting
- First-boot time varies; 10–20 minutes is observed, not guaranteed
- This Phase 17D environment was **not** a clean-room VM; REPLAY specimens may already exist on the instructor’s Splunk volume and may be absent on a student’s first Splunk


## Workshop flow with the EVAL, Risk and Governance Centers (development branch)

### Suggested flow (about 90 minutes)
1. 10 min: the AcmeBank scenario and the Learn tab of LAB-MCP-003.
2. 20 min: learners predict and reveal the recorded packet in LAB-HITL-APPROVAL (Practice tab), then read its Prove tab.
3. 20 min: Splunk investigation of the same runs.
4. 20 min: EVAL Center, reading findings and the limitations of a single run.
5. 20 min: Risk Center, each learner drafts one assessment; compare judgments.

### Discussion prompts
- What does a recorded run prove, and what can it not?
- Where did your risk judgment come from, and what evidence was missing?
- Does a framework relationship mean the control works? (No: see the [Governance guide](GOVERNANCE_GUIDE.md).)

Risk drafts are local, unapproved learning artifacts, not authoritative records.
