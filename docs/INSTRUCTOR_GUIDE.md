# Instructor guide

Learners work in one app: the React Academy at `https://localhost/learn` (installer and HTTPS gateway; see the [installation guide](INSTALLATION_AND_DEPLOYMENT.md)). Sections below that mention `lab-up.sh`, direct ports or the Splunk Academy Home describe the legacy flow ([legacy multi-port flow](LEGACY_MULTI_PORT_FLOW.md), [legacy guide](LEGACY_SPLUNK_ACADEMY_GUIDE.md)), which is not the supported path. The React Academy workshop flow is the section titled "Workshop flow with the EVAL, Risk and Governance Centers (v1.2.0)".

This is not a hidden privileged learner mode. Instructors use the same Attack Service and Academy.

## Before a workshop

Legacy `lab-up.sh` steps (not the supported path; keep for the old flow only; the supported steps are in step 5 and the installation guide):

1. `./scripts/lab-preflight.sh`
2. `cp .env.example .env` if needed (do not share real secrets; lab defaults are localhost-only)
3. `./scripts/lab-up.sh` (or `--build` if images may be stale)
4. `./scripts/lab-ready.sh`
5. Browser: the React Academy at `https://localhost/learn` (start here; behind the gateway the legacy direct address `http://127.0.0.1:5001/learn` does not answer). Investigation happens inside the Academy (Investigate notebook, Security Assurance); Splunk Web is an optional Advanced view. Run `./agentsec splunk-access --check` first so the notebook can search.
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

- Path A is the search (the notebook's fixed-template search, or Splunk Search in the legacy flow); Path B is a review key (Studio may show Path B without a click — known limitation)
- Splunk is not the PDP
- ATTACK overlay must not be described as RETEST
- Missing evidence ≠ blocked
- Historical official run.ids are REPLAY/historical, not this student’s LIVE launch

## Remaining instructor-only assumptions (honest)

- Docker resource sliders on Docker Desktop are not documented as a product setting
- First-boot time varies; 10–20 minutes is observed, not guaranteed
- This Phase 17D environment was **not** a clean-room VM; REPLAY specimens may already exist on the instructor’s Splunk volume and may be absent on a student’s first Splunk


## Workshop flow with the EVAL, Risk and Governance Centers (v1.2.0)

### Suggested flow (about 90 minutes)
1. 10 min: the AcmeBank scenario and the Learn tab of LAB-MCP-003.
2. 20 min: learners predict and reveal the recorded packet in LAB-HITL-APPROVAL (Practice tab), then read its Prove tab.
3. 20 min: investigation of the same runs in the Academy's Investigate notebook (Splunk Web only as an optional Advanced view).
4. 20 min: EVAL Center, reading findings and the limitations of a single run.
5. 20 min: Risk Center, each learner drafts one assessment; compare judgments.

### Discussion prompts
- What does a recorded run prove, and what can it not?
- Where did your risk judgment come from, and what evidence was missing?
- Does a framework relationship mean the control works? (No: see the [Governance guide](GOVERNANCE_GUIDE.md).)

Risk drafts are local, unapproved learning artifacts, not authoritative records.
