# Instructor guide

This is not a hidden privileged learner mode. Instructors use the same Attack Service and Academy.

## Before a workshop

1. `./scripts/lab-preflight.sh`
2. `cp .env.example .env` if needed (do not share real secrets; lab defaults are localhost-only)
3. `./scripts/lab-up.sh` (or `--build` if images may be stale)
4. `./scripts/lab-ready.sh`
5. Browser: Academy Home, Direct Prompt Injection, Attack Service http://127.0.0.1:5001, Search
6. Confirm ATLAS qualifier **REQUIRES REVALIDATION** on Attack Service (proves current UI)
7. Explain LIVE vs REPLAY ([LIVE_VS_REPLAY.md](LIVE_VS_REPLAY.md))
8. Recommended first lab: Direct Prompt Injection LIVE ATTACK, copy run.id, Path A
9. Capstone only after L1–L3 LIVE
10. Debrief limitations ([KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md))

## Reset between demos

- Soft: `./scripts/lab-down.sh` && `./scripts/lab-up.sh` if services wedged
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
