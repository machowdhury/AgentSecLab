# Phase 15D — LIVE vs REPLAY (Goal Integrity)

**LIVE EXPERIMENT:** Attack Service `POST /api/launch` mints a fresh `run.id`. The learner copies it and hunts in Splunk Search.

**REPLAY SPECIMEN:** Canonical Phase 13C Investigate dropdown ids. Never relabel those as a fresh LIVE launch.

REPLAY (canonical Investigate):

- BASELINE `0aced342-1295-4820-b807-9a8718d9e847`
- ATTACK `fd994587-7e1c-4a70-8013-54cb2c85254d`
- RETEST `605ba7c1-449b-4338-92df-7da3b704b08e`

Official LIVE pair (MEASURED; not Investigate tokens):

- ATTACK `dc1f549f-ea1f-4ac5-bc25-5d7cca5b1fe9`
- RETEST `624b4223-510e-4a14-88e2-85f82b32d475`

Never paste those LIVE UUIDs into Studio as if they were the REPLAY dropdown. Never label the Phase 13C ids as a fresh LIVE launch. Details: `docs/PHASE15D_SPLUNK_LIVE_VALIDATION.md`.
