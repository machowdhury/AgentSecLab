# Phase 15C — LIVE vs REPLAY (Memory)

**LIVE EXPERIMENT:** Attack Service `POST /api/launch` mints a fresh WRITE `run.id` and a later RECALL `run.id`. The learner copies both and hunts in Splunk Search.

**REPLAY SPECIMEN:** Canonical Phase 11C Investigate dropdown ids. Never relabel those as a fresh LIVE launch.

REPLAY (canonical Investigate):

- BASELINE write `a8407246-7992-4ad8-bd02-cb701e150f30` / recall `914c41ce-5123-49eb-892c-c948295dbc46`
- ATTACK write `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` / recall `b8737cd9-9b6b-48f2-acfa-178ae1446ddc`
- RETEST write `060a0a72-ceb5-4b99-8330-98de81d8ae5e` / recall `5d5b9d1b-092d-4ddb-8422-4092d289cd49`

Official LIVE four-run pair (MEASURED; not Investigate tokens):

- ATTACK write `ad850327-07c8-4b2d-b817-6c1bc964b41c` / recall `e686da75-64c0-41a3-9bde-c932d268ed28`
- RETEST write `a3ae94ba-0ffc-4838-912a-c90bef331b16` / recall `87bd07c5-324d-40fb-b3be-797763877095`

Never paste those LIVE UUIDs into Studio as if they were the REPLAY dropdown. Never label the Phase 11C ids as a fresh LIVE launch. Details: `docs/PHASE15C_SPLUNK_LIVE_VALIDATION.md`.
