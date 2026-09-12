# LAB-PI-001 searches

Foundational investigation SPL for Direct Prompt Injection. Not detections. Bound into Dashboard Studio `ws_lab_pi_001` without rewriting the questions.

Replace `__RUN_ID__` with a concrete `agentsec.run.id` before running.

Validated 2026-09-11 against:

- BASELINE `b3611d56-0d3f-4b2e-9a51-75ae36628155`
- Vulnerable ATK-002 `f39fed12-de89-45ba-b684-5b6077942580`
- Defended ATK-002 `78f05d1b-728e-4e70-8993-f5e365871f87` (`ATTACK`)
- Defended ATK-002 RETEST `bbe75cb8-0190-47d6-86be-5feba58ad5c0`

Q-LLM-AFTER-DENY positive control is SIMULATED (`makeresults`, not indexed). See `Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl`.

Workshop: `../workshop.md`. Studio: `../dashboard.md`. See `docs/PHASE2C_SPL_VALIDATION.md` and `docs/PHASE2C3_DASHBOARD.md`.
