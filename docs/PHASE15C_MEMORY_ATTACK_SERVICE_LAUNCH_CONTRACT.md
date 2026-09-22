# Phase 15C — Memory Attack Service launch contract

Closed catalog lab: `LAB-MEMORY-001`.

Runtime route: `memory_lifecycle` = `POST /memory/write` then `POST /memory/recall` with the same closed `{memory_id, user_id, experiment_id}`.

Browser selects only BASELINE / ATTACK / RETEST. Browser cannot send profile, grants, memory body, trust, allowed_tools, policy, identity, Python, shell, environment, or SPL.

## Before launch the page teaches

WHAT IS AGENT MEMORY, WHY ATTACK IT, WHAT THE ATTACKER CONTROLS, WHAT PERSISTS, WRITE RUN, RECALL RUN, TRUST BOUNDARY, VULNERABLE vs DEFENDED, WHAT SPLUNK SHOULD SHOW, WHAT NOT TO INFER, PREDICT BEFORE LAUNCH.

## Result UX

LIVE ATTACK / LIVE RETEST show:

- WRITE RUN uuid
- RECALL RUN uuid
- memory.id
- content fingerprint
- WRITE / RECALL / EXPERIMENT evidence states

Copy write run.id. Copy recall run.id. Open write in Search. Open recall in Search. Server-built compare handoff for the four-run set. No learner-supplied SPL. No Studio token writes from browser JS.

Primary `run_id` in the JSON is the recall UUID for generic compare-handoff lookup. Write id is also indexed on the launch record.
