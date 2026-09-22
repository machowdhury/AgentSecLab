# AgentSec attack learning experience (Phase 17B)

Attack Service is a closed educational launcher. It is not a grant console.

## Before launch

The page must already answer:

- What are you about to run?
- Why?
- What does the attacker control? (specimen bytes only)
- What does the attacker not control? (profile, grants, policy)
- What does the server own?
- What do you predict?
- What evidence should appear?

Then launch.

## After launch

- Fresh run.id (or write/recall, or retrieve/write/recall)
- Evidence state: LAUNCHING → TELEMETRY SENT → WAITING FOR SPLUNK → EVIDENCE READY
- Copy run.id
- Wait until EVIDENCE READY
- Open Search
- ATTACK vs RETEST comparison in this browser session when both exist

HTTP 200 is not evidence ready. HEC accepted is not searchable. WAITING is not attack failed.

## What the learner never chooses

Profile, allowed tools, scopes, overlay, coded policy. Those stay server-owned.

## Two-run and three-run labs

Memory: WRITE run persisted the bytes; RECALL run is where authorization and execution evidence live.

Capstone: retrieve, write, and recall are independent run.ids. The experiment is not EVIDENCE READY until all required ids are searchable.

## After the last LIVE launcher

Capstone is the last LIVE launcher. Next is Mastery Check (reasoning), not another attack.
