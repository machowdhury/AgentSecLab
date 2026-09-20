# Guided investigation (LAB-PI-001)

## WHAT IS IT?

A reusable investigation object plus a Dashboard Studio HUNT tab that offers two paths: try the hunt yourself, or reveal a solution cell.

## WHY DOES IT EXIST?

Phase 14B could launch a live run and hand off Search. Learners still needed a notebook-like sequence: question → attempt → hint → solution SPL → result → meaning → limitation.

## HOW DOES IT WORK?

Metadata lives in `investigations.json`. It is not policy. Studio binds existing Q-* hunts. Path A is Splunk Search. Path B is a stacked solution cell plus a bound REPLAY table. Fresh LIVE `run.id` is not written into Studio tokens. Studio 10.2 hide/show overlapped Path B onto the question origin, so this lab does not use visibility tokens.

## WHERE DOES IT SIT IN AGENTSEC?

Inside LAB-PI-001 tabs LEARN → PROVE. Instructional beats PREDICT / HINT / SOLUTION do not become new global navigation.

## WHAT IS THE TRUST BOUNDARY?

Untrusted input still meets CTRL-INPUT-001 in AcmeBank. Splunk observes. Attack Service remains an untrusted client.

## WHAT COULD AN ATTACKER CONTROL?

The catalog payload already allowlisted. Not Studio tokens, not SPL, not grants.

## WHAT CAN GO WRONG?

Treating Path B tables as the live launch. Treating empty Splunk as DENY. Treating HEC 200 as EVIDENCE READY. Using custom JS to stuff a UUID into Studio.

## WHAT TELEMETRY SHOULD EXIST?

The same 1.9.0 events as LAB-PI-001. Guided cells do not emit new event names.

## HOW WILL SPLUNK SHOW IT?

Path A: learner Search. Path B: Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-EXECUTED, Q-LLM-AFTER-DENY.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001 / `AGENTSEC_SECURITY_PROFILE`. Not the investigation JSON.

## WHAT TEST PROVES THE LOGIC?

Offline: investigation loader + Studio definition tests. Live: restaged 1.9.0 specimen searchable in Splunk. UI review: Playwright screenshots.

## What I should now be able to explain

1. Why Path A must not be replaced by Path B.
2. Why Investigate specimen is REPLAY, not the fresh LIVE id.
3. Why HUNT is a stacked notebook instead of Studio hide/show.
4. Why `run.id` is the correlation key.
5. Why DENY is not proof of non-execution by itself.
6. Why missing `llm.*` is not blocked.
7. Why Splunk is not the enforcement point.
8. Why BASELINE is not SAFE.
9. Why HEC success is not EVIDENCE READY.
10. How the same SOURCE → BOUNDARY → REQUEST → AUTHZ → EXECUTION → TELEMETRY loop will apply to later labs without teaching those labs yet.
