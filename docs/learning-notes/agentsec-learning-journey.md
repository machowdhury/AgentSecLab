# How to travel the AgentSec learning journey

**Status:** Phase 16C learning note. Design/audit only. Schema 1.9.0. Splunk is evidence, not the PDP.

AgentSec is a range where you attack controlled agent behaviors, watch real telemetry, and investigate in Splunk yourself. It is not a dashboard gallery and not a production AI-security product.

---

## WHAT IS IT?

A sequenced academy path over labs that already exist: seven LIVE Attack Service loops plus REPLAY workshops for grant anatomy, result trust, catalog, scanner, and confused deputy, ending in an integrated capstone.

## WHY DOES IT EXIST?

Individually validated labs can still feel like a pile of demos. The journey exists so you know where you are, what you are learning, and what “done” honestly means.

## HOW DOES IT WORK?

1. Read the mission / LEARN tab (trust boundary, PDP vs classifier).
2. Predict ATTACK.
3. Launch from Attack Service (server-owned profile; you do not choose grants).
4. Copy `run.id`(s). Wait for evidence — HTTP 200 is not Splunk.
5. Path A: construct SPL in Search.
6. Optional Path B: answer key, not policy.
7. Defend the actual PDP (usually remove a lab overlay; not “sanitize everything”).
8. RETEST the same bytes.
9. COMPARE and PROVE (SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT).

Studio = syllabus. Search = notebook. Runtime = enforcement.

## WHERE DOES IT SIT IN AGENTSEC?

Home should be the start (it is currently a stale directory — documented 16C P0). Nav groups Attack Labs, Context, Capstone, Agent Authority, Supply Chain. Attack Service lists the seven LIVE labs. Canonical map: `docs/AGENTSEC_CURRICULUM_MAP.md`.

## WHAT IS THE TRUST BOUNDARY?

Each lab names one. Across the academy: untrusted input, retrieved data, stored memory, tool requests, task/goal, identity claims. Authority still has to come from a coded control.

## WHAT COULD AN ATTACKER CONTROL?

In these labs: catalog strings, retrieved document bytes, memory bytes, instructions, delegation claims — never coded_policy() via the browser.

## WHAT CAN GO WRONG?

You may blame the wrong plane (RAG “granted” the tool; Splunk “blocked” RETEST; missing rows “prove” prevention; Goal/Identity “must have failed” because a tool ran).

## WHAT TELEMETRY SHOULD EXIST?

Schema 1.9.0 security events: run, control.decision, domain context, mcp/llm execution. Capstone uses three run.ids. Privacy: hashes and previews, not full bodies or secrets.

## HOW WILL SPLUNK SHOW IT?

Index `agentsec_telemetry`, sourcetype `otel:agentic:json`. Reuse Q-* hunts. Completeness is local count vs `dc(_raw)`. Detector DET-MCP-001 is narrow; 0 rows ≠ SAFE.

## WHAT CONTROL COULD CHANGE THE RESULT?

The lab’s PDP (CTRL-INPUT-001, CTRL-MCP-001, or CTRL-GOAL-INTEGRITY-001). Classifiers stay OBSERVE. Splunk does not change the result.

## WHAT TEST PROVES THE LOGIC?

Official LIVE pairs in 14E–16B docs (MEASURED there). Offline pytest does not prove Splunk. 16C adds academy consistency tests only.

---

## Suggested order (do not follow nav blindly)

PI → MCP-001 → (REPLAY 003/004) → RAG → Memory → (REPLAY 005/catalog/scanner) → Goal → Identity → (REPLAY MCP-006) → Capstone.

---

## What I should now be able to explain

1. Why MCP-001 comes before RAG and Memory even though RAG is “context.”
2. Why Home can be wrong while the capstone still PASSed as a lab.
3. What LIVE vs REPLAY means in this repository.
4. Why Path B must not replace Path A.
5. Which inequalities must stay repeated vs which belong in Level 0.
6. Why the capstone asks you to rule out Goal and Identity.
7. What an AgentSec graduate can and cannot claim.
8. Why 16C must not add DET-* or bump schema.
9. What P0 vs P3 means on the gap matrix.
10. Why learner time-to-investigate is not a SOC TTDR metric.
