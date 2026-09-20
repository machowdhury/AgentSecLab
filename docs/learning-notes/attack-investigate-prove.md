# Attack, investigate, prove

AgentSec already has labs and Splunk workshops. What it did not have, until this design, is an honest story for **doing** the attack and **doing** the hunt without turning Splunk into a video player.

This note is DESIGN only. Nothing launched a new specimen. Schema is still 1.9.0.

---

## Simple picture

You are not clicking “hack” inside Splunk.

1. You learn what property is being tested.
2. You predict what you should see.
3. If the lab is LIVE-capable, you launch an **allowlisted** specimen from the Attack Service (today: ATK-002 only).
4. The runtime mints a `run.id` and emits telemetry.
5. Transport (OTEL → HEC) may succeed while Splunk Search is still empty.
6. You investigate in Search (Path A) or reveal a teaching query (Path B).
7. You retest the **same** attack input with the defense isolated.
8. You prove what held — and say what you cannot prove.

Splunk is the SOC workbench. AcmeBank is the enforcement point. The Attack Service is an untrusted lab client.

---

## Why “guided” is not “give them the SPL first”

If the dashboard always shows the finished table, the learner never forms a question. Path A is: question, a few field hints, Open Search. Path B is a notebook-like cell: query, output, meaning, limits, next question.

Beginner / Intermediate / Advanced / Challenge are **how much hint** you get, not different security properties.

---

## Why HEC 200 is not “the attack is in Splunk”

HEC means the collector was allowed to POST. Searchable evidence means the index has the events for that `run.id`. AgentSec already treats `splunk.verified=false` until a search says otherwise. Phase 14A names that gap `WAITING_FOR_EVIDENCE` so we do not lie in the UI later.

---

## Why Studio will not grow a red Launch button that POSTs

Dashboard Studio can **link** to Search and **link** to the Attack Service. It does not call `/process`. Building custom JS so a Studio button fires attacks would make Splunk look like an exploit console and skip the trust boundary we already teach.

---

## LIVE, REPLAY, GUIDED

You can mix them. Canonical dropdowns are REPLAY. A new Attack Service click is LIVE. Showing solution SPL is GUIDED. A SIMULATED `makeresults` detector fixture is still SIMULATED.

Never caption a REPLAY table as “you just ran this.”

---

## What I should now be able to explain

1. Why AgentSec is not “just dashboards” and not “just an attack simulator.”
2. What stays on LEARN→PROVE vs what UNDERSTAND / PREDICT / CONNECT add.
3. Why Path A must happen before Path B.
4. Why Attack Service is untrusted relative to AcmeBank.
5. What an allowlisted launch request contains — and what it must not contain.
6. Why RETEST is not “whatever Splunk didn’t show.”
7. Why HEC health is not evidence readiness.
8. Why PI-001 is the recommended 14B reference instead of MCP-001.
9. Why no published workshop is LIVE READY or GUIDED READY today.
10. Why DET-MCP-001 still must not be cloned into a DET-GOAL “to finish the lab.”
