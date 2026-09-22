# Phase 16D Splunk learning validation

**Pytest does not prove live Splunk, rendering, or detector effectiveness.**

Search remains the notebook. 16D did not replace investigations with dashboards and did not add Q-* or DET-*.

---

## Bootcamp (P1 L0, on Home SPLUNK)

Teaches only what AgentSec labs require:

1. `index=agentsec_telemetry sourcetype=otel:agentic:json`
2. Quoted `agentsec.run.id` (not `index=*`)
3. Sort `agentsec.sequence` ( `_time` is not authority)
4. `event.name` = evidence-plane clue
5. `agentsec.control.id` / `.decision` / `.reason`
6. Execution events (`llm.started` / `mcp.started`) separately from ALLOW

`run.id` correlates one experiment. Completeness is local count vs `dc(_raw)` on a complete copy. One field does not prove the whole outcome.

This is not a full SPL course. It follows `docs/AGENTSEC_SPLUNK_SKILL_PROGRESSION.md` stages Find a run → Timeline → Control decision.

---

## Path A / Path B

LIVE labs: stacked notebook. Question → Search → Hint 1 → Hint 2 → optional solution SPL + bound REPLAY table.

Capstone: Path B language is **review key**, not the default path.

REPLAY labs: no Attack Service. HUNT banner: copy Investigate specimen run.id, construct the hunt, then read bound tables as Path B.

Path B is not an authorization gate. Splunk does not enforce.

---

## What 16D did not change

- Hunt files (Q-*)
- DET-MCP-001 (still the only packaged detector; disabled; DENY-then-start)
- Token binding (bind-only; no custom JS)
- Fresh LIVE run.ids still hand off to Search
- Memory still needs WRITE and RECALL ids
- Capstone still needs retrieve / write / recall ids

---

## Honest limits

A bound Studio table is a REPLAY or official-pack example. It is not the learner’s latest Attack Service UUID unless they happen to match. Missing rows are not SAFE. HEC 200 is not searchable completeness.
