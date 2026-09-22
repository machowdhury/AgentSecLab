# AgentSec capstone assessment

**Status:** IMPLEMENTED as Mastery Check PURPLE TEAM (Phase 17A). Uses existing `LAB-AGENTSEC-CAPSTONE-001`. No new attack. No DET-CAPSTONE.

## Gate before starting

The learner should already be able to name: trust boundary, PDP, `run.id`, control decision, execution evidence, ATTACK vs RETEST, SUPPORTED vs NOT PROVEN.

If not, take FOUNDATIONAL then PRACTITIONER first — or open Home ORIENT.

## Preferred path

PREDICT → launch LIVE ATTACK and RETEST in Attack Service → record retrieve / write / recall `run.id`s → Search → reconstruct → identify control → determine authorization → determine execution → compare → 15-point readout.

Path B on the capstone workshop is a **review key**. Mastery Check does not paste the full capstone solution first.

## REPLAY fallback

Official 16B recall ids (`2437f64a-…` ATTACK, `8d2c016f-…` RETEST) may be used. They are **REPLAY**. Never present them as a launch minted today.

## 15-point readout (not auto-graded)

1. Attack objective
2. Attacker-controlled input
3. Server-owned security configuration
4. Relevant trust boundaries
5. Relevant controls
6. Actual PDP
7. ATTACK authorization
8. ATTACK execution
9. RETEST authorization
10. RETEST execution
11. What remained identical
12. What changed
13. Why the outcome changed
14. What Splunk proves
15. What Splunk cannot prove

## Answer key (instructor / self-study)

- Attacker controls retrieved/memory fixture bytes. Not grants, tools, or profile.
- Server owns `allowed_tools`, overlays, document/memory bodies, ExperimentContext.
- RAG and memory **OBSERVE**. Tool PDP is **CTRL-MCP-001**.
- ATTACK recall: MCP overlay ALLOW, wrong-tool handler 1 (runtime authoritative).
- RETEST recall: MCP DENY `tool_not_granted`, handler 0.
- Same ungranted follow-on request. Different server-owned configuration.
- Hash equality links retrieve content to what was stored. Recall `source_run_id` points at the write run. Do not invent a retrieve-to-write field.
- Goal / Identity 0 rows does **not** mean those domains never fail.
- Splunk copies a complete index. Splunk does not enforce. HEC 200 is not searchable evidence. One RETEST is not universal RAG/memory resistance.

Free-text is not stored and not machine-graded.
