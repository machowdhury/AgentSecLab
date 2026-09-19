# Goal integrity detection model

**Status:** DETECTION ANALYZED — NO NEW DETECTOR (13A design; 13C live; **13D re-justified**).  
**No DET-GOAL.** No Q-GOAL in 13A/13B. Phase 13C published hunt `Q-GOAL-INTEGRITY-AUTHORITY` only (**13D: REUSE**). DET-MCP-001 remains the only operational detector. It is unchanged.

Live 13C DET-MCP-001 on fresh A/B/C: **0 / 0 / 0** (MEASURED). RETEST goal DENY does not group with hop-1 `lookup_policy` start. **0 rows is CORRECT. Silence != SAFE.**

13D workshop: **DESIGNED — NOT IMPLEMENTED**. Phase 13E not started.

## Signal classes

| Signal | Plane | 13D class |
|--------|-------|-----------|
| instruction-like content / `untrusted_instruction` | 2 | **CONTEXT** |
| goal-change proposal (proposed ≠ in-task summarize) | 3 | **HUNT** |
| CTRL-GOAL-INTEGRITY-001 DENY | 3 | **HUNT** |
| vulnerable overlay reason | 3 | **REJECT** (lab vocabulary) |
| authorized tool + out-of-task effective action | 3+4+5 | **FUTURE RESEARCH** / **TELEMETRY DEPENDENT** |
| rare task → action / instruction → tool sequence | behavioral | **FUTURE RESEARCH** |
| execution after explicit tool DENY | 4+5 | existing **DET-MCP-001** |

Do not detect fixture strings, overlay reason strings, `AGENT NOTE`, or known test hashes. Those are workshop artifacts, not production IOCs.

## Verdict

NO DETECTOR JUSTIFIED.

Reasons:

- Overlay reason is LAB-ONLY.
- RETEST DENY is `unauthorized_task_expansion` on CTRL-GOAL-INTEGRITY-001 while CTRL-MCP-001 may still ALLOW `lookup_policy` for the original task. DET-MCP-001 must not be taught as “goal DENY then tool start”.
- Goal hop `gen_ai.tool.name` is the **proposed action id**, not the MCP tool, so DET-MCP-001 grouping by tool stays honest.
- `untrusted_instruction` is present on BASELINE.
- Effective action is preview-bounded, not first-class.
- Three lab specimens are not a production detection population.

ANOMALY != INCIDENT.  
ML MAY PRIORITIZE INVESTIGATION.  
ML MUST NOT DEFINE AUTHORITY.
