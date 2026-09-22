# AgentSec detection-engineering curriculum

**Status:** DESIGN (Phase 16A). **No new detectors.**  
**Do not start Phase 16B from this file.**

Not every suspicious behavior should become an alert. AgentSec already decided this per lab (DETECTION ANALYZED — NO NEW DETECTOR on RAG, memory, goal, identity, result trust, scanner).

---

## Progression model

```text
CONTEXT
  → HUNT
  → DETECTION CANDIDATE
  → DETECTION
  → BEHAVIORAL ANALYTICS
  → FUTURE RESEARCH
```

| Stage | Question | AgentSec example | Learner action |
|-------|----------|------------------|----------------|
| CONTEXT | What provenance/trust label exists? | CTRL-RAG-CONTEXT-001 OBSERVE | Do not alert on “untrusted” |
| HUNT | Can an analyst reconstruct this `run.id`? | Q-MCP-*, Q-RAG-*, Q-MEMORY-*, Q-GOAL-*, Q-AGENT-DELEGATION-* | Path A/B |
| DETECTION CANDIDATE | Is there a repeatable, high-precision condition? | Catalog overlay reason (documented candidate, **not shipped**) | Write why it would false-positive |
| DETECTION | Should SOC be paged? | **DET-MCP-001 only** (DENY then MCP start) | Explain 0 rows on overlay-ALLOW ATTACK |
| BEHAVIORAL ANALYTICS | Does a distribution/baseline help prioritize hunts? | DETECT tabs: NOT IMPLEMENTED / FUTURE | ANOMALY ≠ INCIDENT; ML ≠ PDP |
| FUTURE RESEARCH | MLTK, CDTSM, ES notable | Roadmap advanced track | Out of 16A |

---

## Why some labs have no detector

| Lab | Detector decision | Why |
|-----|-------------------|-----|
| LAB-PI-001 | NONE JUSTIFIED | Regex DENY is the control; paraphrases ALLOW; alerting on input strings is brittle |
| LAB-MCP-001 ATTACK | DET-MCP-001 exists but **0 rows** | ATTACK is overlay **ALLOW** then execute — not DENY-then-start |
| LAB-MCP-003/004 | DET-MCP-001 reuse | Same pattern; no DET-MCP-003/004 |
| LAB-MCP-005 | NONE JUSTIFIED | Result-as-data; OBSERVE |
| LAB-MCP-006 | NONE JUSTIFIED | Deputy path is a grant anatomy lesson |
| LAB-MCP-CATALOG | CANDIDATE later | Overlay-reason notable rejected as production |
| Scanner | NONE JUSTIFIED | SCANNER FINDING ≠ AUTHORIZATION |
| LAB-RAG-CONTEXT | NONE JUSTIFIED (no DET-RAG) | Influence ≠ incident; OBSERVE is correct |
| LAB-MEMORY-001 | NONE JUSTIFIED (no DET-MEMORY) | Persistence ≠ incident |
| LAB-AGENT-GOAL-INTEGRITY-001 | NONE JUSTIFIED (no DET-GOAL) | Goal DENY is control evidence, not a notable template |
| LAB-AGENT-DELEGATION-001 | NONE JUSTIFIED (no DET-A2A) | Claims are data; no auth stack |
| Capstone | Must not invent DET-CAPSTONE | Story is a hunt |

---

## Locked teaching lines

- Not every attack deserves a detector.
- Not every DENY is an alert.
- Not every suspicious string is an IOC.
- Not every anomaly is an incident.
- Overlay fail-open is a **lab** signal, not a production notable.
- DET-MCP-001 0 rows ≠ SAFE.
- Splunk detections do not enforce CTRL-*.
