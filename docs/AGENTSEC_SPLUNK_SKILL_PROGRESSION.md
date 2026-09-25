# AgentSec Splunk skill progression

**Status:** DESIGN (Phase 15A; **16A update**: RAG, memory, goal, and identity are LIVE Attack Service labs). **16C update:** capstone is LIVE (`LAB-AGENTSEC-CAPSTONE-001`); the “Capstone not implemented” heading below is historical 15A/16A text. **16D:** Home SPLUNK bootcamp + LIVE Path B disclosure + REPLAY HUNT Path A banners. Still not an access-control gate.  
**17A:** S1–S8 are assessed on Mastery Check (`docs/AGENTSEC_SPLUNK_INVESTIGATION_ASSESSMENT.md`). No new hunts.  
**Blue-team update:** `LAB-BLUE-TEAM-INCIDENT-001` adds a post-Capstone REPLAY hunt: bounded candidate discovery, hypothesis-led timeline reconstruction, ATTACK/RETEST/BASELINE comparison, evidence ledger, and reporting. Three new Q-* searches are live-validated; no detector is created.
Path A (Search) and Path B (solution SPL) are **learning UX**, not access control. Do not implement artificial security gates.  
Historical line: **Do not start Phase 16B from this file.** 16B already shipped. **Do not start Phase 16D from this file.**

---

## 16C skill ladder (canonical)

The learner should eventually investigate without Path B. Each stage: what they type, fields, SPL idea, output, interpretation, common error.

| Stage | Learner types | Fields | SPL concept | Expected output | Means | Incorrect |
|-------|---------------|--------|-------------|-----------------|-------|-----------|
| Find a run | `index=agentsec_telemetry sourcetype=otel:agentic:json agentsec.run.id="…"` | `run.id` | quoted field, no `index=*` | events for one experiment | copy of one run | index presence = completeness |
| Timeline | same + sort `agentsec.sequence` | `event.name`, `sequence` | sort by runtime sequence | ordered names | order of emission | `_time` as authority |
| Control decision | `event.name=agentsec.control.decision` | `control.id`, `decision`, `reason` | filter event.name | ALLOW/DENY/OBSERVE rows | runtime decision copied | Splunk decided |
| Request vs authz vs execution | Q-MCP-AUTHZ / TOOL / EXECUTED | tool, scope, resource, `mcp.started` | three questions, not one table | request row ≠ grant ≠ start | REQUEST ≠ GRANT; ALLOW ≠ EXECUTION | DENY string = handler 0 |
| ATTACK vs RETEST | two `run.id`s + fingerprint | `content.hash` / request fingerprint, `testbed.mode` | compare, do not invent join | same bytes, different decision | defense changed | different payload |
| RAG influence | Q-RAG-CONTEXT-AUTHORITY | document.id, hash, OBSERVE, follow-on | domain hunt + Q-MCP | OBSERVE then request | data ≠ authority | provenance = trust |
| Memory WRITE → RECALL | Q-MEMORY with **both** ids | `memory.id`, `source_run_id`, hash | cross-run | linked write/recall | stored ≠ trusted | one `run.id` is enough |
| Identity / delegation | Q-AGENT-DELEGATION-AUTHORITY | caller/callee, claim, IDENTITY OBSERVE, MCP | claim vs grant | OBSERVE + MCP ALLOW or DENY | claim ≠ authn | caller id authenticated |
| Goal vs tool | Q-GOAL + Q-MCP | task, proposed, effective, MCP ALLOW | two planes | GOAL DENY + MCP ALLOW on RETEST | tool ≠ goal | MCP DENY is the Goal lesson |
| Capstone | Q-RUN-EVENTS on three ids, then Q-RAG, Q-MEMORY, Q-MCP, Q-GOAL, Q-IDENT | retrieve/write/recall ids, hashes | campaign reconstruction | 16B shape 5+5+11 / 5+5+10 | fused chain; Goal/Identity 0 rows ≠ those domains never fail | one run.id; inventing a new detector |
| Blue-team incident | bounded window, candidates, self-selected pivots, baseline | time, run.id, sequence, control, mcp.*, source_run_id, hash | hypothesis-led hunt without transaction | candidate runs, timelines, support/refute ledger | bounded conclusion with uncertainty | anomaly = attack; correlation = causation |

**Capstone Path B (16C OBSERVED):** solution SPL is on the INVESTIGATE/TRACE/AUTHORITY tabs after hints. Pedagogy still wants Path A first; product does not delay Path B behind a review gate. DESIGN a disclosure later; do not implement in 16C.

**16D:** LIVE Path B is labeled optional / answer key. Capstone Path B is labeled a **review key**. Studio still cannot hide Path B (no custom JS). Search remains Path A.

---

## Why progression

If every lab only teaches `index=... run.id=...`, the learner never becomes an investigator. Dashboard Studio remains the syllabus; **Search** remains the workbench (`docs/AGENTSEC_GUIDED_INVESTIGATION_STANDARD.md`).

---

## Skill stages

### Early (Level 1–2 start: PI-001, MCP-001)

- Find the run (`run.id`).
- Filter the lab index / sourcetype honestly.
- Read event **sequence**, not a single pretty panel.
- Interpret `control.decision` and `control.reason`.
- Check whether execution **started** (`llm.call` / MCP executed).
- Treat HEC 200 as not yet evidence.
- Treat missing events as incomplete copy, not prevention.

**Path B:** Readily available after an honest attempt (current 14C/14E).

### Intermediate (MCP-003, 004, 005, catalog, scanner)

- Correlate request fields: tool, scope, resource, result, catalog hash.
- Normalize multivalue / nested MCP fields without inventing grants.
- Compare ATTACK vs RETEST when LIVE exists; compare specimens when REPLAY.
- Join scanner `sourcetype=agentsec:scanner:finding` to runtime **without** treating join as authorization.
- Interpret OBSERVE vs ALLOW vs DENY vs ERROR.
- Use hashes/fingerprints when the lab emits them.

**Path B:** Hints before full solution SPL.

### Advanced (RAG, memory, identity, goal) — LIVE as of 15B–15E

- Cross-event: retrieve → tool request; write → recall → tool; identity claim → MCP; goal decision → MCP → execution.
- Cross-run for memory (two `run.id`s).
- Separate authoritative (runtime decision on this run) from corroborative (scanner, prior run, catalog text).
- Argue **absence** carefully (coverage, time window, sourcetype).
- Hashes / fingerprints for ATTACK vs RETEST equivalent-input checks (already emitted).
- Comparative analysis (COMPARE tab + Search), not `join` unless a hunt already requires it.

**Path B:** Search independently first; solution after review.

### Blue-team investigation (post-Capstone, implemented)

- Incident domain and final result are **not** named in the prompt.
- Guided Analyst, Investigator, and Threat Hunter use the same REPLAY dataset.
- Learner creates a hypothesis, discovers candidate runs, reconstructs timelines, challenges one explanation, and records gaps.
- Expected BASELINE tool execution supplies false-positive analysis: `MATCH != MALICIOUS`.
- Known incident → observable → candidate SPL is taught without creating a saved search.

**Path B:** Separate review-key tab after four progressive hints. This is pedagogical gating; Studio does not persist completion state.

---

## Path A / Path B by curriculum stage

| Stage | Path A | Path B |
|-------|--------|--------|
| Beginner (PI, MCP-001) | Required try | Available (current investigations.json) |
| Intermediate (003–catalog) | Expected primary | Hints, then solution |
| Advanced (RAG, memory, goal, identity) | Primary | Solution after independent search |
| Capstone | Only workbench | Review key, not a first click |

This is pedagogy. Do not hide SPL behind runtime authorization.

---

## Detection engineering inside Splunk skill (no new DET-*)

Teach the repository’s actual classes:

| Class | Meaning | Example in repo |
|-------|---------|-----------------|
| CONTEXT | Classifier / provenance | CTRL-RAG-CONTEXT-001 OBSERVE |
| HUNT | Analyst reconstruction | Q-MCP-WHO, Q-RAG-CONTEXT-AUTHORITY |
| DETECTION | Repeatable condition worth alerting | DET-MCP-001 DENY-then-start only |
| FUTURE ANALYTIC | Justified later | Catalog candidate (not shipped) |
| REJECTED SIGNAL | Analyzed, no detector | MCP-005, RAG, memory, goal, PI |

Rules the learner must be able to say:

- Not every attack deserves a detector.
- Not every DENY is an alert.
- Not every suspicious string is an IOC.
- Not every anomaly is an incident.
- Not every lab needs DET-*.

---

## Behavioral analytics / MLTK placement (not implemented)

Place **after** deterministic evidence is fluent (after Level 2–3, typically post Wave 2). Candidate future lessons (REFERENCE / DESIGN EXERCISE until built):

- Rare tool after retrieval
- Novel provenance
- Memory recall drift
- Unusual delegation path
- New retrieve→tool sequence
- Per-agent behavioral deviation

Locked inequalities:

```text
ANOMALY != INCIDENT
ML MAY PRIORITIZE INVESTIGATION
ML MUST NOT GRANT OR DENY AUTHORITY
```

Do not add MLTK, CDTSM, or ES notables in 15A or as a substitute for Wave 1. Phase 16A likewise adds no MLTK. Capstone Search remains Path A/B reuse of existing Q-* (`docs/AGENTSEC_CAPSTONE_INVESTIGATION_DESIGN.md`).
