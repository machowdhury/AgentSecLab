# RAG retrieved-context — detection model (design only)

**Status:** Phase 10A DESIGN + Phase 10D ANALYSIS. **No SPL. No detector. DET-MCP-001 not modified.**

Parents: `docs/RAG_EVENT_MODEL_REVIEW.md`, `docs/MCP005_DETECTION_MODEL.md`, `docs/SCANNER_DETECTION_MODEL.md`, `.cursor/rules/33-splunk-agent-skills.mdc`, `.cursor/skills/splunk-ko-review/SKILL.md`.

A hunt is not a detection. Publish a detector only with: security predicate, required telemetry, correlation contract, negative specimens, positive control, FP/FN, performance, severity, window, schedule, throttle, live Splunk validation.

---

## DET-MCP-001 — REUSE, do not edit

Predicate: after authorization **DENY**, did `mcp.started` occur for the same `run.id` + tool?

### Preferred ATTACK (specimen B)

- Retrieval: valid
- CTRL-RAG-CONTEXT-001: **OBSERVE** `retrieved_context_is_data` (not DENY, not ALLOW)
- Follow-on CTRL-MCP-001: **ALLOW** because of per-run overlay `vulnerable_profile_fail_open:retrieved_context_derived_authority`
- Follow-on `mcp.started` matches that ALLOW

**There is no DENY to pair with a later start.** DET-MCP-001 must stay **silent**. Correct for *its* invariant. **Insufficient** for INV-002.

### RETEST (specimen C)

- Follow-on CTRL-MCP-001: **DENY**
- Handler 0 → no `mcp.started`
- DET-MCP-001 **0 rows** (correct)

### When DET-MCP-001 *would* fire (not RAG-001)

Follow-on DENY, then handler still begins — MCP-002-shaped bug. Keep that detector. Do not widen it to “caught a poisoned document.”

---

## Signal analysis (no detector created)

| Signal | What it is | Classification | Why |
|--------|------------|----------------|-----|
| Malicious retrieved document (AGENT NOTE present) | Fixture / content pattern | **CONTEXT** | Instruction-like text is not a privilege event. High FP in real corpora (policies, runbooks, “note to staff”). |
| Retrieval from suspicious source | Provenance ≠ expected | **HUNT** (later) | Lab has only `rag.local.fixture`. Production source anomalies belong to the behavioral chapter, after field discovery. |
| Retrieved instruction-like text | Regex / LLM classifier | **HUNT** | Prompt-injection indicators are **not** automatic alerts (Microsoft MSRC 2025: probabilistic shields ≠ permission). |
| Follow-on request formed | Interpreter / model requested a tool | **CONTEXT** | REQUEST ≠ GRANT. Forming a request is allowed. |
| Follow-on ALLOW | CTRL-MCP-001 | **CONTEXT** | Vulnerable overlay ALLOW is a **labeled lab fail-open**, not a production notable (same reject as catalog overlay-reason detector). |
| Follow-on DENY | CTRL-MCP-001 | **CONTEXT** | Expected RETEST. DENY is success of the control, not an incident by itself. |
| Execution after DENY | `mcp.started` after DENY | **DETECTION** | Existing **DET-MCP-001**. Already justified. Do not duplicate as DET-RAG-001. |
| Same hash in ATTACK vs RETEST | Integrity of the teaching pair | **CONTEXT** / workshop proof | Not a SOC alert. |
| Retrieval observation OBSERVE | CTRL-RAG-CONTEXT-001 | **CONTEXT** | Classification, not malice. |
| Execution after overlay ALLOW | mcp.started | **NOT JUSTIFIED** as new detector | Matches ALLOW. Teaching signal, not production predicate. |

**Do not automatically convert prompt-injection indicators into alerts.**

---

## Verdict

| Label | Meaning |
|-------|---------|
| **DETECTION REUSE** | DET-MCP-001 remains the after-DENY detector. Workshops should show it **0 rows** on ATTACK B and RETEST C. |
| **DETECTION GAP** | No indexed predicate today for “retrieved context widened authority.” 1.5.0 cannot emit RAG observation. |
| **NO DETECTOR JUSTIFIED** | Do not publish DET-RAG-001 because Phase 10A exists. Overlay reason and AGENT NOTE regex are **REJECT** as production detectors. |
| **DETECTION CANDIDATE (later, not now)** | Only if all of: untrusted retrieval **and** ungranted tool **executed**, with 1.6.0 telemetry, negative specimens (BASELINE, RETEST, MCP-005 result channel, catalog metadata channel), live Splunk. That is a **10C+** decision, not 10A. |

Until bump + live validation: **DETECTION BLOCKED BY TELEMETRY GAP** for any RAG-specific notable.

Phase 10C live validation: **DETECTION ANALYZED — NO NEW DETECTOR.** Overlay reason and AGENT NOTE regex remain **REJECT**. DET-RAG was not created.

Phase 10D detection engineering analysis: **DETECTION ANALYZED — NO NEW DETECTOR.** Candidate I (retrieved content + privileged request + execution as “unauthorized”) remains a **TELEMETRY GAP** until a grant snapshot exists. DET-MCP-001 remains sufficient **only** for DENY-then-start. See `docs/PHASE10D_RAG_DETECTION_ANALYSIS.md`.

---

## Splunk / ML future path (not implemented)

Input to a later **Agent Behavioral Anomaly Detection** chapter. Not 10A. Not MLTK in this phase.

| Idea | Splunk use | Prerequisite |
|------|------------|--------------|
| Retrieval frequency per agent | `timechart` / report | Bound retrieval events |
| Novel document sources | rare `rag.context.provenance` | Provenance enum + more than one source |
| Novel document ids | rare `rag.document.id` | Fixture/id field |
| Retrieval → tool-call sequences | transaction / join on `run.id` | 1.6.0 + follow-on already exist |
| Rare tool after retrieval | notable **candidate** only after baseline | Behavioral chapter; high FP risk |
| Source anomalies | hunt | Not a detector first |
| Time-series anomaly (CDTSM / MLTK) | after a real metric series | Explicitly later; Feature Preview caveats |

Deterministic authorization remains the control. ML may **rank hunts**. ML must not ALLOW tools.

---

## Explicit non-creates

No DET-RAG. No DET-MCP-RAG. No saved search. No ES notable. No Studio. No SPL in this file.
