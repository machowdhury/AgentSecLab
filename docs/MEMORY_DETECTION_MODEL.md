# Agent memory — detection model (design only)

**Status:** Phase 11A DESIGN. **No SPL. No detector. DET-MCP-001 not modified.**

Parents: `docs/MEMORY_EVENT_MODEL_REVIEW.md`, `docs/RAG_DETECTION_MODEL.md`, `.cursor/rules/33-splunk-agent-skills.mdc`.

A hunt is not a detection. Do not create DET-MEMORY because Phase 11 exists.

---

## DET-MCP-001 — REUSE, do not edit

Predicate: after authorization **DENY**, did `mcp.started` occur for the same `run.id` + tool?

### ATTACK recall (specimen B2)

- CTRL-MEMORY-CONTEXT-001: **OBSERVE** (planned)
- CTRL-MCP-001: **ALLOW** overlay `vulnerable_profile_fail_open:memory_derived_authority`
- Handler starts matching ALLOW

**No DENY to pair with a later start.** DET-MCP-001 **silent**. Correct for *its* invariant. **Insufficient** for INV-003.

### RETEST recall (specimen C2)

- CTRL-MCP-001 **DENY**; handler 0
- DET-MCP-001 **0 rows** (correct)

Do not widen DET-MCP-001 to “caught poisoned memory.”

---

## Signal analysis (no detector created)

| Signal | Class | Why |
|--------|-------|-----|
| Memory write | **CONTEXT** | Persistence is not malice |
| `untrusted_data` | **CONTEXT** | Default classification, not IOC |
| Known malicious hash | **CONTEXT** / workshop | Lab fingerprint ≠ compromise |
| Cross-run recall | **CONTEXT** | Normal product behavior |
| Memory-derived privileged request | **HUNT** | REQUEST ≠ GRANT |
| Memory-derived ALLOW | **REJECT** as detector | Overlay reason is lab fail-open |
| Execution after recall | **HUNT** | Not unauthorized without grant snapshot |
| DENY then execution | **DETECTION** | Existing **DET-MCP-001** |
| Rare memory→tool sequence | **FUTURE BEHAVIORAL** | Needs baselines |
| Cross-user / cross-tenant access | **TELEMETRY GAP** | Not in first lab; identity chapter |
| `AGENT MEMORY NOTE` regex | **REJECT** | Instruction-like text; high FP |
| Overlay reason as production IOC | **REJECT** | Same as RAG overlay |

**NO DETECTOR JUSTIFIED.** Until 1.7.0 + live validation: **DETECTION BLOCKED BY TELEMETRY GAP** for any memory-specific notable.

Phase 11C live validation: **DETECTION ANALYZED — NO NEW DETECTOR.** Overlay reason and AGENT MEMORY NOTE regex remain **REJECT**. DET-MEMORY was not created.

Phase 11D detection engineering analysis: **DETECTION ANALYZED — NO NEW DETECTOR.** Candidate “untrusted recall + privileged execution as unauthorized” remains a **TELEMETRY GAP** until a grant snapshot exists. DET-MCP-001 remains sufficient **only** for DENY-then-start. See `docs/PHASE11D_MEMORY_DETECTION_ANALYSIS.md`.

---

## Behavioral / ML future path (not implemented)

Label **FUTURE — NOT IMPLEMENTED**.

| Idea | Later tool |
|------|------------|
| Rare recalled-memory → privileged-tool | Statistical SPL |
| New memory provenance for an agent | rare / `rare` |
| Unusual writer→reader relationship | identity chapter first |
| Cross-user / cross-agent recall | identity / A2A telemetry |
| Persistence duration anomaly | needs TTL fields |
| Memory write burst | `timechart` |
| New sensitive tool after recall | sequence |
| Cross-run behavioral drift | MLTK / CDTSM **where a real series exists** |

**ANOMALY != INCIDENT.**  
**ML MAY PRIORITIZE INVESTIGATION.**  
**ML MUST NOT GRANT OR DENY AUTHORITY.**
