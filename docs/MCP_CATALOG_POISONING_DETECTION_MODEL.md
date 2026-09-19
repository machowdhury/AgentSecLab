# MCP catalog poisoning — detection model (design only)

**Status:** Phase 8B DESIGN. **No SPL. DET-MCP-001 not modified. No new detector.**

Parents: `docs/MCP005_DETECTION_MODEL.md`, `docs/PHASE3E_MCP_DETECTION.md`, `.cursor/rules/33-splunk-agent-skills.mdc`.

---

## DET-MCP-001 — REUSE, do not edit

Predicate: after authorization **DENY**, did `mcp.started` occur for the same `run.id` + tool?

### Preferred ATTACK B

- First `lookup_policy`: ALLOW (not DENY)
- METADATA-001: **OBSERVE** `metadata_is_data` (not DENY; 8C does not ALLOW on this control)
- Follow-on CTRL-MCP-001: **ALLOW** because of overlay
- Follow-on `mcp.started` matches that ALLOW

**There is no DENY to pair with a later start.** DET-MCP-001 must stay **silent**. Correct for *its* invariant. **Insufficient** for INV-002.

Do not change DET-MCP-001 to “catch catalog poisoning.” That would break the teaching of execution-after-DENY.

### When it *would* fire (not the ATTACK)

Follow-on CTRL-MCP-001 DENY, then handler still begins — MCP-002-shaped bug. Not MCP-CATALOG-001.

---

## Verdict

| Label | Meaning |
|-------|---------|
| **DETECTION REUSE** | DET-MCP-001 remains the after-DENY detector. Workshops show it **0 rows** on ATTACK B. |
| **DETECTION GAP** | No indexed predicate today for “metadata-derived overlay widened a grant.” Schema 1.5.0 can emit METADATA-001; that is classification, not a notable. |
| **NO DETECTOR JUSTIFIED** | A scanner finding is a **hunt/finding**, not a runtime detection. Do not publish DET-MCP-CATALOG because the phase exists. |

---

## Future detector (proposal only)

Would need **all** of: security predicate (metadata treated as grant **and** ungranted tool executed), required telemetry (METADATA-001 + CTRL-MCP-001 + mcp.started), correlation (`run.id` + follow-on tool), negative specimens (BASELINE A, RETEST C, MCP-005 result channel), positive control, FP/FN, live Splunk.

Until 1.5.0 + live validation: **DETECTION BLOCKED BY TELEMETRY GAP**.

A future hunt (not detector) may join scanner sourcetype to runtime **only** when both share an experiment `run.id`. Host-wide scans must not be inner-joined on coincidence of tool name.
