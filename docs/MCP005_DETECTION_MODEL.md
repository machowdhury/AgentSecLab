# MCP-005 detection model (design only)

**Status:** Phase 6A **DESIGN**. No SPL written. DET-MCP-001 **not** modified. DET-MCP-005 **not** created.  
**Parents:** `docs/MCP005_EVENT_MODEL_REVIEW.md`, `docs/PHASE3E_MCP_DETECTION.md`.  
**Evidence class:** **DOCUMENTED**. DET-MCP-001 behavior cited below is **MEASURED** on earlier labs, not on MCP-005 (which does not exist yet).

---

## What we are detecting (later)

Did returned **data** become **authority** — specifically, did a follow-on tool execute because a result-derived overlay widened what CTRL-MCP-001 would allow, while the **server-owned** grant still excluded that tool?

That is INV-002, not INV-001 “execution after DENY.”

---

## DET-MCP-001 — reuse, do not edit

| Item | Fact |
|------|------|
| Question | After CTRL-MCP-001 **DENY**, did `mcp.started` occur for the same `run.id` + tool? |
| Grouping | `run.id` + `tool` |
| Severity | HIGH (authorization already denied, handler began) |

### Why it is silent on preferred ATTACK B

Preferred MCP-005 vulnerability:

- First call ALLOW (not DENY).
- RESULT-001 ALLOW fail-open (not DENY).
- Follow-on CTRL-MCP-001 **ALLOW** because of overlay.
- Follow-on `mcp.started` is consistent with that ALLOW.

There is **no DENY** to pair with a later start. DET-MCP-001 must not fire. That is correct for *its* invariant and **insufficient** for INV-002.

### When DET-MCP-001 *would* fire (teaching contrast)

Possibility 1: follow-on CTRL-MCP-001 **DENY** `tool_not_granted`, then the follow-on handler still begins.

That is the MCP-002-shaped bug. DET-MCP-001 would apply (same `run.id` + `lookup_customer_tier`). **Do not** make possibility 1 the MCP-005 ATTACK. Prefer possibility 2 so learners see a hole DET-MCP-001 cannot see.

### Two-tool grouping note

DET-MCP-001 groups by `run.id` + tool. MCP-005’s two **different** names do not break that detector. A later same-tool-twice lab still wants `gen_ai.tool.call.id`. Do not change DET-MCP-001 in 6A to “fix” MCP-005.

---

## Existing hunts — reuse as-is (no SPL in 6A)

| Hunt | Role in a future MCP-005 workshop |
|------|-----------------------------------|
| Q-MCP-WHO / AUTHZ / TOOL / SCOPE / RESOURCE-AUTHZ | First-call (and, as extra rows, follow-on) identity |
| Q-MCP-EXECUTED | Did **this** tool’s handler begin? |
| Q-MCP-RESULT | What preview/hash/trust/provenance did a completed call emit? |
| Q-MCP-RESULT-TRUST | **Label only:** `untrusted_data` on `mcp.completed`. Already VALIDATED. Not “used as authority.” |
| Q-MCP-AFTER-DENY | Investigation form of DET-MCP-001 |

Do not rewrite Q-MCP-RESULT-TRUST to become the authority hunt. The Phase 3A LAB_PLAN name collided with the implemented meaning. Implemented meaning wins.

---

## Justified future questions (IDs only)

No files. No SPL.

| Future ID | Question | Sketch (not SPL) |
|-----------|----------|------------------|
| **Q-MCP-RESULT-AUTHORITY** | Did the result-trust control refuse mutation, and does telemetry still show server-owned `allowed_tools` / coded grant excluding the follow-on? | Filter RESULT-001 rows when they exist; compare reason `result_is_data` vs `…:result_derived_grant`; show unchanged grant fields |
| **Q-MCP-RESULT-FOLLOWON** | Was a follow-on tool requested, what did CTRL-MCP-001 decide, did the second handler begin? | Second `gen_ai.tool.name=lookup_customer_tier` control + execute flags |

These require RESULT-001 emission and (for honest OBSERVE) a schema bump. Not 6A.

---

## Possible later detector (do not create now)

**Working name:** DET-MCP-005 (not reserved as a saved search in this phase).

**Hypothesis:** a follow-on CTRL-MCP-001 **ALLOW** whose reason is result-derived (`vulnerable_profile_fail_open:result_derived_grant` or equivalent), while server-owned allowed tools **do not** include that tool.

| Property | Intent |
|----------|--------|
| High-confidence core | Reason string is the labeled fail-open **and** grant field still `lookup_policy` **and** `mcp.started` for `lookup_customer_tier` |
| Not high-confidence | “Preview contains SECURITY_OVERRIDE” (content hunt, not invariant) |
| Not this detector | DENY then start (that remains DET-MCP-001) |
| Evidence class | Any positive control before LIVE specimens exist is **SIMULATED** |
| ES notable | **NOT ATTEMPTED** |
| Auto-tag | **NOT ATTEMPTED** |

Do not write the SPL. Do not add a savedsearches stanza. Do not enable a schedule.

---

## Expected negatives (when specimens exist)

| Specimen | Why DET-MCP-001 must not fire | Why a future DET-MCP-005 might / might not |
|----------|-------------------------------|--------------------------------------------|
| A BASELINE | No DENY | No follow-on ALLOW / no overlay reason |
| B ATTACK (preferred) | Fail-open **ALLOW**, then start | **Would** be the positive (INV-002), once written |
| C RETEST | Follow-on DENY, no second start | DENY alone is not an alert |
| MCP-002 RETEST (old lab) | DENY, no start | Different tool story; not result-derived |
| Possibility 1 contrast | **Would** fire DET-MCP-001 | Optional teaching; not the MCP-005 notable |

---

## Non-goals

- Modify DET-MCP-001
- Create DET-MCP-005
- Cisco / MLTK
- Risk scores / ES notables
- Claiming a detection “works” without LIVE + SIMULATED validation later
