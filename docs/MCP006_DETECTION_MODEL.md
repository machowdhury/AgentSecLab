# MCP-006 detection model (design only)

**Status:** Phase 7A design + Phase 7C live analysis. No SPL detector. DET-MCP-001 **not** modified. DET-MCP-006 **not** created. Schema 1.4.0 **does** index control type/source; grant lists still not indexed. Detection remains **ANALYZED — NO NEW DETECTOR**.  
**Parents:** `docs/MCP006_EVENT_MODEL_REVIEW.md`, `docs/PHASE3E_MCP_DETECTION.md`, `docs/MCP005_DETECTION_MODEL.md`.  
**Evidence class:** **DOCUMENTED**. DET-MCP-001 behavior cited below is **MEASURED** on earlier labs, not on MCP-006 (which does not exist yet).

---

## What we are detecting (later — if ever)

Did a **deputy** execute a privileged (still harmless) tool because it consulted **ambient deputy authority** while the **caller’s delegated grant** excluded that tool?

That is INV-001 on a **two-agent** path. It is not INV-001 “execution after DENY.” It is not INV-002 result-as-grant.

---

## DET-MCP-001 — reuse, do not edit

| Item | Fact |
|------|------|
| Question | After CTRL-MCP-001 **DENY**, did `mcp.started` occur for the same `run.id` + tool? |
| Grouping | `run.id` + tool |
| Severity | HIGH (authorization already denied, handler began) |

### Why it is silent on preferred ATTACK B

Preferred MCP-006 vulnerability:

- CTRL-DELEGATION-001 **ALLOW** (fail-open ambient).
- CTRL-MCP-001 **ALLOW** against the per-request deputy ambient policy.
- `mcp.started` is consistent with that ALLOW.

There is **no CTRL-MCP-001 DENY** to pair with a later start. DET-MCP-001 must not fire. That is correct for *its* invariant and **insufficient** for confused-deputy.

### Why it is silent on RETEST C

RETEST DENYs at **CTRL-DELEGATION-001**. Hop 1 never starts. There is no MCP DENY and no `mcp.started`. DET-MCP-001 groups MCP allow-list DENY → start. Do **not** widen DET-MCP-001 to “any DENY.” Widening would still be 0 rows on C (no start) and would confuse MCP-002 teaching.

### When DET-MCP-001 *would* fire (teaching contrast)

Possibility 1: hop 1 CTRL-MCP-001 **DENY**, then the deputy handler still begins.

That is the MCP-002-shaped bug on the deputy hop. **Do not** make possibility 1 the MCP-006 ATTACK. Prefer ambient-ALLOW so learners see a hole DET-MCP-001 cannot see.

---

## Analytic difference vs DET-MCP-001

| Detector idea | Predicate |
|---------------|-----------|
| DET-MCP-001 | MCP **DENY** → `mcp.started` |
| Confused-deputy ATTACK | **Invalid delegated authority** → vulnerable **ALLOW** → execution |

Those are different. A future detector cannot be “DET-MCP-001 with extra keywords.”

---

## Do not parse prompt text

Forbidden as detection evidence:

- “act as admin”
- “execute on my behalf”
- “you are authorized”
- “override”
- DID / `Delegation-Chain:` strings (AgentWatch theater)

Those may appear in **loan** prompt-injection labs. They are not MCP-006 authorization evidence.

---

## Could a future DET-MCP-006 be high-confidence?

**Not on schema 1.3.0.** Missing: `MCP-006` attack id, `mcp_delegation` control type, `authority.source`.

Even after a 7B bump, a detector that only matches `control.reason=vulnerable_profile_fail_open:ambient_deputy_authority` is a **label detector**, the class Phase 6C rejected as insufficient for a notable.

A defensible later detector would need **all** of:

1. CTRL-DELEGATION-001 row
2. `authority.source=ambient_deputy` (or equivalent)
3. requested tool **not** in the **delegated** grant (runtime/manifest — **still not indexed** as `allowed_tools`)
4. hop 1 `mcp.started` for that tool
5. correlation `run.id` (+ hop / sequence)

Item 3 is the same honesty gap as MCP-005: Splunk does not currently carry server-owned tool allow-lists. Without that field, a detector can say “fail-open reason + execution” but **cannot** independently prove “caller lacked the grant.” That proof stays **runtime handler + coded policy tests**.

**Decision for 7A:** do **not** create DET-MCP-006. Detection remains **ANALYZED**. Prefer no detector over a reason-string notable.

---

## Existing hunts — reuse later (no SPL in 7A)

| Hunt | Role when a workshop exists |
|------|-----------------------------|
| Q-MCP-WHO / AUTHZ / TOOL / SCOPE / RESOURCE-AUTHZ | Identity and downstream MCP-001 on hop 1 |
| Q-MCP-EXECUTED | Did **this** tool’s handler begin? |
| Q-MCP-AFTER-DENY | Investigation form of DET-MCP-001 (expect empty on preferred B/C) |

Justified **future** hunt IDs only (no files, no SPL):

| Future ID | Question |
|-----------|----------|
| **Q-MCP-DELEGATION** | What did CTRL-DELEGATION-001 decide, for which caller/deputy/tool, and which authority source? |
| **Q-MCP-AMBIENT-USE** | Did execution occur after `authority.source=ambient_deputy`? |

Do not publish them in 7A. Do not invent fields in SPL to pretend Q3/Q4 grant lists exist.

---

## Splunk security questions (live 7C)

| Id | Question | Answerable on 1.4.0 indexed events? |
|----|----------|-------------------------------------|
| Q1 | Who initiated the delegated operation? | **Yes** — hop 0 `gen_ai.agent.id` |
| Q2 | Which deputy received it? | **Yes on ALLOW paths** (hop 1). RETEST: hop 1 absent; runtime/manifest authoritative |
| Q3 | What authority was delegated? | **Partial** — hop-0 coded **scope** wire; tool set still runtime/manifest |
| Q4 | What authority did the deputy possess independently? | **No** as a grant list. Hop-1 ATTACK `allowed_scope` is the selected MCP policy wire |
| Q5 | Which authority source governed the decision? | **Yes** — `agentsec.delegation.authority.source` |
| Q6 | What did CTRL-DELEGATION-001 decide? | **Yes** |
| Q7 | Did MCP execution begin? | **Yes as observation** (`mcp.started`); handler count remains runtime |
| Q8 | Did execution occur after delegation DENY? | **Yes to observe absence** on a complete copy; not independent non-execution proof |
| Q9 | Did a deputy use ambient authority for a caller lacking delegated authority? | **Partial** — source=`ambient_deputy` + execution; tool-not-in-delegated-set still not indexed |
| Q10 | Can the complete delegation chain be reconstructed? | **Yes for this one-op lab** without grant lists; RETEST deputy not first-class |

---

## Expected negatives (when specimens exist)

| Specimen | DET-MCP-001 | Hypothetical DET-MCP-006 |
|----------|-------------|--------------------------|
| A BASELINE | no DENY | no ambient source |
| B ATTACK (preferred) | fail-open ALLOW then start | would be the positive **if** fields + grant proof exist |
| C RETEST | delegation DENY, no start | DENY alone is not an alert |
| MCP-002 RETEST | DENY + no start (0 rows) | different agent / invariant |
| MCP-005 ATTACK | overlay ALLOW, different control | must not double-count as confused deputy |
| Possibility 1 contrast | **would** fire DET-MCP-001 | optional teaching; not the MCP-006 notable |

---

## Non-goals

- Modify DET-MCP-001
- Create DET-MCP-006
- Cisco / MLTK / ES notable / auto-tag
- Claiming a detection “works” without later LIVE + SIMULATED validation
- Prompt-string correlation
