# AgentSec capstone architecture

**Status:** DESIGN ONLY (Phase 16A). **Do not build this runtime, Studio view, or launcher from this file.**  
**Lab ID (reserved):** LAB-AGENTSEC-CAPSTONE-001  
**Schema:** 1.9.0 unchanged. **No DET-CAPSTONE.** **No new PDP.**  
**Do not start Phase 16B from this file.**

15A capstone sketch (`docs/AGENTSEC_CAPSTONE_DESIGN.md`) remains valid as intent. 16A chooses the **smallest honest architecture** that reuses components that already exist.

---

## Why not the giant diagram

A full User → Orchestrator → RAG → Memory → Goal planner → Delegated agent → MCP → Business API stack would require a new orchestrator, a new launcher, and several new trust-boundary stories at once. That is a **demo**, not a teaching experiment.

The six LIVE labs already emit the planes. The missing competency is **cross-domain reasoning on one incident**, not a seventh product.

---

## Smallest honest architecture

```text
Learner (Attack Service, closed)
        ↓
AcmeBank retrieve  →  CTRL-RAG-CONTEXT-001 (OBSERVE)
        ↓
Memory write / later recall  →  CTRL-MEMORY-CONTEXT-001 (OBSERVE)
        ↓
Follow-on tool request (lookup_customer_tier / customer:read)
        ↓
CTRL-MCP-001  (sole tool PDP)  →  handler or prevent
        ↓
OpenTelemetry → collector → HEC → Splunk
```

**Not in the executing chain (by design):**

| Component | Why omitted from the failing path |
|-----------|-----------------------------------|
| New orchestrator agent | No such runtime; do not invent LangGraph scenery |
| CTRL-GOAL-INTEGRITY-001 | Goal LIVE already teaches authorized tool ≠ authorized goal. Capstone asks the learner to **rule goal out** (no goal events, or in-task lookup_policy only). |
| CTRL-IDENTITY-001 / real A2A | Identity LIVE already teaches claims. Capstone does not mint a second A2A theater. Learner **rules identity out**. |
| CTRL-DELEGATION-001 | Confused deputy is MCP-006 REPLAY; not fused here |
| HITL REQUIRE_APPROVAL | Vocabulary only; do not fake an approval gate |
| Business API beyond existing MCP handlers | `lookup_customer_tier` is enough |

CTRL-INPUT-001 is unused (this is not a loan-text lab). Splunk is not a control.

---

## Control ownership (locked)

| Plane | Control | Role in capstone |
|-------|---------|------------------|
| Retrieved bytes | CTRL-RAG-CONTEXT-001 | OBSERVE classifier. Does **not** ALLOW/DENY the tool. |
| Recalled bytes | CTRL-MEMORY-CONTEXT-001 | OBSERVE classifier. Does **not** mint a grant. |
| Tool / scope / resource | CTRL-MCP-001 | **Sole tool PDP.** ATTACK overlay vs RETEST coded deny — same pattern as 15B/15C. |
| Task (absent) | CTRL-GOAL-INTEGRITY-001 | Not the enforcement story. Absence is a finding. |
| Identity (absent) | CTRL-IDENTITY-001 | Not the enforcement story. Absence is a finding. |
| Evidence copy | Splunk | Reconstruction only |

ATTACK SERVICE ≠ PDP. LEARNING METADATA ≠ POLICY.

---

## Implementation modes (future)

| Mode | Honesty |
|------|---------|
| **A — REPLAY packet (honest now)** | Stitch official 15B RAG pair + 15C memory WRITE+RECALL pair. Label **REPLAY**. Learner correlates two historical campaigns. No new runtime. |
| **B — Sequenced LIVE (16B candidate)** | One closed catalog: retrieve (same RAG-001 fixture) → memory write → later recall → MCP invoke. Freeze bytes server-side. Independent ATTACK vs RETEST overlays. Reuse existing retrieve/memory/mcp functions. **No new authorization semantics.** |

16A implements **neither**. Mode B is the recommended 16B slice. Mode A is the honest fallback if Mode B is delayed.

---

## What the learner is told vs not told

Told: a customer reports the agent accessed customer-tier data outside the expected policy-lookup task. Here is a `run.id` (or write/recall pair). Index/sourcetype. Architecture diagram **without** a red X on a control.

Not told: “RAG failed.” “CTRL-MCP-001 overlay.” “This is LAB-RAG-CONTEXT plus memory.”

---

## Purple-team closed loop (educational roles)

| Role | Responsibility |
|------|----------------|
| RED | Choose/launch the closed adversarial retrieve+persist path; keep equivalent bytes on RETEST |
| BLUE | Reconstruct in Search; name source, influence, request, grant, execution |
| PURPLE (learner) | Connect red action to blue evidence; recommend **which existing control** to change; retest |
| RUNTIME / PLATFORM | Emit honest telemetry; enforce CTRL-MCP-001; never let Studio or Splunk authorize |
| SPLUNK | Indexed copy; hunts; DET-MCP-001 still the only operational detector pattern (0 rows ≠ SAFE) |

---

## Non-goals

No schema bump. No DET-CAPSTONE. No new MCP tool. No OAuth. No vector DB. No Kubernetes. No `ws_lab_capstone.xml` in 16A. No change to PI/MCP/RAG/Memory/Goal/Identity labs.
