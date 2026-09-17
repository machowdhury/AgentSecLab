# RAG retrieved-context — detection engineering model

**Status:** Phase 10D DESIGN / ANALYSIS. **No SPL. DET-MCP-001 unchanged. No DET-RAG.**  
**Decision:** **DETECTION ANALYZED — NO NEW DETECTOR**  
**Schema:** `agentsec.security_event` **1.6.0** unchanged in this phase.

Parents: `docs/RAG_DETECTION_MODEL.md`, `docs/RAG_RUNTIME_EVIDENCE_PLANES.md`, `docs/PHASE10C_RAG_SPLUNK_VALIDATION.md`, `.cursor/rules/33-splunk-agent-skills.mdc`.

A hunt is not a detection. Publish a detector only with: security predicate, required telemetry, correlation contract, negative specimens, positive control, FP/FN, performance, severity, window, schedule, throttle, live Splunk validation.

---

## Security property (SOC)

A production SOC does **not** want “was RAG poisoned?” It wants to know which of these happened:

1. Content was **retrieved** (document id, hash, provenance).
2. Content was classified **untrusted data** (OBSERVE).
3. That content **influenced a REQUEST**.
4. Authorization **denied** or **allowed** that request.
5. The handler **started**, **completed**, or **failed**.
6. Execution occurred **after a DENY**.

Collapsing 1–6 into one notable would train analysts to treat retrieved text as policy.

Primary AgentSec property remains **INV-002**: retrieved content cannot independently authorize privileged actions. DET-MCP-001 remains **INV-001-shaped**: execution after DENY.

---

## DET-MCP-001 reuse (do not edit)

Predicate: after CTRL-MCP-001 **DENY**, did `mcp.started` occur for the same `run.id` + tool?

| Specimen | Indexed story | DET-MCP-001 |
|----------|---------------|-------------|
| BASELINE A | no DENY | 0 rows (10C MEASURED) |
| ATTACK B | follow-on **ALLOW** then start | 0 rows — **no DENY to pair** |
| RETEST C | follow-on **DENY**, no later start | 0 rows — invariant holds in telemetry |

**Detects:** execution-after-DENY (MCP-002-shaped bug).  
**Intentionally misses:** RAG ATTACK (ALLOW overlay), successful RETEST DENY, CONTEXT-001 OBSERVE, instruction-like preview.  
**Do not broaden** to “catch poisoned documents.” That would destroy the teaching of execution-after-DENY.

DET-MCP-001 is **sufficient for its own security property**. It is **not** sufficient for INV-002 / retrieved-context authority widening.

Silence is **correct**. Silence is **not SAFE**.

---

## Candidates A–N

### A — Retrieval of content classified untrusted_data

| Item | Analysis |
|------|----------|
| Planes | 1+2 |
| Distinguishes B vs C? | No — A/B/C all OBSERVE |
| FP | Every valid retrieve in this lab, including NORMAL |
| Class | **CONTEXT** |
| Why not detection | `untrusted_data` is the honest default, not malice |

### B — Instruction-like language in retrieved content

| Item | Analysis |
|------|----------|
| Planes | 1 (preview / regex / LLM classifier) |
| Distinguishes B vs C? | No |
| FP | Policies, runbooks, “AGENT NOTE,” training docs, tickets |
| FN | Semantic / multilingual / obfuscated injection |
| Class | **REJECT** as detector; **HUNT** (later, ranked) |
| Why | Microsoft MSRC 2025: probabilistic shields ≠ permission. Preview is bounded; interpreter used full content |

### C — Known malicious document hash

| Item | Analysis |
|------|----------|
| Planes | 1 |
| Distinguishes B vs C? | No |
| FP | Shared lab/training hashes; republished fixtures |
| Class | **CONTEXT** |
| Why | Hash of a teaching fixture is not a current compromise |

### D — Retrieval followed by privileged tool request

| Item | Analysis |
|------|----------|
| Planes | 1+2 |
| Distinguishes B vs C? | No — same REQUEST |
| FP | Legitimate “after reading policy, look up the customer” workflows |
| Class | **CONTEXT / HUNT** |
| Why | REQUEST ≠ GRANT |

### E — Retrieval followed by DENY

| Item | Analysis |
|------|----------|
| Planes | 1+3 |
| Distinguishes | RETEST only |
| FP | Noise: every successful control denial after retrieve |
| Class | **CONTEXT** |
| Why | DENY is control success, not an incident by itself |

### F — Retrieval followed by ALLOW

| Item | Analysis |
|------|----------|
| Planes | 1+3 |
| Distinguishes | ATTACK only **in this lab** |
| FP | Legitimate grants after retrieve |
| Class | **REJECT** as detector |
| Why | Indexed `allowed_scope` is coded **scope**, not proof the tool was ungranted. Overlay reason is lab-only |

### G — Retrieval followed by tool execution

| Item | Analysis |
|------|----------|
| Planes | 1+4 |
| Distinguishes | ATTACK in this lab |
| FP | Authorized tools after retrieve |
| Class | **HUNT** (investigation), **REJECT** as detector without grant snapshot |
| Why | Execution after ALLOW is expected |

### H — Retrieved content + privileged request + ALLOW

| Item | Analysis |
|------|----------|
| Planes | 2+3 |
| Lab signal | Overlay ALLOW |
| Class | **REJECT** production; **CONTEXT** for teaching |
| Why | Same reject as catalog overlay. Lab reason `vulnerable_profile_fail_open:retrieved_context_derived_authority` is **REJECT** as a production predicate |

### I — Retrieved content + privileged request + execution

| Item | Analysis |
|------|----------|
| Planes | 2+4 |
| Required for “unauthorized execution” | Server-owned **tool grant** snapshot |
| Indexed? | **No** `allowed_tools` |
| Class | **TELEMETRY GAP** as detector; **HUNT** reconstruction via Q-RAG + handler counts |
| 10A note | “Ungranted tool executed after untrusted retrieval” remains a **future** candidate only after a grant snapshot exists |

### J — DENY followed by execution

| Item | Analysis |
|------|----------|
| Planes | 3+4 |
| Class | **DETECTION** — existing **DET-MCP-001** |
| Why | Already justified. Do not duplicate as DET-RAG |

### K — Rare tool after retrieval

| Item | Analysis |
|------|----------|
| Class | **FUTURE BEHAVIORAL / ML** |
| Prerequisite | Per-agent baseline, sensitive-tool list, more than two documents |
| Why | High FP; lab has one follow-on tool |

### L — Novel retrieval source followed by privileged operation

| Item | Analysis |
|------|----------|
| Class | **FUTURE BEHAVIORAL / ML** / **TELEMETRY GAP** |
| Why | Lab provenance enum is only `rag.local.fixture` |

### M — Abnormal retrieve→tool sequence

| Item | Analysis |
|------|----------|
| Class | **FUTURE BEHAVIORAL / ML** |
| Why | Needs population baselines; `transaction`/`join` not justified as a detector first |

### N — High-frequency retrieval followed by sensitive operations

| Item | Analysis |
|------|----------|
| Class | **FUTURE BEHAVIORAL / ML** |
| Why | No metric series yet; CDTSM / MLTK Feature Preview later |

---

## Production detection bar (not met)

| Requirement | Status |
|-------------|--------|
| Stable correlation identity (`run.id` + sequence) | **AVAILABLE NOW** |
| Tool-call identity (`gen_ai.tool.call.id`) | **TELEMETRY GAP** |
| Server-owned grant snapshot (`allowed_tools`) | **TELEMETRY GAP** |
| Retrieval source identity | **PARTIAL** (enum `rag.local.fixture` only) |
| Document / version identity | **PARTIAL** (fixture id + hash; no corpus version) |
| Authorization decision | **AVAILABLE NOW** |
| Execution evidence | **PARTIAL** (indexed mcp.*; handler authoritative) |
| Time bounds | **AVAILABLE NOW** (lab `earliest=0` not production) |
| Tenant identity | **TELEMETRY GAP** |
| Agent identity | **AVAILABLE NOW** (`gen_ai.agent.id`) |
| Sensitive-tool classification | **FUTURE** |
| Baseline behavior | **FUTURE** |

Until grant snapshot + negative specimens beyond this lab: **TELEMETRY GAP — QUERY NOT DEFENSIBLE** for a RAG-specific notable claiming unauthorized execution.

---

## Severity (do not invent a score)

Distinguish, in order of SOC consequence:

1. Malicious-**looking** retrieved content (plane 1) — not an incident.
2. Unauthorized **request** (plane 2) — investigation.
3. Authorization **failure** / unexpected ALLOW (plane 3) — needs grant evidence.
4. Unauthorized **execution began** (plane 4 after unexpected ALLOW or after DENY).
5. Successful **privileged operation** (completed handler).

A SOC incident requires at least (3) with a grant snapshot, or (4) via DET-MCP-001, or (5) with both. Preview text and `untrusted_data` never suffice.

---

## Verdict

**DETECTION ANALYZED — NO NEW DETECTOR**

DET-MCP-001 remains sufficient **only** for DENY-then-start. Overlay reason and AGENT NOTE regex are **REJECT**. Candidate I is blocked by missing `allowed_tools`. No DET-RAG.
