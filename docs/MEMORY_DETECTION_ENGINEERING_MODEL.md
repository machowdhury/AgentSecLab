# Persistent-memory detection engineering model

**Status:** Phase 11D DESIGN / ANALYSIS. **No SPL. DET-MCP-001 unchanged. No DET-MEMORY.**  
**Decision:** **DETECTION ANALYZED — NO NEW DETECTOR**  
**Schema:** `agentsec.security_event` **1.7.0** unchanged in this phase.

Parents: `docs/MEMORY_DETECTION_MODEL.md`, `docs/MEMORY_RUNTIME_EVIDENCE_PLANES.md`, `docs/PHASE11C_MEMORY_SPLUNK_VALIDATION.md`, `.cursor/rules/33-splunk-agent-skills.mdc`.

A hunt is not a detection. Publish a detector only with: security predicate, required telemetry, correlation contract, negative specimens, positive control, FP/FN, performance, severity, window, schedule, throttle, live Splunk validation.

---

## Security property (SOC)

A production SOC does **not** want “was malicious memory detected?” It wants to know which of these happened:

1. Memory was **written** (id, hash, provenance, writer run).
2. Memory was **later recalled** (destination run, `source_run_id`).
3. Recalled content was classified **untrusted data** (OBSERVE).
4. Recall **influenced a REQUEST**.
5. Authorization **denied** or **allowed** that request.
6. The handler **started**, **completed**, or **failed**.
7. Execution occurred **after a DENY**.

Collapsing 1–7 into one notable would train analysts to treat persistence as compromise.

Primary AgentSec property remains **INV-003**: untrusted memory cannot silently become trusted instruction. Supporting **INV-002**: content may influence a request but cannot independently create authority. DET-MCP-001 remains **INV-001-shaped**: execution after DENY.

---

## DET-MCP-001 reuse (do not edit)

Predicate (as implemented): after `control.decision` **DENY**, did `mcp.started` occur for the same `run.id` + tool (`eventstats` by `run_id, tool`; `sequence>deny_sequence`)?

| Specimen | Indexed story | DET-MCP-001 (11C MEASURED, recall `run.id`) |
|----------|---------------|---------------------------------------------|
| BASELINE A recall | CONTEXT-001 OBSERVE; no hop-1; no DENY | **0 rows** |
| ATTACK B recall | CONTEXT-001 OBSERVE; hop-1 **ALLOW** overlay then start | **0 rows** — **no DENY to pair** |
| RETEST C recall | CONTEXT-001 OBSERVE; hop-1 **DENY**; no later start | **0 rows** — invariant holds in telemetry |

**Detects:** execution-after-DENY.  
**Intentionally misses:** memory ATTACK (ALLOW overlay), successful RETEST DENY, CONTEXT-001 OBSERVE, `AGENT MEMORY NOTE` preview, known fixture hash.  
**Do not broaden** to “catch poisoned memory.” That would destroy the teaching of execution-after-DENY.

**0 rows is CORRECT BEHAVIOR.** It is not SAFE, not a missed attack, and not a detector failure.

DET-MCP-001 is **sufficient for its own security property**. It is **not** a memory-poisoning detector and is **not** sufficient for INV-003.

Silence is **correct**. Silence is **not SAFE**.

---

## Candidates A–O

### A — Memory write

| Item | Analysis |
|------|----------|
| Planes | 1 |
| Distinguishes B vs C? | No |
| FP | Every legitimate preference / workflow write |
| Class | **CONTEXT** |
| Why not detection | Persistence is not malice |

### B — Memory recall

| Item | Analysis |
|------|----------|
| Planes | 2 |
| Distinguishes B vs C? | No |
| FP | Normal product recall |
| Class | **CONTEXT** |
| Why | Recalled ≠ attack |

### C — Untrusted memory recall

| Item | Analysis |
|------|----------|
| Planes | 2 |
| Distinguishes B vs C? | No — A/B/C all `untrusted_data` + OBSERVE |
| FP | Every valid recall in this lab, including NORMAL |
| Class | **CONTEXT** |
| Why | `untrusted_data` is the honest default, not an IOC |

### D — Memory recall followed by privileged request

| Item | Analysis |
|------|----------|
| Planes | 2+3 |
| Distinguishes B vs C? | No — same REQUEST |
| FP | Legitimate “remember preference, then look up the customer” workflows |
| Class | **CONTEXT / HUNT** |
| Why | REQUEST ≠ GRANT. Q-MEMORY + Q-MCP-AUTHZ already reconstruct this |

### E — Memory recall followed by DENY

| Item | Analysis |
|------|----------|
| Planes | 2+4 |
| Distinguishes | RETEST only |
| FP | Noise: every successful control denial after recall |
| Class | **CONTEXT** |
| Why | DENY is control success, not an incident by itself |

### F — Memory recall followed by ALLOW

| Item | Analysis |
|------|----------|
| Planes | 2+4 |
| Distinguishes | ATTACK only **in this lab** |
| FP | Legitimate grants after recall |
| Class | **REJECT AS PRODUCTION SIGNAL** |
| Why | Indexed `allowed_scope` is coded **scope**, not proof the tool was ungranted. Overlay reason is lab-only |

### G — Memory recall followed by execution

| Item | Analysis |
|------|----------|
| Planes | 2+5 |
| Distinguishes | ATTACK in this lab |
| FP | Authorized tools after recall |
| Class | **HUNT**; **REJECT AS PRODUCTION SIGNAL** without grant snapshot |
| Why | Execution after ALLOW is expected |

### H — Write → later recall → privileged request → execution

| Item | Analysis |
|------|----------|
| Planes | 1–5 |
| Lab signal | Unique memory story; Q-MEMORY already reconstructs it |
| Distinguishes | ATTACK vs RETEST via plane 4, not via memory bytes |
| Class | **HUNT** (published); **REJECT AS PRODUCTION SIGNAL** as a detector |
| Why | Same overlay / grant-snapshot problems as F/G. Do not duplicate the hunt as DET-MEMORY |

### I — New/rare provenance → recall → privileged request

| Item | Analysis |
|------|----------|
| Class | **FUTURE BEHAVIORAL ANALYTICS** / **TELEMETRY GAP** |
| Why | LIVE provenance enum is only `agentsec.memory.fixture` |

### J — Rare recall → tool sequence for this agent

| Item | Analysis |
|------|----------|
| Class | **FUTURE BEHAVIORAL ANALYTICS** |
| Prerequisite | Per-agent baseline, more than one follow-on tool, population |
| Why | Lab has one agent and one closed follow-on tool |

### K — Large or unusual memory-write burst

| Item | Analysis |
|------|----------|
| Class | **FUTURE BEHAVIORAL ANALYTICS** |
| Why | Six lab writes are not a metric series; `timechart` / CDTSM later |

### L — Memory fingerprint change between write and recall

| Item | Analysis |
|------|----------|
| Planes | 1+2 |
| LIVE 11C | Hunt `fingerprint_survived=same_sha256` on A/B/C |
| Class | **HUNT** (already a hunt column); **not** DETECTION JUSTIFIED |
| Why | No integrity-break specimen. Overwrite policy is not indexed. Mismatch would be investigation, not automatically an incident |

### M — Cross-agent / cross-tenant memory access

| Item | Analysis |
|------|----------|
| Class | **TELEMETRY GAP** / **FUTURE** |
| Why | Single agent `acme-agent-memory-001`. No tenant field. Writer≠reader and tenant mismatch need identity/A2A chapters. Do not invent `session.id` |

### N — `vulnerable_profile_fail_open:memory_derived_authority`

| Item | Analysis |
|------|----------|
| Class | **REJECT AS PRODUCTION SIGNAL** |
| Why | Labeled lab fail-open. Same reject as RAG overlay. Teaching signal only |

### O — `AGENT MEMORY NOTE` regex / fixture marker

| Item | Analysis |
|------|----------|
| Class | **REJECT AS PRODUCTION SIGNAL** |
| Why | Instruction-like text; high FP in policies and tickets. Preview is bounded; interpreter used full content. Fixture marker is not a general IOC |

---

## Production detection bar (not met)

A production memory-security detection would need at least one of:

- an **authorization boundary** violation with a **grant snapshot** (tool not in server-owned allow-list) plus execution; or
- **execution after explicit DENY** (already DET-MCP-001); or
- **cross-identity / cross-tenant** recall that policy forbids (telemetry gap); or
- a demonstrated **memory integrity** policy (unexpected hash change with a defined overwrite rule) plus live negative/positive specimens; or
- strong behavioral deviation **and** a consequential unauthorized action — never anomaly alone.

Do **not** equate: malicious-looking text, `untrusted_data`, memory recall, scanner finding, rare event, or ML anomaly with an incident.

| Requirement | Status |
|-------------|--------|
| Stable correlation (write + recall `run.id`, `source_run_id`, SHA-256) | **AVAILABLE NOW** (lab) |
| Tool-call identity (`gen_ai.tool.call.id`) | **TELEMETRY GAP** |
| Server-owned grant snapshot (`allowed_tools`) | **TELEMETRY GAP** |
| Memory source identity | **PARTIAL** (enum `agentsec.memory.fixture` only) |
| Authorization decision | **AVAILABLE NOW** |
| Execution evidence | **PARTIAL** (indexed mcp.*; handler authoritative) |
| Tenant identity | **TELEMETRY GAP** |
| Writer ≠ reader identity | **TELEMETRY GAP** |
| Sensitive-tool classification | **FUTURE** |
| Baseline behavior | **FUTURE** |

Until grant snapshot (or identity isolation telemetry) + specimens beyond this overlay lab: **TELEMETRY GAP — QUERY NOT DEFENSIBLE** for a memory-specific notable claiming unauthorized execution after untrusted recall.

---

## Severity (do not invent a score)

1. Malicious-**looking** stored text (plane 1) — not an incident.
2. Untrusted recall (plane 2) — context.
3. Privileged **request** after recall (plane 3) — investigation.
4. Unexpected ALLOW / authz failure (plane 4) — needs grant evidence.
5. Unauthorized **execution began** (plane 5 after unexpected ALLOW or after DENY).
6. Successful **privileged operation** (completed handler).

A SOC incident requires at least (4) with a grant snapshot, or (5) via DET-MCP-001, or (6) with both. Preview text and `untrusted_data` never suffice.

---

## Verdict

**DETECTION ANALYZED — NO NEW DETECTOR**

DET-MCP-001 remains sufficient **only** for DENY-then-start. Overlay reason and AGENT MEMORY NOTE regex are **REJECT**. Candidate H is already a hunt. Candidate M is blocked by identity telemetry. No DET-MEMORY.
