# Attack and Control Model

**Status:** PLANNED (Phase 1A contract)  
**Related:** `THREAT_MODEL.md`, `SECURITY_INVARIANTS.md`, `ARCHITECTURE.md`

Reference controls exist to teach. They are not a vendor product. They are not Cisco CodeGuard, DefenseClaw, or a real MCP gateway.

---

## Control placement

```text
HTTP → validate schema / reject extra policy fields
     → INPUT CONTROL          ← dangerous op = LLM inference
     → Ollama (only if ALLOW)
     → emit actual outcome
     → next agent or finish
```

The input control runs **before each hop**, because handoff text can carry injection.

| Control | Dangerous operation | Legal decisions now |
|---------|---------------------|---------------------|
| Schema / agent allow-list | Any processing | ERROR |
| Input inspection | LLM call | DENY, ALLOW, ERROR |

Not in the first implementation: output inspection, tool allowlist, HITL, quarantine, simulated emit.

---

## What DENY means

**DENY** means the dangerous operation **did not run**.

| Situation | Legal decision | `operation.executed` |
|-----------|----------------|----------------------|
| Injection matched, Ollama not called | DENY | false |
| Empty/malformed input in `defended` | ERROR | false |
| Ollama HTTP completed | Must not be DENY for that call | true |
| Output looks bad after a successful call | Later: SANITIZE or OBSERVE | true |

A control must not report DENY as prevention if the dangerous operation already occurred.

ERROR is for schema, missing context, unknown agent, or dependency failure — not a synonym for DENY.

---

## Profiles

| Profile | Injection match | Empty input |
|---------|-----------------|-------------|
| `defended` | DENY | ERROR |
| `vulnerable` | ALLOW + `vulnerable_profile_fail_open:<rule>` | Documented labeled fail-open or ERROR — must not be silent |

---

## Modes

| Mode | Meaning in this slice |
|------|------------------------|
| LIVE | Real AcmeBank path, including attacks |
| BASELINE | Real AcmeBank path, benign ticker or benign UI submit |
| SIMULATED | **Not used** in the first implementation |
| HYBRID | **Not used** |

Attack Service **must not** implement a second LLM client and **must not** skip controls in `defended`.

---

## First-implementation attacks

| ID | Name | Mode | Invariant | Expected `defended` result |
|----|------|------|-----------|----------------------------|
| ATK-001 | Benign loan | BASELINE or LIVE | INV-007 | ALLOW; LLM runs; events share `run.id` |
| ATK-002 | Direct prompt injection | LIVE | INV-008 | DENY; `operation.executed=false`; zero LLM calls |

Payloads are lab-owned strings with tests. Do not import AgentWatch’s 51 generic replay templates.

Output-pattern attacks, Top 10, kill chains, and execute-all are **later**.

---

## Control vocabulary (full enum, unused values reserved)

ALLOW, DENY, SANITIZE, QUARANTINE, REQUIRE_APPROVAL, OBSERVE, ERROR.

Do not invent runtime paths just to emit every value. Unused values stay reserved so Splunk and the event model can grow without renaming.

---

## Workshop action result (when UI exists)

ACTION, RUN ID, STATUS, WHAT HAPPENED (from telemetry), AGENTS INVOLVED, CONTROL DECISION, IMPORTANT TELEMETRY, WHY IT MATTERS, NEXT STEP.

Never fabricate “what happened.”

---

## Later catalog (not first-implementation IMPLEMENTED)

Reuse AgentWatch **teaching surfaces**, not their regex-as-protocol implementations:

| Surface | Control when IMPLEMENTED | Until then |
|---------|--------------------------|------------|
| Output inspection | SANITIZE / OBSERVE after inference | omit |
| Tools / MCP | Allow-list before invoke | omit (do not regex-simulate MCP) |
| A2A | Identity check | omit |
| Memory | Trust labels | omit |
| RAG | Data ≠ authority | omit |
| Orchestration | State machine | omit |
| HITL | REQUIRE_APPROVAL in `defended` | omit or labeled vulnerable demo only |

---

## Major decisions

### Decision: Attack Service is a client, not a control plane

**WHY:** Trust boundary. AgentWatch skip flags were easy to misunderstand.  
**SECURITY:** Red-team UX cannot silently disable INV-008.  
**LEARNING:** Same API, different payload.

### Decision: Two runs, one control

**WHY:** First target is one benign workflow, one injection, one lightweight control.  
**SECURITY:** Each has an expected decision and a stub test.  
**LEARNING:** Depth over coverage percentage.

### Decision: SIMULATED cannot prove a control

**WHY:** Phase 0 kill chains could emit HARD_DENY without Ollama.  
**SECURITY:** No simulated emit API in this slice.  
**LEARNING:** MEASURED vs SIMULATED starts with not emitting fiction.
