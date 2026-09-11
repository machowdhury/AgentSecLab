# Attack and Control Model

**Status:** Phase 1A contract. Phase 2A implements CTRL-INPUT-001 and the first-lab operation semantics. Splunk detections are later.  
**Related:** `THREAT_MODEL.md`, `SECURITY_INVARIANTS.md`, `ARCHITECTURE.md`  
**Event/operation/dimension semantics:** `SECURITY_EVENT_MODEL.md` (Phase 1B) is authoritative.

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

**DENY** means the dangerous operation **was not invoked**.

| Situation | Legal decision | attempted | executed | outcome |
|-----------|----------------|-----------|----------|---------|
| Injection matched, Ollama not called | DENY | false | false | prevented |
| Empty/malformed input (both profiles) | ERROR | false | false | prevented |
| ALLOW at decision time (LLM not started yet) | ALLOW | false | false | omit |
| LLM invocation started | — | true | true | omit until terminal |
| Ollama HTTP completed successfully | Must not be DENY for that call | true | true | success |
| LLM invocation started, then failed | ERROR (not DENY) | true | true | error |
| Output looks bad after a successful call | Later: SANITIZE or OBSERVE | true | true | success |

`operation.executed=true` means the governed call **began**. It does not mean success. Dependency failure is not non-execution and is not DENY.

A control must not report DENY as prevention if the dangerous operation already occurred.

ERROR before invocation (schema, missing context, unknown agent) is not a synonym for DENY, but it shares `attempted=false`, `executed=false`, `outcome=prevented`. Dependency failure **after** invocation started is `outcome=error`, not `prevented`.

---

## Profiles

| Profile | Injection match | Empty input |
|---------|-----------------|-------------|
| `defended` | DENY | ERROR |
| `vulnerable` | ALLOW + `vulnerable_profile_fail_open:<rule>` | ERROR (same as `defended`; empty input is not a labeled fail-open) |

---

## Experiment dimensions

Do **not** use `LIVE` as `testbed.mode`. First lab emits:

| Dimension | Values | First-lab emission |
|-----------|--------|--------------------|
| `testbed.mode` | `BASELINE` \| `ATTACK` \| `RETEST` | all three as below |
| `execution.mode` | `LIVE` \| `SIMULATED` \| `HYBRID` \| `REPLAYED` | **LIVE only** (others reserved) |
| `telemetry.fidelity` | `OBSERVED` \| `SYNTHETIC` \| `MIXED` | **OBSERVED only** (others reserved) |

Attack Service **must not** implement a second LLM client and **must not** skip controls in `defended`.

---

## First-implementation attacks

| ID | Name | testbed.mode | execution.mode | telemetry.fidelity | Invariant | Expected `defended` result |
|----|------|--------------|----------------|--------------------|-----------|----------------------------|
| ATK-001 | Benign loan | BASELINE | LIVE | OBSERVED | INV-007 | ALLOW; LLM runs (`executed=true`, `outcome=success`); events share `run.id` = `incident.id` |
| ATK-002 | Direct prompt injection | ATTACK | LIVE | OBSERVED | INV-008 | DENY; attempted=false, executed=false, outcome=prevented; zero LLM calls |

Defensive replay of the same ATK-002 payload after a profile/control change uses `testbed.mode=RETEST` (still `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED`).

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
