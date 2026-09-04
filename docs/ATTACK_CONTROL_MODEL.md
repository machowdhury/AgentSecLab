# Attack and Control Model

**Status:** PLANNED  
**Related:** `THREAT_MODEL.md`, `SECURITY_INVARIANTS.md`, `SECURITY_EVENT_MODEL.md`

Reference controls exist to teach. They are not a vendor product.

---

## Control placement

```text
HTTP → validate schema/agent/profile
     → INPUT CONTROL          ← dangerous op = LLM inference
     → Ollama (if ALLOW)
     → OUTPUT INSPECT         ← inference already happened
     → next agent or finish
```

| Control | Dangerous operation | Legal decisions |
|---------|---------------------|-----------------|
| Schema / agent allow-list | Any processing | ERROR, DENY |
| Input inspection | LLM call | DENY, ALLOW, ERROR |
| Output inspection | Cannot un-call LLM | SANITIZE, OBSERVE, ERROR |
| Tool allowlist (later) | Tool invoke | DENY, ALLOW, ERROR |
| HITL (later) | Privileged transition | REQUIRE_APPROVAL, ALLOW, ERROR |

---

## Modes

LIVE attacks use the real AcmeBank path.  
SIMULATED (later) emits telemetry only.  
HYBRID (later) is per-stage and must label each stage.

Attack Service **must not** implement a second LLM client.

---

## Phase 1 attacks

| ID | Name | Mode | Invariant | Expected defended result |
|----|------|------|-----------|---------------------------|
| ATK-001 | Benign loan | BASELINE or LIVE | INV-007 | ALLOW, LLM runs, events for `run.id` |
| ATK-002 | Input injection catalog | LIVE | INV-008 | DENY, `operation.executed=false` |
| ATK-003 | Output-pattern probe | LIVE | Honest DENY rule | LLM runs; SANITIZE or OBSERVE |

Payloads are lab-owned strings with tests. Do not import AgentWatch’s 51 generic replay templates in Phase 1.

---

## Later catalog (not Phase 1 IMPLEMENTED)

Reuse AgentWatch **teaching surfaces**, not their regex-as-MCP implementations, until redesigned:

| Surface | Control when IMPLEMENTED | Until then |
|---------|--------------------------|------------|
| Tools / MCP | Allow-list before invoke | SIMULATED or omit |
| A2A | Identity check | SIMULATED or omit |
| Memory | Trust labels | omit |
| RAG | Data ≠ authority | SIMULATED hunt only |
| Orchestration | State machine | omit |
| HITL | REQUIRE_APPROVAL in defended | vulnerable demo only if labeled |

---

## Workshop action result (when UI exists)

ACTION, RUN ID, STATUS, WHAT HAPPENED (from telemetry), AGENTS INVOLVED, CONTROL DECISION, IMPORTANT TELEMETRY, WHY IT MATTERS, NEXT STEP.

Never fabricate “what happened.”

---

## Major decisions

### Decision: Attack Service is a client, not a control plane

**DECISION:** POST to AcmeBank only. No skip-control query param in `defended`.

**ALTERNATIVES:** Shared `call_ollama`; `?unguarded=1` for demos.

**WHY CHOSEN:** Trust boundary (`TRUST_BOUNDARIES.md`). AgentWatch skip flags were easy to misunderstand.

**SECURITY CONSEQUENCE:** Red-team UX cannot silently disable INV-008.

**LEARNING VALUE:** Same API, different payload.

### Decision: Three Phase 1 attacks, not fifty-one

**DECISION:** ATK-001–003 only.

**ALTERNATIVES:** Port Top 10; port 51.

**WHY CHOSEN:** Inventory: Top 10 is high quality later; 51 mixed LIVE/SIM. Phase 1 DoD is one loop.

**SECURITY CONSEQUENCE:** Each attack has a test and an expected control decision.

**LEARNING VALUE:** Depth over coverage percentage.

### Decision: SIMULATED cannot prove a control

**DECISION:** Coverage/attestation (later) must partition `testbed_mode`. SIMULATED never increments “live control proved.”

**ALTERNATIVES:** AgentWatch execute-all lighting dashboards with mixed modes unlabeled.

**WHY CHOSEN:** Research integrity.

**SECURITY CONSEQUENCE:** Stops false confidence in regex-free OTel injection.

**LEARNING VALUE:** MEASURED vs SIMULATED.

### Decision: Input DENY vs output SANITIZE/OBSERVE

**DECISION:** Only pre-LLM blocks are DENY. Post-LLM is SANITIZE or OBSERVE.

**ALTERNATIVES:** HARD_DENY after generate (AgentWatch AcmeSentinel).

**WHY CHOSEN:** Security rule on DENY vs completed operation.

**SECURITY CONSEQUENCE:** Token use and model behavior already happened; evidence says so.

**LEARNING VALUE:** Why “output firewall” is not “the call never happened.”
