# Trust Boundaries

**Status:** PLANNED (Phase 1A contract)  
**Applies to:** `ARCHITECTURE.md`  
**Event/operation/dimension semantics:** `SECURITY_EVENT_MODEL.md` (Phase 1B) is authoritative.

A trust boundary is where data or identity from a less-trusted side is used by a more-trusted side. Security checks belong **on the trusted side, before** the dangerous operation.

Existing `src/agentsec/` uses some of these names (EXPERIMENTAL). This file is the contract. It does not claim a production-trusted system.

---

## Picture

```text
UNTRUSTED                         BOUNDARY                 LAB-TRUSTED (not production)
─────────                         ────────                 ───────────────────────────
Learner browser
Attack Service payloads ──HTTP──► AcmeBank API ──► input reference control
Unknown JSON fields               acmebank.http_api              │
                                  │                              ├── DENY/ERROR: stop (no LLM)
                                  │                              └── ALLOW
                                  │                                    │
                                  │                    acmebank.llm_call
                                  │                                    ▼
                                  │                              Ollama (UNTRUSTED MODEL)
                                  │                                    │
                                  │                    acmebank.agent_handoff
                                  │                    (prior text is DATA)
                                  ▼
                           observability.export
                           OTel / Splunk / artifacts     OBSERVE ONLY
                           (cannot grant ALLOW)
```

---

## Named boundaries

| Id | Untrusted side | Trusted side | Dangerous operation on the trusted side |
|----|----------------|--------------|-------------------------------------------|
| `acmebank.http_api` | Browser, Attack Service, any HTTP client | AcmeBank request handling | Accepting a loan pipeline request |
| `acmebank.llm_call` | Policy-approved prompt text | Ollama HTTP generate | LLM inference |
| `acmebank.agent_handoff` | Previous model output | Next agent’s user message | Next LLM inference (still requires input control) |
| `observability.export` | AcmeBank event payload | Collector, Splunk, disk | None (no authorization) |

“Lab-trusted” means AgentSec operators wrote the control code. It does **not** mean production-grade assurance.

---

## Zones

| Zone | Members | May authorize an LLM call? |
|------|---------|----------------------------|
| Untrusted client | Browser, Attack Service | No |
| Enforcement | AcmeBank reference controls | Yes (lab policy only) |
| Untrusted model | Ollama | No |
| Observability | OTel Collector, Splunk, `artifacts/` | No |

MCP servers, A2A peers, RAG corpora, and memory stores **do not exist** in the first implementation. Do not draw them as zones yet.

---

## What an attacker can and cannot control

**Can (untrusted):** payload text; which published AcmeBank route they call; extra JSON (must be rejected, not honored).

**Cannot (`defended`):** `run.id`, `incident.id`, `security.profile`, model name, control decisions, schema name/version, operation attempted/executed/outcome, `testbed.mode`, `execution.mode`, `telemetry.fidelity`, HEC token.

**Vulnerable profile:** may omit the injection DENY; every fail-open must be labeled in telemetry (`security.profile=vulnerable`, reason set).

---

## Agent-to-agent handoff (residual, not a new enclave)

Handoff is string concatenation of the previous agent’s output into the next prompt. It stays inside AcmeBank. It is **not** cryptographic identity (INV-005 later). Prior output is untrusted **data** (INV-002).

The input control still runs **before** each subsequent LLM call, because handoff text can carry injection into credit, risk, or compliance.

Until A2A exists, do not draw four network enclaves on a slide.

---

## Major decisions

### Decision: The authorization boundary is the AcmeBank HTTP API

**ALTERNATIVES:** Controls in Attack Service; controls in Splunk; system-prompt-only safety.

**WHY CHOSEN:** Same door for baseline and attack. Splunk and prompts are not enforcement. AgentWatch skip flags taught the wrong lesson.

**SECURITY CONSEQUENCE:** No privileged exploit hook. Bypass attempts hit the same checks.

**LEARNING VALUE:** Red team tooling is just another client.

### Decision: Attack Service is untrusted relative to AcmeBank

**ALTERNATIVES:** One process; Attack Service imports the LLM client.

**WHY CHOSEN:** A shared import makes the boundary fictional.

**SECURITY CONSEQUENCE:** The red-team UI cannot skip INV-008.

**LEARNING VALUE:** Two doors, one pipeline.

### Decision: Ollama output cannot grant authority

**ALTERNATIVES:** “The model refused, so we are safe”; parse model JSON as policy.

**WHY CHOSEN:** Small live models are inconsistent. Policy is code (INV-002).

**SECURITY CONSEQUENCE:** Jailbreak success is ALLOW with telemetry, not a second policy engine.

**LEARNING VALUE:** LLMs are not security oracles.

### Decision: Splunk and OTel are outside the authorization boundary

**ALTERNATIVES:** Saved searches that write back ALLOW/DENY; AgentWatch SOAR-as-control.

**WHY CHOSEN:** Observation vs enforcement is the SOC lesson.

**SECURITY CONSEQUENCE:** A detection firing is not a blocked call.

**LEARNING VALUE:** DETECT is after OBSERVE. DEFEND is a profile or control change, then RETEST.

### Decision: Phase 1A bind is localhost; Attack Service has no auth

**ALTERNATIVES:** API keys now; OAuth; publish `0.0.0.0/0`.

**WHY CHOSEN:** Smallest useful scope. Anyone who can reach the port is an attacker. That is acceptable only on localhost.

**SECURITY CONSEQUENCE:** Shared/cloud classrooms need auth later (PLANNED).

**LEARNING VALUE:** Lab exposure is part of the threat model.

---

## Future boundaries (not drawn as live)

| Later surface | New boundary | Check before |
|---------------|--------------|--------------|
| Tools / MCP | Agent → tool runtime | Tool invocation |
| A2A | Agent → other agent identity | Accepting a delegated message |
| RAG | Retriever → prompt | Using retrieved text as instruction |
| Memory | Store → prompt | Promoting a memory record to trusted instruction |
| HITL | Agent → human | Privileged workflow transition |
