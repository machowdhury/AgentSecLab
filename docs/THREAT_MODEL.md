# Threat Model

**Status:** PLANNED (Phase 1A contract)  
**Method:** threat, attacker, asset, boundary, invariant, attack, expected result, reference control, telemetry, detection, tests.  
**Event/operation/dimension semantics:** `SECURITY_EVENT_MODEL.md` (Phase 1B) is authoritative.

This is an architecture threat model, not a measured experiment. Existing tests in the repo are EXPERIMENTAL alignment; they are not live Ollama/Splunk proof.

---

## Assets

| Asset | Why it matters |
|-------|----------------|
| Loan pipeline (four LLM hops) | Privileged business-shaped outcome |
| Right to call Ollama | The only dangerous operation in this slice |
| Agent prompts and coded order | Authority (INV-001 / INV-006) |
| Model output shown to a user or next agent | Injection into later hops |
| Telemetry and artifacts | Evidence integrity (INV-007) |
| Splunk index | Detection and investigation |

No tools, RAG corpus, durable memory, or inter-agent network exist yet. Those assets are out of scope.

---

## Attackers

| Attacker | Position | Typical goal |
|----------|----------|--------------|
| External applicant / lab red teamer | HTTP to AcmeBank (or via Attack Service) | Prompt injection that changes later agent behavior or approval language |
| Coverage gamer (later) | SIMULATED emit API (not in this slice) | Fake detections |

Assume the Attack Service operator is a **lab red teamer**, not a bank insider with Splunk admin. The LLM is a **confused deputy**, not the primary attacker.

---

## In-scope threats (first implementation)

### T1 — Direct prompt injection at the HTTP boundary

| Field | Content |
|-------|---------|
| Threat | Untrusted input is treated as instruction |
| Attacker | External / Attack Service |
| Asset | Pipeline reasoning; right to call Ollama |
| Boundary | `acmebank.http_api` then `acmebank.llm_call` |
| Invariant | INV-008 (check before LLM); INV-002 (model/text is not policy) |
| Attack | ATK-002 catalog strings in the loan message |
| Expected (`defended`) | Input control DENY **before** Ollama; attempted=false, executed=false, outcome=prevented; zero LLM calls |
| Expected (`vulnerable`) | May reach LLM; `security.profile=vulnerable` and fail-open reason |
| Reference control | CTRL-INPUT-001 (lightweight input inspection) |
| Telemetry | `run.id` = `incident.id`, control decision + reason, `testbed.mode=ATTACK`, `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED` |
| Detection (later, validated SPL) | ATTACK DENY with attempted=false, executed=false, outcome=prevented. Splunk absence of `llm.*` is corroborating only unless run completeness is established. |
| Tests | Stubbed LLM: zero calls on DENY. Runtime is authoritative for invocation. |

### T2 — Injection via agent handoff

| Field | Content |
|-------|---------|
| Threat | A jailbreak that reaches intake (or is concatenated) poisons credit/risk/compliance |
| Attacker | External (payload survives or is rewritten by the model) |
| Asset | Later hops |
| Boundary | `acmebank.agent_handoff` |
| Invariant | INV-002, INV-006, INV-008 on **each** hop |
| Attack | Same ATK-002 family; or ALLOW path where model echoes injection |
| Expected (`defended`) | Input control on **each** hop; DENY stops remaining LLM calls |
| Reference control | Same input control, not a fake A2A passport |
| Telemetry | Shared `run.id`; hop identity; which hop blocked |
| Tests | Pipeline stops; later stub agents are not called |

### T3 — Baseline vs attack confusion

| Field | Content |
|-------|---------|
| Threat | Analyst cannot tell noise from attack |
| Attacker | None (evidence integrity) |
| Asset | Splunk investigations |
| Boundary | `observability.export` |
| Invariant | INV-007 |
| Expected | `testbed.mode=BASELINE` vs `ATTACK` vs `RETEST`; attacker cannot set `testbed.mode`, `execution.mode`, or `telemetry.fidelity` |
| Reference control | None (observability) |
| Tests | Attacker JSON cannot set `testbed.mode` (including BASELINE) |

### T4 — Evidence spoofing / decision injection

| Field | Content |
|-------|---------|
| Threat | Attacker JSON sets `control.decision`, `run.id`, `incident.id`, `security.profile`, schema version, or operation flags |
| Attacker | HTTP client |
| Asset | Evidence (INV-007), fail-safe (INV-008) |
| Boundary | `acmebank.http_api` |
| Expected | Closed handling: extra fields ERROR; decisions computed server-side |
| Tests | Untrusted JSON cannot bypass |

---

## Out of scope for the first implementation (documented so they are not faked)

| ID | Surface | Invariant | Why it waits |
|----|---------|-----------|--------------|
| T5 | Output jailbreak as a **separate** control story | Honest DENY rule | No output inspector yet. If the model runs, the call is ALLOW + actual text, not DENY |
| T6 | MCP / tool escape | INV-001 | No tool runtime. Regex on `execute_shell_command(` would be AgentWatch theater |
| T7 | RAG / retrieved docs | INV-002 | No retriever |
| T8 | Memory persistence | INV-003 | Display-only session at most |
| T9 | A2A impersonation | INV-005 | No A2A network |
| T10 | Orchestration override strings | INV-006 | Order is code; no Foundry markers |
| T11 | SIMULATED OTel as live proof | Research integrity | No simulated emit API |
| T12 | Cisco “enforce” | Honesty | No Cisco overlay |

---

## Major decisions

### Decision: Threat-model the live HTTP path, not 51 ATLAS IDs

**WHY:** Phase 0: many AgentWatch IDs were SIMULATED or generic replay strings.  
**SECURITY:** Invariants are proven on real calls.  
**LEARNING:** Surfaces and placement before catalog breadth.

### Decision: The attacker is the HTTP client, not “the LLM”

**WHY:** The client chooses the payload. The model may comply or refuse.  
**SECURITY:** Controls sit on AcmeBank, before the model.  
**LEARNING:** Agentic security is still input and workflow policy.

### Decision: Prompt-paste handoff is a residual risk, not hidden

**WHY:** Honesty. Encryption without identity is theater.  
**SECURITY:** Input control on every hop.  
**LEARNING:** Multi-agent increases blast radius of one injection.

### Decision: One catalog attack

**WHY:** First implementation target is one direct prompt-injection.  
**SECURITY:** That attack has an expected control decision and a stub test.  
**LEARNING:** Depth over coverage percentage.
