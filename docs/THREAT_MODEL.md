# Threat Model

**Status:** PLANNED  
**Method:** Identify threat, attacker, asset, boundary, invariant, attack, expected result, reference control, telemetry, detection, tests — as required by AgentSec security rules.

This is an architecture threat model, not a measured experiment.

---

## Assets

| Asset | Why it matters |
|-------|----------------|
| Loan decision path | Privileged business outcome |
| Agent prompts and tool rights | Authority (INV-001) |
| Session / future memory | Instruction vs data (INV-003) |
| Model output shown to a user or next agent | Injection and exfil |
| Telemetry and artifacts | Evidence integrity (INV-007) |
| Splunk index | Detection and investigation |

---

## Attackers

| Attacker | Position | Typical goal |
|----------|----------|--------------|
| External applicant | HTTP to AcmeBank (or via Attack Service) | Inject, jailbreak, tool escape, data leak |
| Malicious retrieved content (later) | RAG/document text | Grant authority via data (INV-002) |
| Impersonating agent (later / SIMULATED) | A2A message | Steal another agent’s role (INV-005) |
| Coverage gamer | SIMULATED emit API | Fake “51 techniques detected” |

Assume the Attack Service operator is a **lab red teamer**, not a bank insider with Splunk admin.

---

## Phase 1 in-scope threats

### T1 — Prompt injection at intake

| Field | Content |
|-------|---------|
| Threat | Untrusted input changes agent behavior |
| Attacker | External |
| Asset | Pipeline reasoning / approval language |
| Boundary | AcmeBank API |
| Invariant | INV-008 (check before LLM); INV-002 |
| Attack | Markup/injection strings in the loan message |
| Expected (defended) | Input control DENY **before** Ollama; `operation_executed=false` |
| Expected (vulnerable) | May reach LLM; labeled profile |
| Reference control | Input inspection |
| Telemetry | `run.id`, `control.decision`, `testbed_mode=LIVE` |
| Detection | SPL: DENY with `operation_executed=false` |
| Tests | Stubbed LLM: zero calls on DENY |

### T2 — Output jailbreak / sensitive-string leakage

| Field | Content |
|-------|---------|
| Threat | Model emits disallowed content after inference |
| Attacker | External (payload aims at output) |
| Asset | Response shown to user / next agent |
| Boundary | Model output → AcmeBank |
| Invariant | Honest placement: inference already happened |
| Attack | Jailbreak / wire-transfer style strings (lab patterns) |
| Expected | SANITIZE or OBSERVE; **not** DENY-of-call |
| Reference control | Output inspection |
| Telemetry | `control.decision=SANITIZE\|OBSERVE`, `operation_executed=true` |
| Detection | Hunt output-inspect events; do not call them “blocked LLM” |
| Tests | After stubbed success, decision is not DENY |

### T3 — Baseline vs attack confusion

| Field | Content |
|-------|---------|
| Threat | Analyst cannot tell noise from attack |
| Attacker | None (integrity of evidence) |
| Asset | Splunk investigations |
| Boundary | Telemetry schema |
| Invariant | INV-007 |
| Attack | N/A |
| Expected | `testbed_mode=BASELINE` vs `LIVE` |
| Reference control | None (observability) |
| Telemetry | `testbed_mode` required |
| Detection | Filter `NOT testbed_mode=BASELINE` |
| Tests | Baseline tick emits BASELINE |

### T4 — Evidence spoofing via SIMULATED events (later, designed now)

| Field | Content |
|-------|---------|
| Threat | OTel injection counted as live control proof |
| Attacker | Lab user or buggy workshop |
| Asset | Coverage / attestation |
| Boundary | Emit-simulated API vs live path |
| Invariant | Research integrity |
| Attack | Force-emit technique events |
| Expected | `testbed_mode=SIMULATED`; excluded from “live proved” |
| Reference control | None executed |
| Telemetry | SIMULATED mode mandatory |
| Detection | Coverage SPL must split modes |
| Tests | Attestation query fixtures |

---

## Later threats (PLANNED / SIMULATED until redesigned)

| ID | Surface | Invariant | AgentWatch lesson |
|----|---------|-----------|-------------------|
| T5 | MCP / tool invocation | INV-001 | Regex on `execute_shell_command(` is not a tool runtime |
| T6 | RAG / retrieved docs | INV-002 | Probe scores that never block are hunts, not controls |
| T7 | Memory persistence | INV-003 | In-process dict is not memory trust isolation |
| T8 | A2A impersonation | INV-005 | `did:acme:` markers fail open if omitted |
| T9 | Orchestration override | INV-006 | Foundry string markers ≠ state machine |
| T10 | Missing HITL | INV-008 | Default fail-open must be a labeled vulnerable lab |
| T11 | Shadow model | INV-004 | Telemetry-only “unapproved model” is not a block |
| T12 | Cisco enforce claim | Honesty | Function with no caller is not a control |

Phase 1 does not implement T5–T12 as live IMPLEMENTED controls. They may appear as **documented future labs** or explicitly SIMULATED hunts.

---

## Major decisions

### Decision: Threat model the live HTTP path first, not 51 ATLAS IDs

**DECISION:** Phase 1 threat model is T1–T4. Technique catalog comes after the path is proven.

**ALTERNATIVES:** Import all 51 AgentWatch techniques as equal live threats.

**WHY CHOSEN:** Many AgentWatch IDs were SIMULATED or generic replay strings. Mapping 51 IDs first would fake completeness.

**SECURITY CONSEQUENCE:** Invariants are proven on real calls, not on coverage percentages.

**LEARNING VALUE:** Surfaces and placement before catalog breadth.

### Decision: Attacker is the HTTP client, not “the LLM”

**DECISION:** The LLM is a confused deputy / untrusted component, not the primary attacker.

**ALTERNATIVES:** Treat model as adversary only; ignore client injection.

**WHY CHOSEN:** The client chooses the payload. The model may comply or refuse; that is not a trust boundary.

**SECURITY CONSEQUENCE:** Controls sit on AcmeBank, before and after the model, never “inside” Ollama.

**LEARNING VALUE:** Agentic security is still input/output/tool policy, plus workflow.

### Decision: Prompt-paste handoff is a residual risk, not hidden

**DECISION:** Document that agent 2–4 consume previous model text. That is a dataflow risk (injection into later agents).

**ALTERNATIVES:** Pretend four trust enclaves; encrypt handoff in Phase 1.

**WHY CHOSEN:** Honesty. Encryption without identity is theater.

**SECURITY CONSEQUENCE:** Output inspect and later workflow rules matter on **each** hop, not only intake.

**LEARNING VALUE:** Multi-agent increases blast radius of one jailbreak.
