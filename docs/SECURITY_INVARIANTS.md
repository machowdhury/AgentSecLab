# Security Invariants

**Status:** PLANNED (Phase 1A contract)  
**Source:** AgentSec rule INV-001–INV-008, mapped to the first implementation.

An invariant is a property that must remain true even when the attacker controls the payload. Labs may **violate** an invariant only in the `vulnerable` profile, and only when telemetry says so.

---

## Applicability to the minimum first implementation

| Invariant | First slice | Role |
|-----------|-------------|------|
| **INV-001** Delegated authorization | **Applies (narrow)** | Agents have no tools. Authority is “may call Ollama with this system prompt.” A prompt cannot add agents or tools. Full MCP delegation is future. |
| **INV-002** Data cannot grant authority | **Applies** | No RAG. Model output and handoff text cannot mint ALLOW after DENY. Model JSON is not policy. |
| **INV-003** Memory trust isolation | **Future-facing** | No durable memory. If a session ring exists for the UI, it is display-only and not trusted instruction. |
| **INV-004** Privileged action attribution | **Applies** | Every LLM call and control decision carries `run.id`, agent id, profile. `run.id` is server-minted. |
| **INV-005** Agent identity integrity | **Applies (narrow)** | No A2A network. Agent id is an allow-list. Unknown ids → ERROR. Cryptographic passports are future. |
| **INV-006** Workflow integrity | **Applies (narrow)** | Only transition is coded: intake → credit → risk → compliance. The model cannot reorder agents. State machines are future. |
| **INV-007** Evidence integrity | **Applies** | Shared `run.id`; decision + reason + `operation.executed`; `testbed_mode`; artifacts pack. |
| **INV-008** Fail-safe decisions | **Applies (primary teaching invariant)** | `defended`: missing context → ERROR or DENY. `vulnerable`: labeled fail-open only. |

“Applies (narrow)” means the invariant is true for this slice’s actual surfaces, not that MCP/A2A/memory labs are done.

---

## INV-001 Delegated authorization

An agent cannot receive more authority than was explicitly delegated.

**First implementation:** Coded scopes per role (`loan.intake`, `loan.credit`, `loan.risk`, `loan.compliance`). No tools.

**Later:** Tool/MCP allowlist **before** invocation. Delegation object, not retrieved text.

**Vulnerable exception:** none required (no tools to over-grant).

---

## INV-002 Data cannot grant authority

Retrieved content cannot independently authorize privileged actions.

**First implementation:** No RAG. Handoff text and model JSON cannot override DENY or reorder the pipeline.

**Later:** RAG hits are data. They cannot expand tools or skip HITL.

---

## INV-003 Memory trust isolation

Untrusted memory cannot silently become trusted instruction.

**First implementation:** Not in play. Do not implement a memory control that is only a regex on `WRITE_MEMORY`.

**Later:** Trust-tagged records. Untrusted facts cannot become system prompt without a control decision.

---

## INV-004 Privileged action attribution

Privileged actions must be attributable to a known principal or delegation.

**First implementation:** Initiator (`user.id`) + agent id + `run.id` + profile on every security-sensitive event.

**Later:** Delegation id on tool calls.

---

## INV-005 Agent identity integrity

Agent impersonation must be rejected or detectable.

**First implementation:** Allow-listed agent ids. No DID/passport theater.

**Later:** Explicit identity check; fail closed in `defended`. SIMULATED impersonation hunts must be labeled.

---

## INV-006 Workflow integrity

Privileged workflow transitions require authorized state transitions.

**First implementation:** Fixed sequence in code. Client cannot pick hop 4 first as a way to skip intake **inside** `/process`. If a single-agent route exists later, it is a separate, documented lab — not a silent skip of the loan workflow.

**Later:** State machine; forged orchestrator strings cannot skip steps in `defended`.

---

## INV-007 Evidence integrity

Security-sensitive actions must generate enough telemetry for reconstruction.

**First implementation:** `run.id` on all hops; control decision + reason + `operation.executed`; `testbed_mode`; artifacts.

**Failure:** Collector down → incomplete Splunk, not fabricated proof. Local artifacts remain.

---

## INV-008 Fail-safe decisions

Missing required security context should not automatically produce ALLOW unless an intentionally vulnerable lab demonstrates this condition.

**`defended`:** Missing profile/config, malformed body, unknown agent, empty input → ERROR or DENY. No LLM call.

**`vulnerable`:** May ALLOW with `control.reason` documenting the missing or skipped check. Workshop must show the label.

This is the invariant the first attack is designed to teach.

---

## Major decisions

### Decision: Invariants are enforced in AcmeBank code, not in Splunk and not in the system prompt

**WHY:** Models miss. Detections fire after the fact.  
**SECURITY:** A hunt is not a control. A polite model is not INV-008.  
**LEARNING:** Where the decision actually happens.

### Decision: Output inspection cannot satisfy “DENY before inference”

**WHY:** Core rule: never report DENY if the dangerous operation already happened.  
**SECURITY:** First slice omits output inspection so the lesson cannot be faked.  
**LEARNING:** Placement vs marketing names.

### Decision: Vulnerable profile is the only allowed automatic fail-open

**WHY:** AgentWatch displayed guard flags that the LLM path ignored.  
**SECURITY:** Defended labs cannot “forget” a check and look secure.  
**LEARNING:** Fail-open vs fail-closed is visible in telemetry.

---

## Tests required when code is claimed complete

| Invariant | Test idea |
|-----------|-----------|
| INV-008 | Defended + injection → DENY, stub LLM call count 0 |
| INV-008 | Vulnerable + same injection → labeled ALLOW |
| INV-008 | Defended + empty/malformed → ERROR, no LLM |
| INV-007 | DENY event includes reason and `operation.executed=false` |
| INV-004 | `run.id` equal across all events of one pipeline |
| INV-005 | Unknown `agent_id` → ERROR, no LLM |
| INV-006 | `/process` cannot be reordered by the payload |
| INV-002 | Stubbed model `{"approve": true}` cannot override prior DENY |
