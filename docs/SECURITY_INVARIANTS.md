# Security Invariants

**Status:** PLANNED  
**Source:** AgentSec rule INV-001–INV-008, mapped to this architecture.

An invariant is a property that must remain true even when the attacker controls the payload. Labs may **violate** an invariant only in the `vulnerable` profile, and only when telemetry says so.

---

## INV-001 Delegated authorization

An agent cannot receive more authority than was explicitly delegated.

**Phase 1:** Agents have no tools. Authority is “may call Ollama with this system prompt.” Pipeline order is code. A prompt cannot add a new agent or tool.

**Later:** Tool/MCP allowlist checked **before** invocation. Delegation object, not retrieved text.

**Vulnerable exception:** none required in Phase 1.

---

## INV-002 Data cannot grant authority

Retrieved content cannot independently authorize privileged actions.

**Phase 1:** No RAG. Model output cannot mint ALLOW after DENY. Model JSON is not policy.

**Later:** RAG hits are data. They cannot expand tools or skip HITL.

---

## INV-003 Memory trust isolation

Untrusted memory cannot silently become trusted instruction.

**Phase 1:** No durable memory. Session ring is display-only.

**Later:** Memory records carry trust labels. Untrusted facts cannot become system prompt without a control decision.

---

## INV-004 Privileged action attribution

Privileged actions must be attributable to a known principal or delegation.

**Phase 1:** Every LLM call and control decision carries `run.id`, `gen_ai.agent.id`, `security.profile`. `run.id` is server-minted.

**Later:** Delegation id on tool calls.

---

## INV-005 Agent identity integrity

Agent impersonation must be rejected or detectable.

**Phase 1:** No A2A network. Agent id is selected from an allow-list on the API (`/agent/<id>` or full pipeline). Unknown ids → ERROR.

**Later:** Cryptographic or explicit passport check; fail closed in `defended`. SIMULATED impersonation hunts must be labeled.

---

## INV-006 Workflow integrity

Privileged workflow transitions require authorized state transitions.

**Phase 1:** The only transition is the coded sequence intake → doc → risk → compliance. The model cannot reorder agents.

**Later:** State machine; forged “orchestrator_override” cannot skip steps in `defended`.

---

## INV-007 Evidence integrity

Security-sensitive actions must generate enough telemetry for reconstruction.

**Phase 1:** `run.id` on all hops; control decision + reason + `operation_executed`; `testbed_mode`; artifacts pack.

**Failure:** Collector down → incomplete evidence, not fabricated Splunk proof.

---

## INV-008 Fail-safe decisions

Missing required security context should not automatically produce ALLOW unless an intentionally vulnerable lab demonstrates this condition.

**Phase 1 `defended`:** Missing profile, malformed body, unknown agent → ERROR or DENY. No LLM call.

**Phase 1 `vulnerable`:** May ALLOW with `control.reason` documenting the missing check. Workshop must show the label.

---

## Major decisions

### Decision: Invariants are enforced in AcmeBank code, not in Splunk and not in the system prompt

**DECISION:** Prompts may describe policy. Only reference controls decide.

**ALTERNATIVES:** Prompt-only safety; detection-only safety.

**WHY CHOSEN:** Models miss; detections fire after the fact.

**SECURITY CONSEQUENCE:** A hunt is not a control. A polite model is not INV-008.

**LEARNING VALUE:** Where the decision actually happens.

### Decision: Output inspection cannot satisfy “DENY before inference”

**DECISION:** Post-LLM matches are SANITIZE, OBSERVE, or ERROR on export — never DENY of the call that already succeeded.

**ALTERNATIVES:** AgentWatch-style HARD_DENY after `/api/generate`.

**WHY CHOSEN:** Core rule: never report DENY if the dangerous operation already happened.

**SECURITY CONSEQUENCE:** Token spend and model side effects already occurred; telemetry tells the truth.

**LEARNING VALUE:** Placement vs marketing names (Gate vs Sentinel).

### Decision: Vulnerable profile is an explicit invariant exception

**DECISION:** `security.profile=vulnerable` is the only allowed automatic fail-open.

**ALTERNATIVES:** Hidden flags; env vars that UI shows but code ignores (AgentWatch).

**WHY CHOSEN:** INV-008 requires intention and evidence.

**SECURITY CONSEQUENCE:** Defended labs cannot “forget” a check and look secure.

**LEARNING VALUE:** Fail-open vs fail-closed is a lab switch you can see in Splunk.

---

## Phase 1 proof tests (required when code exists)

| Invariant | Test idea |
|-----------|-----------|
| INV-004 | `run.id` equal across all events of one pipeline |
| INV-005 | Unknown `agent_id` → ERROR, no LLM stub call |
| INV-006 | Custom path cannot invoke agents out of order |
| INV-007 | DENY event includes reason and `operation_executed=false` |
| INV-008 | Defended + missing profile → ERROR; vulnerable + missing check → labeled ALLOW |
| INV-002 | Stubbed model saying `{"approve": true}` cannot override prior DENY |
