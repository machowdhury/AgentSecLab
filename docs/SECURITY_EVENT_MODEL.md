# Security Event Model

**Status:** PLANNED schema (fixtures are SIMULATED representatives). Not live AcmeBank telemetry.  
**Schema:** `schemas/security_event.schema.json`  
**Fixtures:** `telemetry/events/`  
**Tests:** `tests/telemetry/test_security_event_schema.py`

Do not invent Splunk fields. Hunt only names listed here. OpenTelemetry GenAI conventions are **Development** stability; AgentSec pins the names below.

---

## How Splunk answers the investigation questions

| Question | Fields (OTel first, then AgentSec) |
|----------|-------------------------------------|
| WHO initiated the activity? | `user.id` |
| WHICH principal? | `agentsec.principal.id`, `agentsec.principal.type` |
| WHICH agent? | `gen_ai.agent.id`, `gen_ai.agent.name` |
| WHICH agent delegated authority? | `agentsec.delegator.agent.id` |
| WHICH model? | `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.provider.name` |
| WHAT content influenced the action? | `agentsec.content.influence.kind`, `agentsec.content.preview`, `agentsec.content.hash` |
| WHERE did that content originate? | `agentsec.content.origin.type`, `agentsec.content.origin.id`, `gen_ai.data_source.id` |
| WHAT tool? | `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.type` |
| WHAT operation? | `gen_ai.operation.name`, `event.name` |
| WHAT requested scope? | `agentsec.scope.requested` |
| WHAT allowed scope? | `agentsec.scope.allowed` |
| WHICH control? | `agentsec.control.id` |
| WHAT decision? | `agentsec.control.decision` |
| WHY? | `agentsec.control.reason` |
| WHICH attack technique? | `agentsec.technique.id` |
| WHICH trust boundary? | `agentsec.trust_boundary` |
| WHICH invariant? | `agentsec.invariant.id` |
| WHICH trace, run, incident and chain? | `trace_id`, `span_id`, `parent_span_id`, `agentsec.run.id`, `agentsec.incident.id`, `agentsec.chain.id`, `agentsec.chain.stage_num` |

Not every event populates every field. The **schema** allows the answers. Tool questions are empty on a normal chat event; that is correct.

Research packs still record `run.id` as equal to `agentsec.run.id` (same UUID).

---

## OTel names used (no AgentSec synonym)

| Attribute | Role |
|-----------|------|
| `event.name` | Log event type |
| `user.id` | Human or lab client that started the HTTP activity |
| `service.name` / `service.version` | AcmeBank identity / AgentSec version |
| `deployment.environment` | `lab` |
| `trace_id` / `span_id` / `parent_span_id` | Trace correlation |
| `error.type` | Dependency/schema failures |
| `gen_ai.provider.name` | `ollama` |
| `gen_ai.request.model` / `gen_ai.response.model` | Model |
| `gen_ai.operation.name` | `chat`, `invoke_agent`, `execute_tool`, `create_memory`, `search_memory`, `retrieve` |
| `gen_ai.agent.*` | Which agent |
| `gen_ai.conversation.id` | Session/conversation when the app already has one (not a new UUID invented as a fallback) |
| `gen_ai.workflow.name` | `loan_pipeline` |
| `gen_ai.usage.input_tokens` / `output_tokens` | Usage; zero when DENY before call |
| `gen_ai.tool.*` | Tool identity |
| `gen_ai.memory.*` | Memory store/record |
| `gen_ai.data_source.id` / `gen_ai.retrieval.*` | RAG origin |

Full prompts, `gen_ai.input.messages`, and tool arguments are **not** in the default event body (sensitive). Influence is preview + hash only.

---

## AgentSec extensions (`agentsec.*`)

Added only because OTel GenAI has no equivalent for lab security reconstruction:

| Field | Why OTel is not enough |
|-------|------------------------|
| `agentsec.run.id` | Experiment/pipeline id required by AgentSec research rules |
| `agentsec.lab.id` | Lab instance (`agentsec-local`) |
| `agentsec.incident.id` | Investigation id that may span several runs |
| `agentsec.chain.id` / `stage_num` / `stage_name` | Kill-chain teaching |
| `agentsec.security.profile` | `defended` \| `vulnerable` |
| `agentsec.testbed.mode` | `BASELINE` \| `LIVE` \| `HYBRID` \| `SIMULATED` |
| `agentsec.principal.*` | Authority holder (user vs agent vs system) |
| `agentsec.delegator.agent.id` | Which agent delegated |
| `agentsec.trust_boundary` | Named boundary from `TRUST_BOUNDARIES.md` |
| `agentsec.invariant.id` | INV-001–008 |
| `agentsec.control.id` / `decision` / `reason` | Reference control outcome |
| `agentsec.operation.executed` | Honest DENY (must be false when decision is DENY) |
| `agentsec.scope.requested` / `allowed` | INV-001 |
| `agentsec.technique.id` | ATLAS id; not authorization |
| `agentsec.content.influence.*` / `origin.*` | Content provenance without full prompt dump |
| `agentsec.memory.trust_level` | INV-003 (`untrusted` \| `trusted` \| `quarantined`) |

Do **not** emit attacker-supplied `agentsec.control.decision`. Closed schema: `additionalProperties: false`.

---

## event.name vocabulary

| event.name | Representative file |
|------------|---------------------|
| `agentsec.normal_request` | `telemetry/events/normal_request.json` |
| `agentsec.agent_handoff` | `agent_handoff.json` |
| `agentsec.prompt_attack` | `prompt_attack.json` |
| `agentsec.tool_request` | `tool_request.json` |
| `agentsec.tool_denied` | `tool_denied.json` |
| `agentsec.a2a_delegation` | `a2a_delegation.json` |
| `agentsec.memory_write` | `memory_write.json` |
| `agentsec.memory_read` | `memory_read.json` |
| `agentsec.rag_retrieval` | `rag_retrieval.json` |
| `agentsec.control_decision` | `control_decision.json` |
| `agentsec.attack_chain_step` | `attack_chain_step.json` |

Tool, A2A, memory, RAG, and chain fixtures are **schema examples** for later surfaces. They are not IMPLEMENTED runtime until AcmeBank emits them.

---

## Control decisions

ALLOW, DENY, SANITIZE, QUARANTINE, REQUIRE_APPROVAL, OBSERVE, ERROR.

**DENY ⇒ `agentsec.operation.executed` = false** (enforced in schema).

---

## Correlation rules

| Id | Granularity |
|----|-------------|
| `agentsec.run.id` | One HTTP/pipeline request; all hops share it |
| `trace_id` | Same as that run in Phase 1; child `span_id` per hop |
| `agentsec.incident.id` | Optional; shared across chain stages or related attacks |
| `agentsec.chain.id` | Kill chain (later) |

Normal request and agent handoff fixtures share one `run.id` and `trace_id`; handoff `parent_span_id` is the intake `span_id`.

---

## Major decisions

### Decision: Standard GenAI names; `agentsec.*` only for security reconstruction

**DECISION:** As tabulated above.

**ALTERNATIVES:** Reuse AgentWatch `acme_*` / `incident_id` per hop; invent `who`/`why` fields; dump full prompts.

**WHY CHOSEN:** Splunk can join on names other OTel-aware tools already use. Security questions OTel does not cover stay in one prefix.

**SECURITY CONSEQUENCE:** Attackers cannot add `control.decision`. Full prompts stay out of default logs. DENY cannot claim the LLM/tool ran.

**LEARNING VALUE:** One mapping table from SOC question → field.

### Decision: Principal is not the same as initiator or agent

**DECISION:** `user.id` = who started the activity. `agentsec.principal.*` = whose authority is being used. `gen_ai.agent.id` = which agent code path.

**ALTERNATIVES:** One `actor` field.

**WHY CHOSEN:** A2A and tool calls confuse “who clicked” vs “which agent is acting.”

**SECURITY CONSEQUENCE:** INV-004 attribution stays explicit.

**LEARNING VALUE:** Delegation is visible (`agentsec.delegator.agent.id`).

### Decision: Content is origin + kind + preview + hash

**DECISION:** No default `gen_ai.input.messages`.

**ALTERNATIVES:** Always capture full chat history (OTel opt-in).

**WHY CHOSEN:** PII/prompt leakage into Splunk. Hash supports integrity without storing the attack string in full.

**SECURITY CONSEQUENCE:** INV-007 without turning the SIEM into a prompt archive.

**LEARNING VALUE:** Learners still see what *kind* of content mattered.

---

## Tests

Run: `pytest tests/telemetry/test_security_event_schema.py`

Do not claim pass unless executed.
