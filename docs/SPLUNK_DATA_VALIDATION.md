# Splunk Data Validation

**Status:** Emit-path MEASURED. Splunk ingest **NOT MEASURED**. No SPL in this document. No dashboards.

## How this was validated

| Check | Result | Evidence class |
|-------|--------|----------------|
| Local pipeline emit (stub LLM, closed schema) | BASELINE ATK-001 produced 8 events; LIVE ATK-002 produced 2 events | **MEASURED** 2026-09-04T01:59:05Z |
| Pytest hunt-field presence | `40 passed` including `test_hunt_fields_present_on_every_pipeline_event` | **MEASURED** |
| Splunk Web `http://127.0.0.1:8000` | Connection failed (HTTP 000) | **OBSERVED** |
| Docker / local compose | `docker` binary not present; no `.env`; no HEC on `:8088` | **OBSERVED** |
| Live Ollama / live HEC fields | Not run | **NOT MEASURED** |

Do not write or approve SPL until a lab Splunk instance returns these same JSON keys on `_raw` / KV extraction.

Do **not** search AgentWatch names (`run.id`, `trace.id`, `incident.id`, `agent.role` as bare fields). Those strings are hunt labels. The indexed names are in **SOURCE** below.

## Telemetry fixes applied before any SPL

These were unreliable or missing on the emit path:

1. **`agent.role`** — not emitted. `gen_ai.agent.description` is a sentence, not a role. Runtime now always sets `agentsec.agent.role` (`intake` \| `credit` \| `risk` \| `compliance`).
2. **OTLP log body** — was `json.dumps(event)` (a string). HEC/JSON extraction of a quoted string is unreliable (**INFERRED**). Body is now the event **map**, and hunt keys are also copied to OTLP attributes.

No SPL was added.

---

## Field catalog

Hunt label → actual JSON key. Example values are from the MEASURED stub-LLM runs above (not Splunk).

### timestamp

| | |
|--|--|
| **FIELD** | `timestamp` |
| **SOURCE** | AcmeBank `EventBuilder` (`utc_now()` RFC3339 Zulu) |
| **EXAMPLE VALUE** | `2026-09-04T01:59:05Z` |
| **EVENT TYPES** | All runtime events (`control_decision`, `normal_request`, `agent_handoff`, `prompt_attack`) |
| **WHY WE NEED IT** | Order hops; time picker; reconstruct a run |
| **NULLABLE?** | No (schema required) |
| **ACTUAL VALIDATION RESULT** | **MEASURED** present on 8/8 baseline and 2/2 attack events. **NOT MEASURED** as Splunk `_time`. OTLP also has a log timestamp that may differ by milliseconds (**INFERRED**). |

### run.id

| | |
|--|--|
| **FIELD** | Hunt label `run.id` → **`agentsec.run.id`** |
| **SOURCE** | Server-minted UUID in `RunContext.mint`. HTTP JSON `run.id` is ignored |
| **EXAMPLE VALUE** | `97c7d156-f48d-47de-a25f-58b3c74f9120` (baseline); `fe688977-66b6-420d-9bbf-0617ecc0bded` (attack) |
| **EVENT TYPES** | All hops of one pipeline share one value |
| **WHY WE NEED IT** | INV-007 reconstruction; Q-RUN |
| **NULLABLE?** | No |
| **ACTUAL VALIDATION RESULT** | **MEASURED** one UUID per run across all events. Bare `run.id` is **not** in the event body — SPL on `run.id` would miss. Splunk: **NOT MEASURED**. |

### trace.id

| | |
|--|--|
| **FIELD** | Hunt label `trace.id` → **`trace_id`** |
| **SOURCE** | 32-char hex from `secrets.token_hex(16)`; also OTLP `LogRecord.trace_id` |
| **EXAMPLE VALUE** | `c6ac52f446e59d75b0be1559d24b5151` |
| **EVENT TYPES** | All events in the run |
| **WHY WE NEED IT** | Join hops; OTel correlation |
| **NULLABLE?** | No |
| **ACTUAL VALIDATION RESULT** | **MEASURED** shared across the run; pattern `[0-9a-f]{32}`. There is **no** `trace.id` key. Splunk: **NOT MEASURED**. |

### incident.id

| | |
|--|--|
| **FIELD** | Hunt label `incident.id` → **`agentsec.incident.id`** |
| **SOURCE** | Minted only when `testbed_mode=LIVE` **and** `technique_id` is set (`INC-` + first 8 hex of `run.id`) |
| **EXAMPLE VALUE** | Attack: `INC-fe688977`. Baseline: absent |
| **EVENT TYPES** | Present on LIVE ATK-002 (`control_decision`, `prompt_attack`). Absent on BASELINE ATK-001 |
| **WHY WE NEED IT** | Group related attacks; later chains |
| **NULLABLE?** | Yes — expected empty on benign/baseline |
| **ACTUAL VALIDATION RESULT** | **MEASURED** 0/8 baseline; 2/2 attack. Not a defect. Splunk: **NOT MEASURED**. |

### agent.id

| | |
|--|--|
| **FIELD** | Hunt label `agent.id` → **`gen_ai.agent.id`** |
| **SOURCE** | Coded `AgentSpec.agent_id` |
| **EXAMPLE VALUE** | `acme-agent-intake-001`, `acme-agent-credit-002`, `acme-agent-risk-003`, `acme-agent-compliance-004` |
| **EVENT TYPES** | All runtime events (one agent per hop) |
| **WHY WE NEED IT** | Which hop acted; INV-004 |
| **NULLABLE?** | No |
| **ACTUAL VALIDATION RESULT** | **MEASURED** always set. Splunk: **NOT MEASURED**. |

### agent.role

| | |
|--|--|
| **FIELD** | Hunt label `agent.role` → **`agentsec.agent.role`** |
| **SOURCE** | Coded `AgentSpec.role` (not model output, not description text) |
| **EXAMPLE VALUE** | `intake`, `credit`, `risk`, `compliance` |
| **EVENT TYPES** | All runtime hops after the telemetry fix |
| **WHY WE NEED IT** | Hunt by function without parsing display names |
| **NULLABLE?** | Optional in schema (old fixtures). **Required on Phase 2 runtime emit** |
| **ACTUAL VALIDATION RESULT** | Previously **unreliable** (field missing; description is prose). **FIXED** then **MEASURED** 8/8 baseline, 2/2 attack. Splunk: **NOT MEASURED**. |

### principal

| | |
|--|--|
| **FIELD** | Hunt label `principal` → **`agentsec.principal.id`** + **`agentsec.principal.type`** |
| **SOURCE** | `user_id` from HTTP / baseline ticker; type is always `user` in Phase 2 |
| **EXAMPLE VALUE** | Baseline `applicant-web` / `user`; Attack `attacker-lab` / `user` |
| **EVENT TYPES** | All runtime events |
| **WHY WE NEED IT** | INV-004: whose authority, distinct from which agent |
| **NULLABLE?** | No |
| **ACTUAL VALIDATION RESULT** | **MEASURED** always present. Phase 2 has no agent-as-principal. Splunk: **NOT MEASURED**. |

### model

| | |
|--|--|
| **FIELD** | Hunt label `model` → **`gen_ai.request.model`** (configured) and **`gen_ai.response.model`** (after a successful call) |
| **SOURCE** | Settings `OLLAMA_MODEL`; response model from LLM result |
| **EXAMPLE VALUE** | Request: `llama3.2:1b`. Response on ALLOW stub: `stub-model`. DENY: response model **absent** |
| **EVENT TYPES** | Request model on all events. Response model only when `operation.executed=true` |
| **WHY WE NEED IT** | Know which model was targeted vs which answered |
| **NULLABLE?** | Request: present in emit. Response: yes, when LLM did not run |
| **ACTUAL VALIDATION RESULT** | **MEASURED** request 8/8 and 2/2. Response 8/8 baseline, 0/2 DENY (correct). Live Ollama model string **NOT MEASURED**. Splunk: **NOT MEASURED**. |

### security technique

| | |
|--|--|
| **FIELD** | Hunt label `security technique` → **`agentsec.technique.id`** |
| **SOURCE** | Attack Service / pipeline `technique_id` (ATK-002: `AML.T0054`). Not copied from attacker as a control decision |
| **EXAMPLE VALUE** | Attack: `AML.T0054`. Baseline: absent |
| **EVENT TYPES** | LIVE ATK-002 events. Not on benign BASELINE |
| **WHY WE NEED IT** | Map hunts to ATLAS; must not authorize |
| **NULLABLE?** | Yes on benign |
| **ACTUAL VALIDATION RESULT** | **MEASURED** 0/8 baseline; 2/2 attack. Splunk: **NOT MEASURED**. |

### control

| | |
|--|--|
| **FIELD** | Hunt label `control` → **`agentsec.control.id`** |
| **SOURCE** | `CTRL-INPUT-001` from `inspect_input` |
| **EXAMPLE VALUE** | `CTRL-INPUT-001` |
| **EVENT TYPES** | All Phase 2 hops |
| **WHY WE NEED IT** | Which reference control decided |
| **NULLABLE?** | No |
| **ACTUAL VALIDATION RESULT** | **MEASURED** always `CTRL-INPUT-001`. Splunk: **NOT MEASURED**. |

### decision

| | |
|--|--|
| **FIELD** | Hunt label `decision` → **`agentsec.control.decision`** |
| **SOURCE** | Control result inside AcmeBank. Attacker JSON cannot set it |
| **EXAMPLE VALUE** | Baseline `ALLOW`; ATK-002 `DENY` |
| **EVENT TYPES** | All runtime events |
| **WHY WE NEED IT** | Q-DENY; honest DENY vs ALLOW |
| **NULLABLE?** | No |
| **ACTUAL VALIDATION RESULT** | **MEASURED**. DENY events have `agentsec.operation.executed=false`. Splunk: **NOT MEASURED**. |

### reason

| | |
|--|--|
| **FIELD** | Hunt label `reason` → **`agentsec.control.reason`** |
| **SOURCE** | Control code (`benign_loan_request`, `input_pattern_matched`, `vulnerable_profile_fail_open:<rule>`) |
| **EXAMPLE VALUE** | `benign_loan_request` / `input_pattern_matched` |
| **EVENT TYPES** | All runtime events |
| **WHY WE NEED IT** | Why ALLOW/DENY/ERROR; INV-008 teaching |
| **NULLABLE?** | No |
| **ACTUAL VALIDATION RESULT** | **MEASURED** non-empty on all emitted events. Splunk: **NOT MEASURED**. |

### provenance

| | |
|--|--|
| **FIELD** | Hunt label `provenance` → **`agentsec.content.origin.type`**, **`agentsec.content.origin.id`**, **`agentsec.content.influence.kind`**, plus preview/hash |
| **SOURCE** | First hop: user + `user.id`. Later hops: `agent` + prior `gen_ai.agent.id`, kind `prior_agent_output` |
| **EXAMPLE VALUE** | Intake: `user` / `applicant-web` / `user_message`. Credit: `agent` / `acme-agent-intake-001` / `prior_agent_output`. Hash `sha256:` + 64 hex |
| **EVENT TYPES** | All Phase 2 runtime events (builder always passes content on these hops) |
| **WHY WE NEED IT** | INV-002 / INV-007: what text influenced the hop without storing the full prompt |
| **NULLABLE?** | Schema optional; **present on Phase 2 pipeline emit** |
| **ACTUAL VALIDATION RESULT** | **MEASURED** origin/kind/preview/hash on 8/8 and 2/2. Preview is truncated to 200 chars. Splunk: **NOT MEASURED**. |

---

## Event types observed (MEASURED)

| `event.name` | When |
|--------------|------|
| `agentsec.control_decision` | Every hop |
| `agentsec.normal_request` | First hop ALLOW |
| `agentsec.agent_handoff` | Hops 2–4 ALLOW |
| `agentsec.prompt_attack` | Injection rule matched (ATK-002) |

Fixture-only names (`tool_*`, `a2a_*`, `memory_*`, `rag_*`, `attack_chain_step`) are **not** emitted by Phase 2 runtime.

## Gate for SPL (not started)

SPL may start only after **MEASURED** Splunk results show:

1. Index `agentsec_telemetry`, sourcetype `otel:agentic:json`
2. Keys `agentsec.run.id`, `trace_id`, `gen_ai.agent.id`, `agentsec.agent.role`, `agentsec.control.decision` extracted (not stuck inside a quoted string)
3. One known `agentsec.run.id` from `artifacts/<run-id>/events.jsonl` searchable in Splunk

Until then: **NOT YET VALIDATED** for Splunk. Local Python hunts in `agentsec.detections` remain `splunk_validated: false`.
