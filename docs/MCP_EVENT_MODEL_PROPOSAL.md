# MCP Event Model Proposal

**Status:** Phase 3A **proposal** (historical). Adopted subset: `docs/MCP_EVENT_MODEL.md` (schema **1.1.0**, Phase 3B).  
**Parents:** `SECURITY_EVENT_MODEL.md`, `schemas/security_event.schema.json`.  
**OTel references (Development status):** [MCP semantic conventions](https://github.com/open-telemetry/semantic-conventions/blob/v1.41.0/docs/gen-ai/mcp.md), GenAI `execute_tool` / `gen_ai.tool.*` (conventions are moving to the GenAI conventions repo; treat names as **Development**, not stable).  
**Evidence class:** DOCUMENTED.

A future **schema 1.1.0** (or a tightly scoped additive revision) would implement the accepted subset. This file is not that revision.

---

## Principles

1. Prefer **OpenTelemetry GenAI / MCP** names when they mean the same thing.
2. Add `agentsec.*` only for **authorization and evidence** that OTel does not define.
3. Do not invent duplicates (`agentsec.mcp.tool.name` vs `gen_ai.tool.name`).
4. Do not use `mcp.session.id` as the AgentSec hunt key. Keep `agentsec.run.id` = `agentsec.incident.id`.
5. `operation.executed=true` means the **governed tool invoke began**, including later failure.
6. Content: preview + hash for arguments/results; full payloads remain opt-in and dangerous.

---

## Candidate evaluation

| Proposed concept | OTel / existing AgentSec? | Verdict |
|------------------|---------------------------|---------|
| `agentsec.mcp.server.id` | OTel MCP has **no** `mcp.server.id`. Identify the process with `service.name` (and later `server.address` / `network.peer.address` if remote). | **Do not add** for v1. Use `service.name` of the lab MCP server. If multiple lab servers appear, revisit a **low-cardinality** lab id. |
| `agentsec.mcp.tool.name` | OTel: `gen_ai.tool.name` (conditionally required on `tools/call`) | **Do not add.** Use `gen_ai.tool.name`. |
| `agentsec.mcp.operation` | OTel: `mcp.method.name` (e.g. `tools/call`) plus `gen_ai.operation.name=execute_tool` on the execution span | **Do not add.** Use those two. |
| `agentsec.mcp.requested_scope` | No OTel equivalent (authorization, not protocol) | **Add** (AgentSec) |
| `agentsec.mcp.allowed_scope` | No OTel equivalent | **Add** (AgentSec) |
| `agentsec.mcp.parameter.*` | OTel: `gen_ai.tool.call.arguments` (opt-in, high sensitivity) | **Do not explode** `parameter.*` as unbounded keys. Use OTel arguments **preview/hash** via existing AgentSec content policy, or one object field + hash. |
| `agentsec.principal.id` | **Already required** in schema 1.0.0 | **Reuse.** No new field. |
| `agentsec.delegator.agent.id` | **Already** in 1.0.0 (hop.index ≥ 1) | **Reuse.** No new field. First MCP lab may be a single hop (omit delegator). |

### Also reuse as-is

| Field | Role |
|-------|------|
| `agentsec.run.id` / `incident.id` | Correlation |
| `agentsec.control.decision` / `reason` / `id` | ALLOW DENY ERROR |
| `agentsec.security.profile` | defended / vulnerable |
| `agentsec.operation.attempted` / `executed` / `outcome` | Same semantics, **new governed op** |
| `gen_ai.agent.id` | Agent identity |
| `mcp.method.name` | MCP JSON-RPC method (`tools/call`) |
| `mcp.protocol.version` | Only if a real MCP protocol is spoken |
| `error.type` | Tool or control failure |
| `gen_ai.tool.call.result` | Opt-in; prefer preview/hash |

### Explicitly reject from AgentWatch

| Field | Why |
|-------|-----|
| `session.id` | Forbidden hunt key in AgentSec |
| `mcp.gateway.action=BLOCK` | Implies a gateway that regex-scanned prompts |
| `tool.scope_violation` as the only signal | Replace with decision + scopes |
| Hardcoded `mcp.server.id=acme-mcp-gateway-001` | Lied about a server |

### `mcp.session.id` (OTel)

OTel recommends `mcp.session.id` for the **MCP transport session**. If a future real MCP transport needs it, emit it as **OTel MCP session**, never as a substitute for `agentsec.run.id`. Document the name collision with the dropped AgentWatch `session.id`.

---

## Proposed operation type (schema 1.1.0 — not now)

Schema 1.0.0 `operation.type` enum: `pipeline`, `agent_hop`, `control_evaluation`, `llm_inference`, `pipeline_stop`.

Add:

| Value | Governed dangerous operation |
|-------|------------------------------|
| `mcp_tool_invoke` | Lab tool handler invocation (`tools/call` dispatch) |

Control evaluation for MCP remains `control_evaluation` (same as input control), with `control.type` distinguishing MCP vs input (e.g. `mcp_allowlist`).

Proposed events (closed enum today — would extend):

| `event.name` | When |
|--------------|------|
| `agentsec.control.decision` | Unchanged; used for MCP authorize too |
| `agentsec.mcp.started` | Tool handler **began** (`executed=true`) |
| `agentsec.mcp.completed` | Stub returned (`outcome=success`) |
| `agentsec.mcp.failed` | Handler began then failed (`executed=true`, `outcome=error`) |

Do **not** emit `mcp.started` after DENY/ERROR.

Optional: `agentsec.span.kind` add `mcp_tool_invoke`.

---

## Minimum field set for LAB-MCP-001 (when 1.1.0 exists)

On **MCP control.decision** events:

- All 1.0.0 required envelope fields (`run.id`, schema, profile, `testbed.mode`, …)
- `agentsec.control.decision`, `reason`, `id` (e.g. `CTRL-MCP-001`)
- `gen_ai.tool.name` (requested)
- `mcp.method.name` = `tools/call` (if protocol is real; if in-process stub, still set a documented method name and say so)
- `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`
- `operation.type=mcp_tool_invoke` (on that control row) **or** keep control as `control_evaluation` and put tool name on the event — **recommendation:** control event stays `control_evaluation`; tool name/scopes on the same event; `mcp.started` carries `operation.type=mcp_tool_invoke`

On **mcp.started / completed / failed**:

- `gen_ai.tool.name`
- `gen_ai.operation.name=execute_tool` (OTel execute_tool alignment)
- `mcp.method.name=tools/call`
- `attempted=true`, `executed=true`
- completed: `outcome=success`; failed: `outcome=error`

DENY/ERROR control rows: `attempted=false`, `executed=false`, `outcome=prevented`. No mcp.* execution events.

---

## Telemetry sequences (A–E)

Same truth order as the LLM lab:

```text
ATTEMPT (tool request accepted by API)
  → CONTROL EVALUATION
  → CONTROL DECISION
  → OPERATION ATTEMPT (tools/call only if ALLOW)
  → OPERATION EXECUTION (handler began)
  → ACTUAL OUTCOME
  → TELEMETRY
  → EVIDENCE
```

### A — Normal authorized MCP call

```text
run.started
hop.started (if used)
control.decision  ALLOW   attempted=false executed=false  (decision time)
mcp.started                 attempted=true  executed=true
mcp.completed               attempted=true  executed=true  outcome=success
hop.completed / run.completed
```

ALLOW ≠ “tool ran.” `mcp.started` proves begin.

### B — Unauthorized, vulnerable (fail-open)

```text
control.decision  ALLOW   reason=vulnerable_profile_fail_open:…  profile=vulnerable
mcp.started / mcp.completed   executed=true
```

This is **not** prevention. Do not emit DENY.

### C — Unauthorized, defended DENY

```text
control.decision  DENY   attempted=false executed=false outcome=prevented
pipeline.stopped (if the run ends)
run.completed
```

**No** `mcp.started`. Runtime: handler counter unchanged.

### D — MCP tool execution failure (after ALLOW)

```text
control.decision  ALLOW
mcp.started                 executed=true
mcp.failed                  executed=true  outcome=error
```

Failure ≠ DENY ≠ prevention. Analogous to `llm.failed`.

### E — Authorization / control evaluation failure

```text
control.decision  ERROR   attempted=false executed=false outcome=prevented
```

Reasons: unknown tool, missing agent id, missing allow-list, malformed request, control exception. **No** `mcp.started`. Distinct from C (DENY = policy said no; ERROR = could not decide safely).

---

## Evidence hierarchy (unchanged)

```text
AUTHORITATIVE RUNTIME STATE     (did the stub run? spy/counter)
  → LOCAL RUN EVIDENCE          artifacts/<run-id>/
  → EXPORTED TELEMETRY
  → SPLUNK REPRESENTATION       corroboration only
```

Splunk with no `mcp.started` does **not** prove DENY unless completeness for that `run.id` is established.

---

## Open schema questions (Phase 3A) — resolved in 3B

1. In-process lab without JSON-RPC: still set `mcp.method.name=tools/call`, or wait until a real MCP SDK is used? **3B: in-process JSON-RPC `tools/call` with `mcp.method.name=tools/call`. No initialize handshake; `mcp.protocol.version` not emitted.**
2. Should `gen_ai.tool.call.arguments` ever be full JSON in the lab index? **3B: no. Preview + hash.**
3. Timing of schema bump: **3B: 1.1.0 when LAB-MCP-001 runtime landed.**
4. Registered-but-denied vs omitted unauthorized tool: **3B: `lookup_customer_tier` is registered and not granted (workshop attack). Unknown names remain ERROR.**

Phase 3A text below this heading originally said schema 1.0.0 must not change; that freeze applied to 3A only.
