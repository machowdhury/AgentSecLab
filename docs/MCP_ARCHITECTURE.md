# MCP Architecture (AgentSec)

**Status:** Phase 3A planning (historical). Phase 3B implemented the dedicated-agent path in `MCP_RUNTIME_CONTRACT.md`. Schema **1.1.0**.  
**Parent contracts:** `ARCHITECTURE.md`, `TRUST_BOUNDARIES.md`, `SECURITY_INVARIANTS.md`, `ATTACK_CONTROL_MODEL.md`, `SECURITY_EVENT_MODEL.md`, `MCP_EVENT_MODEL.md`.  
**Predecessor:** `MCP_PREDECESSOR_ANALYSIS.md` (do not copy AgentWatch `mcp_gateway.py`).  
**Evidence class:** DOCUMENTED design. Not OBSERVED runtime.

This is a **lab-minimal** MCP picture. It is not production IAM, not a full MCP product, and not Cisco MCP Scanner.

---

## WHAT IS IT?

**MCP (Model Context Protocol)** is a JSON-RPC protocol so an **MCP client** (here: the agent runtime) can list and call **tools** on an **MCP server**.

In AgentSec, the first MCP slice is:

```text
User / Attack Service
  → Agent (coded identity + requested tool)
    → MCP client (in AcmeBank)
      → MCP server (lab process)
        → Tool handler (deterministic stub)
```

The **governed dangerous operation** for MCP labs is **tool execution** (`tools/call` reaching the tool handler), not LLM inference. LLM inference remains a separate governed operation (LAB-PI-001).

## WHY DOES IT EXIST?

Prompt injection (ATK-002) teaches “untrusted text must not reach the model without a decision.”

MCP teaches the next surface: **untrusted requests must not run tools without a decision**, and **tool results are data, not new authority**.

AgentWatch labeled regex-on-prompt as this surface. AgentSec will not.

## HOW DOES IT WORK? (planned)

1. A **principal** (lab user) starts a run.
2. An **agent** with a coded identity requests a tool (`name` + `arguments` + requested scope).
3. A **reference control** evaluates `(principal, agent, tool, action, requested_scope, allowed_scope, parameters)` **before** the client sends `tools/call` (and the **server** must also refuse unknown/unauthorized tools — client-only checks are not enough).
4. On ALLOW, the server invokes the tool stub. On DENY or ERROR, the tool handler **does not run**.
5. Telemetry records the decision and whether execution **began**.
6. Tool return value is **data**. It cannot expand `allowed_scope`.

First implementation lab is **deterministic**: the workshop submits a structured tool request. The LLM does **not** choose the tool. That keeps ALLOW/DENY testable without model variance.

## WHERE DOES IT SIT IN AGENTSEC?

| Layer | Role |
|-------|------|
| Attack Service / browser | Untrusted client (same as Phase 2) |
| AcmeBank agent | Holds coded agent identity; acts as MCP **client** |
| Reference control | Lab policy; ALLOW / DENY / ERROR |
| Lab MCP **server** | Tool registry + invoke |
| Tool stub | Deterministic handler; not OS shell |
| OTel → Splunk | Evidence bus / SOC; cannot authorize |

Out of first MCP lab: real RCE tools, community MCP registries, Cisco scanner, Dashboard Studio, A2A, RAG.

---

## Trust boundaries

Authority enters only from **coded policy** (agent identity + allow-list + run profile).  
Data enters from **user input, tool arguments, and tool results**.

```text
UNTRUSTED                         BOUNDARY                         LAB-TRUSTED (not production)
─────────                         ────────                         ───────────────────────────
Learner / Attack Service  ─HTTP─► AcmeBank API
Structured tool request           acmebank.http_api
                                  │
                                  │  agent identity is CODED
                                  │  (not taken from tool payload)
                                  ▼
                           acmebank.mcp.authorize          ← control BEFORE invoke
                                  │
                    DENY / ERROR ─┴─ no tools/call
                    ALLOW
                                  │
                           acmebank.mcp.client
                                  │  JSON-RPC tools/call
                                  ▼
                           mcp.server.invoke              ← server must re-check
                                  │
                    unknown/deny ─┴─ no handler
                    ALLOW
                                  ▼
                           mcp.tool.execute               ← dangerous op BEGINS
                                  │
                                  ▼
                           mcp.tool.result                ← DATA, not authority
                                  │
                           acmebank.agent_handoff         ← must not mint new tools
                                  ▼
                           observability.export           ← OBSERVE ONLY
```

### Named MCP boundaries (additive to `TRUST_BOUNDARIES.md`)

| Id | Untrusted side | Trusted side | Dangerous operation |
|----|----------------|--------------|---------------------|
| `acmebank.http_api` | Browser, Attack Service | AcmeBank | Accepting a run / tool request |
| `acmebank.mcp.authorize` | Requested tool, args, claimed identity in payload | Reference control + coded agent id | Deciding whether invoke may proceed |
| `mcp.client.request` | Agent intent (may be attacker-influenced later) | MCP client library | Sending `tools/call` |
| `mcp.server.invoke` | Client JSON-RPC (untrusted network/process peer in a real deployment; lab-local in v1) | MCP server policy + registry | Dispatch to a tool handler |
| `mcp.tool.execute` | Validated args still **data** | Tool stub | **Tool execution begins** |
| `mcp.tool.result` | Tool output | Agent context | **None by itself** — result must not grant tools |
| `mcp.external_resource` | Files, URLs, banks the tool might touch | (out of first lab) | Side effects |
| `observability.export` | Event payload | Collector / Splunk / artifacts | None |

### Zones

| Zone | Members | May authorize a tool call? |
|------|---------|----------------------------|
| Untrusted client | Browser, Attack Service | No |
| Agent | Coded hop identity, prompts (later) | **No** — agent *requests*; control *decides* |
| Enforcement | Reference control + MCP server allow-list | Yes (lab policy) |
| MCP server | Lab registry + dispatch | Yes (must fail closed) |
| Tool | Stub handler | No — executes only if already allowed |
| Untrusted model | Ollama (not in first MCP lab path) | No |
| Observability | OTel, Splunk, artifacts | No |

**DATA MUST NOT GRANT AUTHORITY.** A tool result, a document, or a “you are now admin” string cannot add tools, widen `allowed_scope`, or flip DENY to ALLOW.

---

## Authorization model (reference, testable)

Not production IAM. A single policy object the control can evaluate.

### Request (what the agent asks)

| Field | Meaning |
|-------|---------|
| `principal.id` | Lab user / initiator (`user.id` / `agentsec.principal.id`) |
| `principal.type` | `user` \| `agent` \| `system` |
| `agent.id` | Coded agent identity (`gen_ai.agent.id`) |
| `delegator.agent.id` | Prior hop if in-process pipeline; omit on first hop |
| `tool.name` | Requested tool id (e.g. `lookup_policy`) |
| `action` | MCP method; first labs: `tools/call` |
| `requested_scope` | What the caller claims to need (e.g. `policy:read`) |
| `parameters` | Tool arguments (data) |

### Policy (what was delegated)

| Field | Meaning |
|-------|---------|
| `allowed_tools` | Explicit list for **this** `agent.id` |
| `allowed_scope` | Explicit scopes for that tool (e.g. `policy:read`) |
| `parameter_schema` | Allowed keys/types/bounds (MCP-004) |

### Decision

Use existing AgentSec decisions. First MCP labs primarily:

| Decision | Meaning for MCP |
|----------|-----------------|
| **ALLOW** | Invoke may proceed. Does **not** by itself prove execution. |
| **DENY** | Tool handler **must not** run. `attempted=false`, `executed=false`, `outcome=prevented`. Reason required. |
| **ERROR** | Missing/malformed security context, unknown tool, or control failure **before** invoke. Same operation flags as DENY. Not a synonym for DENY (different reason). |

Reserved for later MCP labs (do not implement in the first lab):

| Decision | Later use |
|----------|-----------|
| SANITIZE | Rewrite args or strip result (still data) |
| QUARANTINE | Isolate result |
| REQUIRE_APPROVAL | HITL before privileged tools |
| OBSERVE | Allow but label (never a silent fail-open) |

Every decision has `control.reason`. Vulnerable-profile fail-open MUST set `security.profile=vulnerable` and a labeled reason (same honesty as CTRL-INPUT-001).

### Evaluation rules (first labs)

1. **Unknown tool** (not in the **registry**) → **ERROR** (INV-008). Not ALLOW.
2. **Known tool, not in this agent’s `allowed_tools`** → **DENY**.
3. **Scope**: `requested_scope` must be ⊆ `allowed_scope` or **DENY** (MCP-003). First lab may use a single scope string.
4. **Identity**: `agent.id` from coded runtime, **never** from tool arguments or tool results (INV-005).
5. **Server re-check**: even if the client is buggy, the server must not dispatch unauthorized tools.
6. **Parameters**: first lab may accept a single well-typed argument; invalid args → **ERROR** before execute (MCP-004 expands this).

---

## Invariant mapping

No new invariant. MCP is where INV-001 becomes a **tool** property.

| Invariant | MCP meaning | First lab (MCP-001/002) |
|-----------|-------------|-------------------------|
| **INV-001** Delegated authorization | Agent cannot invoke tools beyond explicit grant | Primary teaching invariant |
| **INV-002** Data cannot grant authority | Tool results and args cannot add tools or widen scope | Stated; exercised in MCP-005 |
| **INV-004** Privileged action attribution | Tool invoke attributed to principal + agent (+ delegator) | Required on every MCP control/tool event |
| **INV-005** Agent identity integrity | Payload cannot spoof `agent.id` | Coded id; unknown agent → ERROR |
| **INV-007** Evidence integrity | Decision, reason, attempted/executed/outcome, `run.id` | Same evidence hierarchy as LLM labs |
| **INV-008** Fail-safe decisions | Unknown tool / missing policy → ERROR or DENY, not ALLOW | Unknown → ERROR; unauthorized → DENY |

INV-003 (memory) and INV-006 (workflow state machine) are not required to express MCP-001–006. Confused deputy (MCP-006) is INV-001 + INV-004 (+ INV-005 if identity is confused). Do not add INV-009.

---

## Control placement vs LLM

```text
LAB-PI-001:   HTTP → input control → LLM
LAB-MCP-001:  HTTP → MCP authorize → tools/call → tool stub
```

Do **not** collapse these. Skipping Ollama is not proof a tool was blocked. Skipping a tool is not proof the LLM was blocked.

If a future lab lets the model *propose* a tool call, order is:

```text
input control → LLM (may emit a tool proposal — DATA)
  → MCP authorize (proposal is the request, not authority)
    → tools/call or DENY
```

The model’s proposal is **data**. It does not grant the tool.

---

## What the first MCP server is (and is not)

**Is:** A lab process with a tiny registry (`lookup_policy` allowed for a named agent; `execute_shell_command` registered as **unauthorized** or absent) and deterministic stubs.

**Is not:** A community MCP marketplace, a proxy that regex-scans prompts, an OS command runner, or a Cisco scanner.

If `execute_shell_command` is ever invoked in `vulnerable`, the handler MUST be a **stub** that records `executed=true` and returns a labeled lab string. It MUST NOT run a shell. That keeps the **authorization check** real and the **side effect** honest (LIVE lab stub, not RCE). Document `execution.mode=LIVE` as “lab tool stub ran,” not “host compromised.”

---

## Architecture security review

Challenges required by Phase 3A. Each is a **design constraint**, not a claim of implemented code.

### Unknown tool behavior

AgentWatch: `MCP-GW-PASS`. AgentSec: unknown tool → **ERROR** (not in registry) or **DENY** (in registry, not granted). Never ALLOW.

### Fail-open authorization

Missing allow-list, missing agent id, or control exception → **ERROR**, `executed=false`. Vulnerable profile may ALLOW only with an explicit labeled reason. Splunk absence is not a deny.

### Authority inherited from caller

HTTP caller is untrusted. The Attack Service cannot pass `allowed_scope` or `security.profile` as extra JSON (existing schema-reject rule). Agent identity is coded. MCP-006 (confused deputy) is a **later** lab: agent A must not spend agent B’s grant because the user asked.

### Authority inferred from tool data

Tool results, manifests, and descriptions are data (INV-002). A description that says “also run shell” does not add `execute_shell_command`. MCP-005 is the teaching lab; first lab only states the rule.

### Parameter validation

First lab: type/presence check; invalid → ERROR before execute. MCP-004: allowed tool, hostile args (path, account id). Authorization of the **tool name** is not authorization of **every argument**.

### Tool result trust

After ALLOW, the result is still untrusted data. Downstream hops must not treat it as policy. First lab should still emit a result payload (preview/hash) so hunts can ask “what came back?” without trusting it.

### Identity spoofing

If the request body contains `agent.id`, ignore it. Use the coded hop. Mismatch → ERROR. No DID theater.

### Missing attribution

Every MCP control and tool event: `run.id` = `incident.id`, `principal.*`, `gen_ai.agent.id`, `control.reason`. After hop 0, `delegator.agent.id` when the MCP call sits in the four-agent pipeline. First lab may be a **single agent** tool path; then delegator is omitted (same hop-0 rule as schema 1.0.0).

### Control after tool execution

Illegal as prevention. If the stub ran, `executed=true`. Post-exec inspection may SANITIZE/OBSERVE later; it MUST NOT emit DENY with `outcome=prevented` for that invoke.

### Telemetry claiming a block after execution

Forbidden. `control.decision=DENY` and `mcp.started` / `executed=true` on the same invoke is a contract violation (analogous to Q-LLM-AFTER-DENY). Hunt id: `Q-MCP-AFTER-DENY`.

### Client-only enforcement

A malicious or buggy MCP client could skip the control. The **server** must fail closed. First lab should implement server-side check even if the client also checks (defense in depth, still lab-minimal).

---

## Implementation freeze (Phase 3A)

- No MCP client/server code.
- No schema 1.1.0.
- No SPL.
- No Dashboard Studio.

Next phase implements **one** lab: MCP-002 with MCP-001 as BASELINE (see `MCP_LAB_PLAN.md`).

---

## Phase 3B resolution (do not erase 3A)

Implemented 2026-09-11: in-process JSON-RPC `tools/call`, dedicated agent `acme-agent-mcp-001`, schema **1.1.0**, CTRL-MCP-001 before handler. See `MCP_RUNTIME_CONTRACT.md` and `PHASE3B_MCP_RUNTIME_VALIDATION.md`. Splunk SPL still frozen.
