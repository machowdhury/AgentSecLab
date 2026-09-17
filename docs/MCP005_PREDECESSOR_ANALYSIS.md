# MCP-005 predecessor analysis (AgentWatch Range)

**Status:** Phase 6A **DESIGN**. No AgentSec MCP-005 runtime.  
**Predecessor:** `/Users/mahamudc/Documents/workspace/AgentwatchRange` (READ-ONLY).  
**Evidence class:** **OBSERVED** from source. Not a live AgentWatch experiment. Not MEASURED AgentSec MCP-005 behavior.  
**Related:** `docs/MCP_PREDECESSOR_ANALYSIS.md` (MCP-001/002), `docs/MCP003_PREDECESSOR_ANALYSIS.md` (scope), `docs/MCP004_PREDECESSOR_ANALYSIS.md` (resource). This file is the **tool-result / data-cannot-grant-authority** slice only.

Do not copy AgentWatch code. Do not treat prompt regex, poisoned-manifest fixtures, or SIMULATED RAG injection as INV-002 enforcement.

---

## Question this document answers

Does AgentWatch evaluate **content returned by an authorized tool** and decide whether that content may change later authority?

**No.** AgentWatch has no MCP server, no handler, and no tool-result objects. Nothing in the predecessor inspects a live `tools/call` payload and then re-authorizes a follow-on tool.

The useful teaching story (“returned text must not become a grant”) is real. The implementation does not enforce that property on a result.

---

## Three problems AgentWatch mixes

Keep these separate. MCP-005 is only **A**.

| Problem | Meaning | AgentWatch analogue | AgentSec |
|---------|---------|---------------------|----------|
| **A** | Authorized tool returns malicious / instruction-like **data** | Absent as a result object. Closest theater is RAG/document injection (SIMULATED) and prompt strings that *look* like tool calls | **This lab** — fixture data after a real `lookup_policy` |
| **B** | Compromised tool **binary** / handler | No tool binary exists | **Do not depend on this** |
| **C** | Unauthorized tool call | Prompt regex for `execute_shell_command(` | Already LAB-MCP-001 / MCP-002 |

---

## Code-path traces (OBSERVED)

### mcp_gateway.py — regex on the user prompt, not a result

`inspect_tool_invocation(user_input: str)`:

1. If the prompt contains `MCP_MANIFEST_REGISTER` / `mcp_tool_manifest`, load the **static** `POISONED_MCP_MANIFEST` fixture and regex its **descriptions**.
2. Else shell/invoke regex on the **same user string** → fake tool `execute_shell_command`, `scope_violation=True`.
3. Else approved **tool name** substring in the prompt → `MCP-GW-ALLOW`.
4. Else `MCP-GW-PASS`.

There is no JSON result. There is no `summary` field. There is no post-handler gate. “Result trust” does not exist as a function.

**Classification:** **DROP** as a control for MCP-005.

### inspect_tool_manifest — fixture descriptions, never a live result

`inspect_tool_manifest` walks `manifest["tools"][*].description` with `MANIFEST_INJECTION_PATTERNS` (`[SYSTEM OVERRIDE`, `ignore prior constraints`, …). It runs only when the **user prompt** contains a register marker. It never sees a handler return value.

Phase 3A already marked this **DROP now / REDESIGN later**. MCP-005 is that later lesson, but **not** as “regex the catalog description at register time.” The redesign is: treat **returned content** as data (INV-002), after a real authorized call.

**Classification:** **DROP** as this lab’s control. The *idea* (“instruction-like text is not authority”) is **REUSE** as a teaching contrast only.

### workflow_guard.py — blocks the LLM, not a tool handler

`run_workflow_guards` calls the gateway on the **user message before Ollama**. A “scope violation” skips the model. There is no `mcp.completed`, no result object, no second authorize.

**Classification:** **REDESIGN** the placement idea only (“control before the dangerous operation”). Move the gate to **after the result, before any authority mutation or follow-on invoke**. Do not keep prompt-as-MCP.

### attack_payloads.py Workshop 6

Scenario 6 is a **user prompt** containing `execute_shell_command(...)`. That is attacker **input**, not a tool **output**.

**Classification:** **REFACTOR** as an attacker-input story only. Do not use it as the MCP-005 result fixture. AgentSec follow-on remains the already-registered, ungranted `lookup_customer_tier` — not a shell.

### chain_engine.py KC-C (document → RAG → privilege theater)

`KC-C001` description (OBSERVED): adversary embeds injection in a loan document; RAG retrieval “causes the credit agent to process the injection, escalating privileges to the payment tool.” Stages emit SIMULATED fields (`injection_vector`, `payload`, later privilege-escalation technique ids). No MCP `tools/call`. No handler. No grant object.

**Classification:** **DROP**. Chains are out of scope. SIMULATED theater is not MCP-005 proof.

### technique_executor.py

LIVE posts to the bank HTTP path. SIMULATED writes MCP-shaped fields without a tool call.

**Classification:** **DROP** for MCP-005 proof.

### control_validator.py

Post-hoc YAML `pass_signal` / `fail_signal` against an OTel field bag. Does not decide whether a result may mutate policy. Does not sit before a dangerous operation.

**Classification:** **DROP** as enforcement.

### Four-agent LLM path

Feeds **user / RAG-shaped** text to Ollama. Does not feed MCP tool-result objects into a follow-on authorize.

**Classification:** **REUSE** idea only: an LLM may later *read* results. Security correctness must **not** depend on the model obeying or resisting the string.

### Splunk (AgentWatch app)

Hunts `scope_violation`, `mcp.gateway.action=BLOCK`, `tool_manifest_tampered`, technique ids. No saved search reconstructs “this completed result widened `allowed_tools`.” **PLAUSIBLE BUT UNVALIDATED** as AgentWatch SPL. Not an INV-002 hunt.

---

## What AgentWatch does not have (OBSERVED)

| Property | Present? |
|----------|----------|
| MCP client / server / JSON-RPC `tools/call` | No |
| Tool handler return objects | No |
| Result labeled as data vs authority | No |
| Server-owned grant that a result cannot widen | No (no grant object) |
| Follow-on authorize after a result | No |
| LLM consuming MCP results | No |

AgentWatch **simulates** tool-escape and injection. It does not execute tools and then refuse to treat their output as policy.

---

## AgentSec today (context — OBSERVED, not this phase’s work)

`POST /mcp/invoke` already:

1. Authorizes **one** `tools/call` per HTTP request (tool, then scope, then resource).
2. On ALLOW, runs the handler.
3. Emits `mcp.completed` with `agentsec.mcp.result.trust=untrusted_data` and `agentsec.mcp.result.provenance=mcp.tool.handler`.
4. Exposes `policy_unchanged_by_result()` which **discards** the result and returns the same `McpPolicy`.

What it does **not** do:

- Interpret result text as a follow-on tool request.
- Apply a per-run grant overlay.
- Re-enter CTRL-MCP-001 for a second tool in the same run.
- Prove INV-002 as a lab with a malicious **data** fixture (the stub exists; the attack path does not).

That gap is MCP-005. It is not an AgentWatch port.

---

## Classification table

| Asset | Claimed property | Actual behavior | Classification | AgentSec MCP-005 |
|-------|------------------|-----------------|----------------|------------------|
| `inspect_tool_invocation` | Tool-scope enforcement | Regex on **user prompt** | **DROP** | Structured first call already authorized; result is a later question |
| `inspect_tool_manifest` | Poisoned descriptions rejected | Regex on **fixture** descriptions if prompt has a marker | **DROP** | Instruction-like text lives in `lookup_policy.summary`, not a register protocol |
| `workflow_guard` MCP branch | Tool surface gated | Before **LLM**, not after a result | **REDESIGN** idea | Control **before merge / follow-on**, after `mcp.completed` |
| W6 `execute_shell_command(` payload | Gateway blocks shell | Prompt string, no handler | **REFACTOR** | Attacker-input story only; follow-on is `lookup_customer_tier` |
| KC-C RAG → privilege | Injection becomes payment authority | SIMULATED chain fields | **DROP** | No chains; no payment tool |
| `technique_executor` SIMULATED MCP | Tool invoked outside scope | Field emission without `tools/call` | **DROP** | LIVE first call + deterministic interpreter |
| `control_validator` | Control passed | YAML vs OTel after the fact | **DROP** | Runtime decision before mutation |
| Four-agent Ollama path | Model follows / resists injection | User/RAG text, not MCP results | **REUSE** idea | Optional later education; not the proof |
| Result provenance / data≠authority | — | **Absent** | **REDESIGN** | Already started: `untrusted_data` + `policy_unchanged_by_result`; this lab makes the failure visible |

---

## What to take / what to leave

**Take (ideas only):**

- Instruction-like text is not a grant.
- Control must run before the dangerous operation (here: **policy mutation**, then **follow-on execute**).
- “Came from an approved-looking source” is not the same as “is authoritative.”

**Leave:**

- Prompt regex as MCP.
- Manifest-register marker protocol.
- Shell as the follow-on tool.
- SIMULATED chains as proof.
- Model-resistance as the security property.

---

## Evidence class reminder

Everything above about AgentWatch is **OBSERVED** from source. AgentSec MCP-005 behavior in later phases must be MEASURED. Do not represent this file as a live experiment.
