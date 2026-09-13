# MCP Security 101

**Status:** Phase 3A planning. There is **no** AgentSec MCP runtime yet. This note teaches the **design** and the **predecessor mistake**, not a live tool gateway.  
**Parents:** `docs/MCP_ARCHITECTURE.md`, `docs/MCP_PREDECESSOR_ANALYSIS.md`, `docs/MCP_LAB_PLAN.md`.  
**Evidence:** AgentWatch behavior is OBSERVED from source. AgentSec MCP behavior is DOCUMENTED only.

---

## WHAT IS IT?

**MCP (Model Context Protocol)** is a way for an agent to call **tools** on an **MCP server** using JSON-RPC (for example `tools/call` with a tool name and arguments).

A **tool** is a privileged action: look up a policy, score risk, or (in a bad design) run a shell. The security problem is not “the model said something.” It is “did this **agent** have the **right** to run **this tool** with **these arguments**?”

## WHY DOES IT EXIST?

LAB-PI-001 taught: untrusted text must not reach the **LLM** without a control decision.

MCP labs teach the next surface: untrusted requests must not reach a **tool** without a control decision — and whatever the tool **returns** is still data. It cannot mint new rights.

AgentWatch Range had a module named `mcp_gateway` that **did not speak MCP**. It regex-scanned the prompt. AgentSec exists so that lesson is not repeated as if it were enforcement.

## HOW DOES IT WORK?

Planned lab path (not implemented):

1. You (principal) start a run.
2. An **agent** with a **coded** identity requests a tool.
3. A **reference control** compares requested tool + scope to that agent’s **allow-list**.
4. **ALLOW** → MCP client → MCP server → tool stub **begins**.
5. **DENY** or **ERROR** → the stub **does not run**.
6. The stub’s return value is **data**. It does not add tools.

First workshop (planned `LAB-MCP-001`):

- **BASELINE (MCP-001):** allowed tool `lookup_policy` actually runs (deterministic stub).
- **ATTACK (MCP-002):** `execute_shell_command` (or any unggranted name) is **denied** in `defended`, and only runs a **labeled stub** in `vulnerable` — never a real shell.

The LLM does **not** choose the tool in the first lab. That keeps the result testable.

## WHERE DOES IT SIT IN AGENTSEC?

```text
LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE
```

Same lifecycle as prompt injection. Different **dangerous operation**: tool execution, not Ollama.

Splunk is still observe-only. Schema 1.0.0 stays frozen until a 1.1.0 MCP event proposal is accepted.

## WHAT IS THE TRUST BOUNDARY?

Named boundaries (see `MCP_ARCHITECTURE.md`):

- HTTP API (Attack Service is untrusted)
- MCP authorize (control)
- MCP server invoke (must fail closed even if the client is wrong)
- Tool execute (**dangerous op starts here**)
- Tool result (**data in**)
- Telemetry / Splunk (**cannot ALLOW**)

**Authority in:** coded agent identity + allow-list + security profile.  
**Data in:** user request, tool arguments, tool results, later model text.

## WHAT COULD AN ATTACKER CONTROL?

The structured tool **name**, **arguments**, and any **claimed** identity/scope in the JSON.

They must **not** control (`defended`): `run.id`, profile, allow-list, control decision, operation flags.

## WHAT CAN GO WRONG?

1. **Fail open** on unknown tools (AgentWatch `MCP-GW-PASS`).
2. Calling a **prompt regex** “MCP security.”
3. Emitting `BLOCK` / `DENY` **after** the tool already ran.
4. Treating **SIMULATED** OTel as a blocked tool.
5. Letting a **tool result** expand the allow-list (INV-002).
6. Trusting `agent.id` inside the payload (INV-005).
7. Proving prevention with **Splunk silence** alone.
8. Calling a lab stub “we popped the host.”

## WHAT TELEMETRY SHOULD EXIST?

Enough to answer:

- Which agent requested which tool?
- What scope was requested vs allowed?
- What did the control decide, and why?
- Did the tool handler **begin**?
- If DENY, was there still an execute event? (contract violation)
- What came back (preview/hash), without treating it as policy?

Prefer OTel `gen_ai.tool.name` and `mcp.method.name`. Add AgentSec fields only for **requested/allowed scope**. Do not add a second name for the tool. Hunt with `run.id`, not `session.id`.

Details: `docs/MCP_EVENT_MODEL_PROPOSAL.md`.

## HOW WILL SPLUNK SHOW IT?

Later: same index `agentsec_telemetry`, questions `Q-MCP-*` (no SPL in Phase 3A).

Same honesty as `Q-LLM-AFTER-DENY`: zero execute-after-DENY rows on a **complete** copy is corroboration, not independent proof.

## WHAT CONTROL COULD CHANGE THE RESULT?

**CTRL-MCP-001** (planned): allow-list + unknown-tool ERROR, **before** dispatch.

- `defended`: unauthorized → DENY, no stub.
- `vulnerable`: labeled ALLOW, stub runs.

Not a control: Cisco MCP Scanner, Splunk notable, regex on `execute_shell_command(` in a prompt.

## WHAT TEST PROVES THE LOGIC?

When implemented: a spy on the tool handler.

- Authorized → called.
- Unauthorized defended → **not** called.
- Control ERROR (unknown tool) → **not** called.
- After ALLOW, stub throws → called, `outcome=error` (not DENY).

Do not use the LLM as the oracle.

---

## Predecessor in one paragraph

AgentWatch `inspect_tool_invocation(user_input)` scanned strings. Shell-shaped regex blocked **Ollama**. Approved tool **names** in the prompt were ALLOW. Anything else was `MCP-GW-PASS`. The file `acme_banking_mcp.json` was for an optional scanner, not the gateway. SIMULATED techniques wrote `mcp.gateway.action=BLOCK` without a tool. That is useful as a **negative** example. It is not something to port.

---

## First lab in one paragraph

Build the smallest real path: agent → client → server → `lookup_policy` stub, then the same path with an unauthorized name. Deterministic. Fail closed. Honest DENY. Stub, not RCE. Then stop. Scope, params, malicious results, and confused deputy wait.

---

## What I should now be able to explain

1. What MCP is (client, server, tool, `tools/call`) versus what AgentWatch’s “MCP gateway” actually did.
2. Why unknown tools must ERROR/DENY rather than pass.
3. Where authority enters versus where data enters; why a tool result cannot add tools.
4. Which invariants cover MCP (INV-001, 002, 004, 005, 007, 008) and why a new invariant is unnecessary.
5. Why the first lab is authorized-then-unauthorized, not a kill chain.
6. Why DENY must happen before the stub runs, and why stub failure is not prevention.
7. Which event fields should be OTel (`gen_ai.tool.name`, `mcp.method.name`) versus AgentSec (`requested_scope` / `allowed_scope`).
8. Why `session.id` and hardcoded `mcp.server.id` are the wrong hunt keys.
9. How Splunk questions (`Q-MCP-EXECUTED`, `Q-MCP-AFTER-DENY`) parallel the LLM lab without copying AgentWatch SPL.
10. What would count as proof that an unauthorized tool was prevented (runtime handler not called + complete local evidence), and what would not (empty Splunk, SIMULATED BLOCK, skipped LLM).
