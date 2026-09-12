# MCP Predecessor Analysis (AgentWatch Range)

**Status:** Phase 3A planning. **No AgentSec MCP runtime.**  
**Predecessor:** `/Users/mahamudc/Documents/workspace/AgentwatchRange` (READ-ONLY).  
**Evidence class:** OBSERVED from source (this analysis). Not a live AgentWatch experiment. Not MEASURED AgentSec MCP behavior.  
**Related:** `docs/MIGRATION_INVENTORY.md` (Phase 0 already classified the gateway as REDESIGN). This file is the MCP-domain deep dive.

Do not copy AgentWatch MCP code into AgentSec. Do not present regex, substring matching, or SIMULATED OTel as tool-scope enforcement.

---

## What AgentWatch MCP actually is

AgentWatch has **no MCP client, no MCP server, and no JSON-RPC `tools/call`**. There is no tool executor that runs `validate_document_format` or `execute_shell_command`.

What exists:

1. A Python module named `mcp_gateway.py` that **regex-scans the user prompt string**.
2. A static JSON catalog `data/mcp/acme_banking_mcp.json` used by an optional Cisco MCP Scanner overlay.
3. Workflow-guard placement **before Ollama** that can stop the LLM if those regexes fire.
4. SIMULATED / HYBRID technique emissions that **write MCP-shaped fields** without a tool call.
5. Splunk saved searches that hunt those fields and claim “MCP tool scope escape.”

The teaching story (“agents must not invoke unapproved tools”) is useful. The implementation does not enforce that property on a tool.

---

## Code-path trace (OBSERVED)

```text
Attack Panel Scenario 6 payload (string containing execute_shell_command(...))
    → banking HTTP / LLM hop
    → llm_client.generate()
        → run_workflow_guards(user_message)
            → inspect_tool_invocation(user_message)     # regex on prompt
            → if mcp.scope_violation: blocked=True
        → if workflow.blocked: emit WORKFLOW_GUARD_BLOCK, return (no Ollama)
        → else: Ollama generate
```

Parallel paths that **do not** invoke tools:

| Path | What it does |
|------|----------------|
| `technique_executor` SIMULATED / HYBRID | Emits OTel with MCP-shaped fields (`tool_manifest_tampered`, `scope_violation`) |
| `chain_engine` AML.T0050 stage | Synthetic fields (`tool_requested=initiate_wire_transfer`) |
| `cisco_integration.run_mcp_scan` | Static name scan of JSON; optional `mcp-scanner` CLI; **does not block** the loan path unless Cisco enforce mode |
| `agent_registry` | Copies the global `APPROVED_TOOLS` set onto every agent as `mcp_scope` |

---

## What is real vs theater

| Kind | What AgentWatch does |
|------|----------------------|
| **Real operation** | Blocking **Ollama** when the prompt matches shell/invoke regexes. That is a real pre-LLM gate. It is **not** a tool invocation gate. |
| **Regex / substring** | `TOOL_INVOKE_PATTERNS` (`execute_shell_command(`, `os.system(`, `subprocess.*`, `__import__(`, `mcp.tool.invoke(`). Approved-tool **name substring** in the prompt → `MCP-GW-ALLOW`. Manifest scan is regex on fixture descriptions. Cisco local scan is substring on tool **names** (`shell`, `exec`, `system`, `eval`). |
| **Simulated** | AML.T0070 execution mode `SIMULATED`. `enrich_simulated_emission` writes `mcp.gateway.action=BLOCK` without a gateway call. Chain-engine AML.T0050 “privilege escalation to payment tool.” |
| **Metadata only** | `acme_banking_mcp.json` `approved: true/false`. Gateway **does not load this file** for allow/deny. `agent_registry.mcp_scope` is inventory JSON, not an enforcement table. |
| **Can actually block** | Prompt-regex match → skip Ollama. Cisco scan can theoretically block only if `cisco_enabled()` **and** `lab_mode()=="enforce"` **and** scanner `FAIL` — default Docker does not use this as the loan control. |
| **Validation vs dangerous action** | Check runs **before LLM**. There is **no** dangerous tool action. Claims that a “tool was blocked” are stronger than the code. |
| **Unknown tools** | **Fail open.** No approved-tool substring and no shell regex → `MCP-GW-PASS`, `blocked=False`, empty `tool_name`. |
| **Caller identity** | `agent_id` / `session_id` passed into the LLM client. **Not** bound to a tool allow-list. Registry assigns the **same** `mcp_scope` to every running agent. |
| **Requested authority** | Inferred from prompt text (tool-name-shaped substrings). No structured `{tool, action, scope, params}`. |
| **Parameter validation** | None. Regex does not parse JSON arguments. |
| **Telemetry** | `gen_ai.tool.name` (or `"none"`), `tool.scope_violation`, hardcoded `mcp.server.id=acme-mcp-gateway-001`, `mcp.gateway.rule_id`, `session.id`, optional `mcp.gateway.action=BLOCK`. SIMULATED paths add `workflow.blocked`. |
| **Over-claims** | Docstring: “scope enforcement for agent tool invocations.” Scenario 6: “MCP gateway blocks execute_shell_command.” Technique AML.T0050: “unauthorised execution of privileged operations.” Splunk: “MCP tool invoked outside approved scope.” Registry: “real lab agents + MCP scope.” None of these are true of a tool runtime. |

---

## Classification table

| Component | Current behavior | Security property claimed | Actual enforcement point | Failure behavior | Telemetry | Weakness | Classification | AgentSec direction |
|-----------|------------------|---------------------------|--------------------------|------------------|-----------|----------|----------------|--------------------|
| `mcp_gateway.inspect_tool_invocation` | Regex/substring on **user prompt** | Unapproved tools cannot run | Before **LLM**, not before a tool | Unknown → `MCP-GW-PASS` (fail open) | `mcp.gateway.*`, `tool.scope_violation`, fake `gen_ai.tool.name` | Not MCP; not a tool call; fail-open | **DROP** as control | Teach “allow-list before invoke” with a real (lab-minimal) client→server→tool path |
| `APPROVED_TOOLS` frozenset | Four banking-shaped names | Per-agent tool grant | Used only as substring allow in the prompt | Names in prompt → ALLOW even if no call | `gen_ai.tool.name` set to that name | Not per-agent; not a registry lookup | **REUSE** (shape only) | Per-agent allow-list of tool **ids**, consulted on structured requests |
| `inspect_tool_manifest` | Regex on fixture descriptions when prompt contains `MCP_MANIFEST_REGISTER` | Poisoned manifests rejected at registration | Never inspects a live register; loads `POISONED_MCP_MANIFEST` | No marker → skip | `tool_manifest_tampered` | Marker + regex theater | **DROP** now; **REDESIGN** later (MCP-005) | Treat tool **descriptions** as untrusted data (INV-002), not as this regex |
| `data/mcp/acme_banking_mcp.json` | Static catalog; `execute_shell_command` `approved: false` | Scanner-visible allow/deny list | Not loaded by the gateway | Unused by runtime | Cisco `mcp.config_path` | Metadata theater | **REFACTOR** | Become the **lab tool registry** the server actually consults |
| `workflow_guard` MCP branch | Calls `inspect_tool_invocation` on every hop | Tool surface gated | Before LLM | Fail-open if regex misses | `workflow.block_reason=MCP_TOOL_SCOPE_VIOLATION` | Wrong dangerous op | **REDESIGN** | Keep “control before dangerous op.” Move the gate to **tool invoke**, not prompt-as-MCP |
| `llm_client` pre-LLM return | Skips Ollama on workflow block | Prevention | Real skip of LLM | N/A for tools | `WORKFLOW_GUARD_BLOCK` | Honest for LLM; dishonest if labeled MCP tool block | **REUSE** placement idea | LLM control stays CTRL-INPUT-001. MCP control is a **separate** evaluation |
| Scenario 6 / `attack_payloads` W6 | Prompt containing `execute_shell_command({...})` | Live tool-escape attack | String only | LLM may still run if regex missed | Campaign week 6 fields | No tool, no params parsed | **REFACTOR** | Workshop **attacker input** for MCP-002; structured request, not “looks like a call” |
| `emerging_threats` AML.T0070 | `SIMULATED`; poisoned fixture + enrichment `BLOCK` | Manifest poisoning blocked | Telemetry writer | Always “blocked” in sim emit | `mcp.manifest.scan_rule_id` | SIMULATED presented as gateway | **DROP** as proof | Later MCP-005; label SIMULATED if used as a hunt fixture |
| `technique_executor` | LIVE posts to bank; SIMULATED emits fields | Technique coverage | Dual path | SIMULATED success without tool | Mixed LIVE/SIMULATED | Coverage gaming | **DROP** for MCP proof | AgentSec: LIVE stub tool + honest `execution.mode`; no fake BLOCK |
| `chain_engine` AML.T0050 stage | Synthetic `tool_requested` / `scope_violation` | Kill-chain privilege escalation | None | N/A | Custom chain fields | Fabricated tool request | **DROP** | No attack chains in first MCP labs |
| `control_validator` + `control_matrix.yaml` | String match on already-emitted OTel | NIST control PASS/FAIL | After telemetry exists | NOT_APPLICABLE / miss | Control summary fields | Does not prevent anything | **DROP** for MCP enforcement | Evidence is runtime decision + `operation.*`, not a post-hoc YAML matcher |
| `agent_registry` `mcp_scope` | All agents get the same joined `APPROVED_TOOLS` | Inventory of MCP grants | None | Shadow agent `unscoped` is a story | Registry JSON | Same scope for everyone; INV-001 not represented | **REDESIGN** | Per-agent `allowed_tools` / `allowed_scope` as the **policy object** the control reads |
| Cisco `run_mcp_scan` | JSON name heuristics; optional CLI | Supply-chain scan of MCP surface | Overlay; default non-blocking | Local `WARN` on “shell” in name | `cisco.mcp.*` | Scanner ≠ runtime allow-list | **DROP** from first labs | Optional later overlay, labeled; never a substitute for invoke-time DENY |
| Splunk “MCP Tool Scope Escape” / “Manifest Poisoning” | Hunt `scope_violation` / `tool_manifest_tampered` + `HARD_DENY` | Detection of tool abuse | Index only | False confidence from SIMULATED fields | AgentWatch field names | Questions are good; SPL assumes theater fields | **REUSE** questions; **DROP** SPL | New Q-MCP-\* ids; no SPL in 3A; do not copy `session.id` or `mcp.gateway.action` |
| Attack Panel W6 UI | Story + payload button | Learner can fire MCP week | Client of banking API | Same as payload | Campaign metadata | UX is fine; claims are not | **REFACTOR** later | Attack Service workshop button for LAB-MCP-001; no Cisco/MCP chrome |
| Hardcoded `mcp.server.id` | Always `acme-mcp-gateway-001` | Identifies an MCP server | Constant | N/A | `mcp.server.id` | Implies a server that does not exist | **DROP** | Real `service.name` of the lab MCP server process; do not fake server id |
| `session.id` on MCP fields | Correlation for AgentWatch hunts | Session-scoped tool use | N/A | Split from incident id | `session.id` | AgentSec forbids this as hunt key | **DROP** | `agentsec.run.id` = `incident.id` |

---

## Claims stronger than the code (do not inherit)

1. “MCP gateway blocks `execute_shell_command`.” — It blocks **prompts that look like** that string from reaching Ollama.
2. “Tool scope enforcement in the code path.” — There is no tool scope object and no invoke.
3. `gen_ai.tool.name=execute_shell_command` — No tool of that name ran.
4. `mcp.gateway.action=BLOCK` on SIMULATED AML.T0070 — Written by `enrich_simulated_emission`.
5. Registry `mcp_scope` as evidence of least privilege — Every agent gets every approved name.
6. Cisco scan PASS/WARN as runtime authorization.

---

## What to take (ideas only)

| Keep as a **lesson** | Do not keep as **code** |
|----------------------|-------------------------|
| Allow-list before a privileged action | Regex on the prompt labeled as MCP |
| Unknown capability must not fail open | `MCP-GW-PASS` |
| Tool catalog as an inspectable object | JSON unused by the gateway |
| Splunk asks “which tool, which scope, after DENY?” | AgentWatch SPL and field names |
| Control **before** the dangerous operation | Treating LLM skip as tool prevention |

---

## AgentSec migration rule (locked for Phase 3A)

AgentSec MCP labs MUST have a **structured tool request** and a **control decision before tool execution**. A stub tool body is allowed if labeled LIVE (deterministic lab tool) rather than OS RCE. Regex-on-prompt is not an MCP control.

Schema 1.0.0 is unchanged. No runtime in this phase.
