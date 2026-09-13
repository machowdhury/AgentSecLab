# MCP-003 predecessor analysis (AgentWatch Range)

**Status:** Phase 4A **DESIGN**. No AgentSec MCP-003 runtime.  
**Predecessor:** `/Users/mahamudc/Documents/workspace/AgentwatchRange` (READ-ONLY).  
**Evidence class:** **OBSERVED** from source. Not a live AgentWatch experiment. Not MEASURED AgentSec MCP-003 behavior.  
**Related:** `docs/MCP_PREDECESSOR_ANALYSIS.md` (Phase 3A MCP-001/002). This file is the **scope** slice only.

Do not copy AgentWatch code. Do not treat `tool.scope_violation` as structured scope authorization.

---

## Question this document answers

Does AgentWatch assign broad or equal MCP scope to agents, and does it perform structured scope authorization?

**Yes, from source:** every running lab agent receives the **same** `mcp_scope` string (the full `APPROVED_TOOLS` name list). There is **no** structured `{tool, requested_scope}` check against a per-agent grant. “Scope violation” is a regex/substring flag on the **prompt**, or a SIMULATED A2A privilege-creep marker.

---

## Code-path traces (OBSERVED)

### Registry — equal MCP scope

`apps/framework/agent_registry.py` `build_registry_snapshot`:

```text
mcp_scope = ",".join(sorted(APPROVED_TOOLS))
for every running agent in AGENTS:
    row["mcp_scope"] = mcp_scope
```

`APPROVED_TOOLS` is four names: `validate_document_format`, `extract_financial_fields`, `lookup_policy`, `score_credit_risk`.

The shadow agent is `"unscoped"`. Running agents are **not** differentiated. The snapshot docstring claims “real lab agents + MCP scope.” The field is inventory JSON, not an enforcement table.

### Gateway — prompt regex, not scope tokens

`apps/framework/mcp_gateway.py` `inspect_tool_invocation(user_input: str)`:

1. Manifest-injection regex if the prompt contains a register marker.
2. Shell/invoke **regex** (`execute_shell_command(`, `os.system(`, …) → `scope_violation=True`, `tool_name=execute_shell_command`.
3. Else if an approved **tool name substring** appears in the prompt → `MCP-GW-ALLOW`, `scope_violation=False`.
4. Else `MCP-GW-PASS`, `blocked=False`, empty tool name.

There is no `requested_scope` argument. There is no comparison to `allowed_scope`. `scope_violation` means “prompt looked like a forbidden invoke,” not “scope token exceeded grant.”

### Workflow guard — blocks LLM, not a tool handler

`workflow_guard.run_workflow_guards` calls `inspect_tool_invocation` on the user message. If `mcp.scope_violation`, it returns `block_reason=MCP_TOOL_SCOPE_VIOLATION` and the LLM hop is skipped. That is a real pre-LLM gate. It is **not** a tool-invoke gate. There is no MCP server.

### A2A “privilege creep” — different property

`a2a_verifier.track_agent_scope` compares in-memory `granted` vs accumulated `used` **A2A** tokens (`read:intake`, `write:approve`, …). It runs when the prompt contains `PRIVILEGE_CREEP_SIM` or technique AML.T0073. It does not authorize `POST /mcp/invoke`. Do not reuse as MCP-003.

### control_validator.py

Evaluates YAML `pass_signal` / `fail_signal` against an OTel field bag (including `tool.scope_violation=true`). It does not authorize tools.

### technique_executor / chain_engine

SIMULATED / HYBRID emissions write MCP-shaped fields (`scope_violation=true`, privileged tool names) without a tool call. Telemetry theater.

### Splunk

Saved search copy: “MCP tool invoked outside approved scope — potential privilege escalation.” Hunt fields: `framework.technique_id=AML.T0050`, `scope_violation=true`, `mcp.gateway.action=BLOCK`. Privilege-creep search uses `granted_scope` / `used_scope` from A2A SIMULATED fields. **PLAUSIBLE BUT UNVALIDATED** as AgentWatch SPL (Phase 0 inventory). Not a structured MCP-003 hunt.

### Cisco MCP Scanner

`cisco_integration.run_mcp_scan` optionally runs `mcp-scanner` on `data/mcp/acme_banking_mcp.json`, or substring-matches tool **names** for `shell`/`exec`/`system`/`eval`. Teach-mode telemetry. Does **not** compare requested vs allowed scope. Does not sit on AgentSec `/mcp/invoke`.

---

## Classification

| Asset | Claimed property | Actual behavior | Classification | AgentSec MCP-003 |
|-------|------------------|-----------------|----------------|------------------|
| `agent_registry.mcp_scope` | Per-agent MCP scope | Same `APPROVED_TOOLS` CSV on every running agent | **DROP** as enforcement. **REUSE** the teaching idea “scope is per agent” | Coded `allowed_scopes` on `acme-agent-mcp-001` only |
| `APPROVED_TOOLS` | Approved tool set | Prompt substring allow | **REUSE** shape (tool ids). **REDESIGN** as registry + grant | Already done in LAB-MCP-001 |
| `inspect_tool_invocation` | Tool scope enforcement | Regex on prompt | **DROP** | Structured `requested_scope` vs `allowed_scopes` |
| `tool.scope_violation` | Scope mismatch | Boolean on regex/SIMULATED | **DROP** field | Keep `requested_scope` / `allowed_scope` / `decision` / `reason` |
| `workflow_guard` MCP branch | Block tool abuse | Blocks **Ollama** | **REDESIGN** placement | Control remains **before handler**, already CTRL-MCP-001 |
| `track_agent_scope` / AML.T0073 | Privilege creep | A2A token accumulation, marker-driven | **DROP** for MCP-003 | Out of scope (A2A later) |
| `control_validator` | NIST pass/fail | Telemetry bag match | **DROP** | AgentSec tests + Splunk hunts |
| `technique_executor` MCP fields | Privileged tool escape | SIMULATED OTel | **DROP** | LIVE `/mcp/invoke` specimens |
| Splunk “outside approved scope” | Detection of MCP scope escape | Hunts regex/SIMULATED flags | **DROP** SPL | Reuse AgentSec Q-MCP-SCOPE + DET-MCP-001 |
| Cisco `mcp-scanner` | Scanner of MCP config | Name/static JSON; optional CLI | **DROP** for this lab | No Cisco in MCP-003 |
| `acme_banking_mcp.json` | Catalog of approved tools | Not loaded by gateway | **REFACTOR** later as registry metadata | Not required for MCP-003 if `ToolSpec` already lists valid scopes |

---

## Known weakness — verified

| Claim | Source | Verdict |
|-------|--------|---------|
| Agents get broad/equal MCP scope | `agent_registry.py` line assigning `mcp_scope = ",".join(sorted(APPROVED_TOOLS))` inside the loop over `AGENTS` | **OBSERVED true** for all `agent_status=running` rows |
| No structured scope authorization | `inspect_tool_invocation` takes a string; no scope token; no grant set comparison | **OBSERVED true** |
| `scope_violation` means requested > allowed | Set true on shell regex or poisoned-manifest regex | **OBSERVED false** relative to MCP-003’s meaning |

---

## What AgentSec already has (context, not this phase’s implementation)

LAB-MCP-001 `authorize_tool` uses **exact set membership** `requested_scope in policy.allowed_scopes`. Defended already returns `DENY` `scope_not_granted` when the tool is granted and the scope is not. The **vulnerable** profile fail-opens only for **ungranted tools** (MCP-002), not for excessive scope on a granted tool.

MCP-003 is therefore a **new lab property** on the existing path, not a port of AgentWatch.

---

## Do not copy

- Regex or substring as scope authorization
- Equal `mcp_scope` on every agent
- `tool.scope_violation` as the hunt key
- Cisco scanner as the control
- A2A privilege-creep tokens as MCP scopes
- Shell/`execute_shell_command` as the MCP-003 tool
