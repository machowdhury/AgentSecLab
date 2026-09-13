# MCP-004 predecessor analysis (AgentWatch Range)

**Status:** Phase 5A **DESIGN**. No AgentSec MCP-004 runtime.  
**Predecessor:** `/Users/mahamudc/Documents/workspace/AgentwatchRange` (READ-ONLY).  
**Evidence class:** **OBSERVED** from source. Not a live AgentWatch experiment. Not MEASURED AgentSec MCP-004 behavior.  
**Related:** `docs/MCP_PREDECESSOR_ANALYSIS.md` (MCP-001/002), `docs/MCP003_PREDECESSOR_ANALYSIS.md` (scope). This file is the **parameter / resource** slice only.

Do not copy AgentWatch code. Do not treat prompt regex or `found:false` handler returns as resource authorization.

---

## Question this document answers

Does AgentWatch distinguish **argument schema validity** from **authorization to access the resource named by the argument**?

**No.** AgentWatch never parses tool arguments. It never compares a resource identifier to a per-agent grant. `lookup_policy` is a **name substring in the user prompt**. The optional `acme_banking_mcp.json` catalog has tool **names** only — no parameter schema, no `policy_id`, no object ACL.

---

## Code-path traces (OBSERVED)

### mcp_gateway.py — prompt regex, not arguments

`inspect_tool_invocation(user_input: str)`:

1. Manifest-injection regex if the prompt contains a register marker.
2. Shell/invoke regex → `scope_violation=True`, fake tool `execute_shell_command`.
3. Else if an approved **tool name** substring appears in the prompt → `MCP-GW-ALLOW`.
4. Else `MCP-GW-PASS`.

There is no JSON `arguments` object. There is no `policy_id`. There is no schema check and no resource grant check. “Parameter authorization” does not exist as a function.

### acme_banking_mcp.json — names only

`lookup_policy` is listed as “Read internal lending policy snippets” with `approved: true`. No `inputSchema`, no required keys, no resource catalog. Cisco `mcp-scanner` (optional) substring-matches tool **names** for `shell`/`exec`. It does not authorize objects.

### workflow_guard — blocks LLM, not a tool handler

`run_workflow_guards` calls `inspect_tool_invocation` on the **user message**. A “scope violation” skips Ollama. There is no MCP server, no `tools/call`, no handler, no argument dict.

### control_validator.py

YAML `pass_signal` / `fail_signal` against an OTel field bag. Does not parse arguments. Does not authorize resources.

### technique_executor / chain_engine

SIMULATED / HYBRID MCP-shaped fields without a tool call. Telemetry theater. Not an IDOR test.

### a2a_verifier privilege creep

Compares in-memory A2A tokens (`read:intake`, …). Not MCP arguments. **DROP** for MCP-004.

### Splunk

No saved search in the AgentWatch app matches `policy_id`, `customer_id`, `account_id`, or tool-call arguments as structured fields (**OBSERVED** grep of `splunk_app/`). MCP hunts use `scope_violation` / `mcp.gateway.action=BLOCK` / technique ids. **PLAUSIBLE BUT UNVALIDATED** as AgentWatch SPL. Not a resource-authorization hunt.

### AgentSec today (context — OBSERVED, not this phase’s work)

`McpServer.authorize` already:

1. Runs CTRL-MCP-001 for **tool** and **scope**.
2. Then `_argument_error`: required keys present, values are non-empty strings, no extra keys → else ERROR `malformed_arguments`.
3. Mints `AllowTicket` containing the argument dict.
4. Handler `lookup_policy` does `POLICY_FIXTURES.get(policy_id)` and returns `{found: False}` if missing.

So AgentSec **does** distinguish malformed JSON keys/types from “a string policy_id was supplied.” It does **not** yet distinguish:

- known granted resource
- known ungranted resource
- unknown resource

Any well-typed `policy_id` that survives schema check is **ALLOW** (when tool and scope already passed) and the **handler runs**. That is the MCP-004 gap. It is not an AgentWatch port.

---

## Classification

| Asset | Claimed property | Actual behavior | Classification | AgentSec MCP-004 |
|-------|------------------|-----------------|----------------|------------------|
| `inspect_tool_invocation` | Tool/parameter enforcement | Regex on prompt | **DROP** | Structured `policy_id` vs server catalog + grant |
| `APPROVED_TOOLS` / JSON catalog | Approved tools | Name list; no params | **REUSE** shape (`lookup_policy` id). **REDESIGN** as resource catalog + grant | `POLICY_RESOURCE_CATALOG` vs `allowed_policy_ids` |
| `acme_banking_mcp.json` | MCP tool schema | Names/descriptions only | **DROP** as ACL. **REFACTOR** later only as registry metadata | Not the grant |
| `workflow_guard` MCP branch | Block tool abuse | Blocks **Ollama** | **REDESIGN** placement | Control remains **before handler** (already CTRL-MCP-001) |
| `control_validator` | NIST pass/fail | Telemetry bag match | **DROP** | Tests + Splunk hunts |
| `technique_executor` MCP fields | Privileged tool escape | SIMULATED OTel | **DROP** | LIVE `/mcp/invoke` specimens |
| A2A `track_agent_scope` | Privilege creep | A2A tokens | **DROP** | Out of scope |
| Splunk argument/resource hunts | Object authorization | **Absent** | **DROP** SPL | Reuse Q-MCP-* ; propose hunt question for resource vs grant |
| AgentSec `_argument_error` | Argument schema | Keys/types/emptiness | **REUSE** as step 5 (schema). **Do not** treat as resource auth | Keep ERROR `malformed_arguments` |
| AgentSec `POLICY_FIXTURES.get` + `found:false` | Resource lookup | Happens **in the handler after ALLOW** | **REDESIGN** | Catalog/grant **before** ticket; handler must not be the ACL |
| AgentSec `AllowTicket` | Capability after ALLOW | Holds argument dict | **REUSE** | Add ticket `resource_id` = authorized exact identifier (no crypto) |

---

## Known weakness — verified

| Claim | Source | Verdict |
|-------|--------|---------|
| AgentWatch authorizes `policy_id` / customer / account objects | `mcp_gateway.py` takes a string; JSON catalog has no params | **OBSERVED false** |
| AgentWatch separates schema validity from object authorization | No argument parser exists | **OBSERVED false** — neither check exists |
| AgentSec schema check is resource authorization | `_argument_error` then handler `get()` | **OBSERVED false** — schema is not the grant |

---

## What not to copy

- Prompt regex as parameter authorization
- Shell / `execute_shell_command` as the MCP-004 tool
- Cisco scanner as the control
- Handler `found: false` as DENY
- A2A privilege-creep tokens as resource ids
- Unbounded `parameter.*` or full `gen_ai.tool.call.arguments` in Splunk
