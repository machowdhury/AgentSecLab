# MCP-004 runtime contract (LAB-MCP-004)

**Status:** Phase 5B **IMPLEMENTED + LOCALLY VALIDATED**. Not Splunk-validated. Not a workshop. Not a new detection.  
**Schema:** `agentsec.security_event` **1.2.0** (additive over 1.1.0).  
**Control:** CTRL-MCP-001 (extended). No CTRL-MCP-004.  
**Evidence class:** pytest and local bundles are **MEASURED** / **OBSERVED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/MCP004_LAB_SPECIFICATION.md`, `docs/MCP004_PARAMETER_MODEL.md`, `docs/SCHEMA_1_2_0.md`.

---

## WHAT IS IT?

A granted MCP tool (`lookup_policy`) at a granted scope (`policy:read`) is still unauthorized when `policy_id` names a **catalog-valid** resource the agent was never granted (`executive-restricted`).

- LAB-MCP-001 answers: may this agent call this **tool**?
- LAB-MCP-003 answers: may this agent call this tool **at this scope**?
- LAB-MCP-004 answers: may this agent perform that permitted operation **on this resource**?

## WHY DOES IT EXIST?

Tool and scope grants are easy to over-read as “the agent may call lookup_policy.” Resource identity is a third authorization question. The handler remains a harmless in-memory fixture. This is not RCE, not Cisco, and not a customer-data lab.

## HOW DOES IT WORK?

```text
POST /mcp/invoke  {tool, arguments, requested_scope, user_id?}
        │  extra JSON → ERROR unknown_fields (no handler)
        │  duplicate JSON keys → ERROR duplicate_json_keys (no authorize, no handler)
        ▼
1.  tool exists                         else ERROR unknown_tool
2.  tool granted                        else DENY tool_not_granted
                                        (vulnerable: MCP-002 fail-open)
3.  requested_scope present / acceptable else ERROR missing_requested_scope
4.  requested_scope known to tool       else ERROR unknown_scope
5.  requested_scope granted to agent    else DENY scope_not_granted
                                        (vulnerable: MCP-003 fail-open)
6.  arguments structurally valid        else ERROR malformed_arguments
7.  resource identifier extracted       (exact policy_id string; no strip)
8.  resource exists in server catalog   else ERROR unknown_resource
9.  resource granted to agent           else DENY resource_not_granted
                                        (vulnerable: MCP-004 fail-open)
10. ALLOW ticket created (resource_id bound)
11. handler begins (ticket only; uses ticket.resource_id)
```

Matching is **exact opaque identity**. No strip, lowercase, Unicode normalization, prefix, wildcard, regex, or substring matching.

`lookup_customer_tier` has **no** resource catalog. Steps 7–9 are skipped so LAB-MCP-001 / MCP-002 remain a tool-grant lesson.

## WHERE DOES IT SIT?

Same `POST /mcp/invoke` path as LAB-MCP-001 and LAB-MCP-003. Same agent `acme-agent-mcp-001`. Same CTRL-MCP-001. MCP-004 **extends** the pipeline; it does not replace tool or scope checks.

## TRUST BOUNDARY

`acmebank.mcp.authorize` before `mcp.tool.execute`. Authorize reads the parsed `arguments.policy_id` plus coded `McpPolicy.allowed_policy_ids` and `ToolSpec.valid_resources`. HTTP cannot set `allowed_policy_ids`, catalog membership, profile, or `control.decision`.

## RESOURCE MODEL

| Role | Values |
|------|--------|
| Catalog (`lookup_policy.valid_resources`) | `{lending-basics, executive-restricted}` |
| Agent grant `allowed_policy_ids` | `{lending-basics}` |
| BASELINE `policy_id` | `lending-basics` |
| ATTACK / RETEST `policy_id` | `executive-restricted` |

Both catalog ids return static lab text. `executive-restricted` is a second harmless snippet, not a real executive document.

The client must never control the grant. Extra HTTP `allowed_policy_ids` → ERROR `unknown_fields`. Extra argument keys (`allowed_policy_ids`, `authorized`, `role`) → ERROR `malformed_arguments`.

## UNKNOWN_RESOURCE

A structurally valid string that is **not** in the resource catalog is:

- decision **ERROR**
- reason **`unknown_resource`**
- `attempted=false`, `executed=false`, `outcome=prevented`
- handler count **0**
- **no** `mcp.started`
- **no** fail-open (defended or vulnerable)

This includes: `does-not-exist`, `LENDING-BASICS`, `"lending-basics "` (trailing space), `" lending-basics"`, `lending-basics%00`, `lending*`, `lending`, `*`.

Internal telemetry retains the exact requested id. There is no `list_policies` API. Lab hop `control.reason` stays the existing teaching field; it is not a catalog dump.

DENY is reserved for a **known** catalog id that is not in the agent grant.

## STRUCTURAL ARGUMENTS

`lookup_policy` requires exactly `{"policy_id": "<string>"}`. Reject missing key, non-string, empty/whitespace-only, arrays, nested objects, unexpected keys. These are ERROR `malformed_arguments`, not MCP-004 ATTACK specimens.

## DUPLICATE JSON KEYS

`POST /mcp/invoke` parses the raw body with a decoder that **rejects duplicate object keys** at any nesting level. Example:

```json
{"policy_id": "lending-basics", "policy_id": "executive-restricted"}
```

is ERROR `duplicate_json_keys` **before** authorize. Handler count **0**. Default `json.loads` last-wins is not used.

## ALLOWTICKET BINDING

`AllowTicket.resource_id` is the exact string that passed catalog + grant (or MCP-004 fail-open). `execute()` builds handler arguments as `{policy_id: ticket.resource_id}`. The handler must not re-read the HTTP body or treat `POLICY_FIXTURES.get(untrusted_argument)` as the ACL. Catalog membership was already checked.

## VULNERABLE vs DEFENDED

| Condition | defended | vulnerable |
|-----------|----------|------------|
| Granted tool + `policy:read` + `lending-basics` | ALLOW `tool_granted` | ALLOW `tool_granted` |
| Granted tool + `policy:read` + `executive-restricted` | **DENY** `resource_not_granted` | **ALLOW** `vulnerable_profile_fail_open:resource_not_granted` |
| Known ungranted tool | DENY `tool_not_granted` | ALLOW MCP-002 fail-open (existing reason; `allowed_tools` in text) |
| Granted tool + excessive catalog scope | DENY `scope_not_granted` | ALLOW `vulnerable_profile_fail_open:scope_not_granted` |
| Unknown resource | ERROR `unknown_resource` | ERROR `unknown_resource` (no fail-open) |

The three fail-open **reasons differ**. Fail-open does **not** rewrite `allowed_resource.ids` (stays `lending-basics`). It does **not** pretend the resource became granted.

## OPERATION SEMANTICS

Unchanged from MCP-001 / MCP-003:

| Moment | attempted | executed | outcome |
|--------|-----------|----------|---------|
| Control ALLOW | false | false | omitted |
| `mcp.started` | true | true | omitted |
| `mcp.completed` | true | true | success |
| `mcp.failed` | true | true | error |
| DENY / pre-execution ERROR | false | false | prevented |

## TELEMETRY (schema 1.2.0)

On `agentsec.control.decision` for `lookup_policy` resource checks:

- `agentsec.mcp.resource.id` — requested / ticket identity
- `agentsec.mcp.allowed_resource.ids` — coded grant (`lending-basics`)

Alongside existing tool, method, scope, control, and operation fields. Preview/hash unchanged. Full arguments are not emitted. No `effective_resource`. No `resource.authorized`.

## DET-MCP-001

**Unchanged.** Canonical RETEST is DENY `resource_not_granted` with no later `mcp.started`, so the detector invariant is unviolated for one invocation per run.

Limitation: DET-MCP-001 groups by `run_id` + tool. Future multiple same-tool invocations in one run would need stronger correlation (likely invocation identity). Not solved in 5B.

## TESTS THAT PROVE IT

`tests/security/test_mcp_resource_authorization.py`, `tests/unit/test_mcp_authorize.py`, `tests/unit/test_json_strict.py`, `tests/integration/test_mcp_004_api.py`, `tests/telemetry/test_mcp_004_events.py`, `tests/unit/test_mcp_004_evidence.py`. Authoritative non-execution: `ToolRegistry.invoke_counts`.
