# MCP-004 parameter / resource model

**Status:** Phase 5A **DESIGN**. No runtime change.  
**Lab:** LAB-MCP-004. Do not modify LAB-MCP-001 or LAB-MCP-003 specimens or semantics.  
**Evidence class:** **DOCUMENTED** design. AgentSec current behavior cited below is **OBSERVED**.

This document **supersedes** the MCP-004 sketch in `docs/MCP_LAB_PLAN.md` (“validate params before execute” mixed schema with authorization). Schema validity and resource authorization are different questions.

---

## Security property

| Lab | Question |
|-----|----------|
| LAB-MCP-001 | May this agent **call this tool**? |
| LAB-MCP-003 | May this agent call this tool **at this requested scope**? |
| LAB-MCP-004 | May this agent perform this authorized tool/scope operation **on this resource**? |

Do not collapse:

- **input validation** (is `policy_id` a present string with the required key?)
- **parameter / resource authorization** (is that exact id in the agent’s resource grant?)

A parameter may be syntactically valid and still unauthorized.

---

## Harmless resource model

Tool: existing `lookup_policy`. No shell, filesystem mutation, network, credentials, real customers, or real banking actions.

| Role | `policy_id` | Catalog | Agent grant | Teaching |
|------|-------------|---------|-------------|----------|
| Authorized fixture | `lending-basics` | known | granted | BASELINE ALLOW |
| Known, not granted | `executive-restricted` | known | **not** granted | ATTACK / RETEST |
| Unknown | `does-not-exist` | **not** in catalog | n/a | ERROR (not RETEST) |

Both catalog fixtures return **static lab text only**. `executive-restricted` is a second harmless snippet, not a real executive document.

`requested_scope` stays `policy:read` on every MCP-004 specimen. Do not use `policy:restricted:read` here (that is MCP-003). Do not use `lookup_customer_tier` (that is MCP-002).

---

## Two server-owned sets

Parallel to MCP-003 `valid_scopes` vs `allowed_scopes`:

| Set | Owner | Meaning |
|-----|-------|---------|
| **Resource catalog** `POLICY_RESOURCE_CATALOG` | Tool / server | Identifiers the **tool may name**. Not the agent grant. |
| **Resource grant** `allowed_policy_ids` | Coded `McpPolicy` | Identifiers this **agent** may request. |

v1 catalog: `{lending-basics, executive-restricted}`  
v1 grant for `acme-agent-mcp-001`: `{lending-basics}`

HTTP cannot supply `allowed_policy_ids`. Arguments **identify** the requested resource. Arguments **do not** define whether it is permitted.

Rejected authority sources:

- `arguments.allowed_policy_ids`
- `arguments.authorized=true`
- `arguments.role`
- extra HTTP fields
- `requested_scope`
- LLM output
- tool results
- user prose

---

## Comparison (exact opaque identifiers)

```text
policy_id type/presence OK              else ERROR malformed_arguments
policy_id ∈ POLICY_RESOURCE_CATALOG     else ERROR unknown_resource
policy_id ∈ agent.allowed_policy_ids    else DENY resource_not_granted
```

No prefix, regex, substring, wildcard, path traversal, case folding, Unicode normalization, or silent trim on the **authorization** comparison.

Colons are irrelevant here: these ids are opaque labels (`lending-basics`), not scope tokens.

---

## Three resource states (do not collapse)

### KNOWN + GRANTED

`policy_id=lending-basics`

Eligible for ALLOW (after tool + scope + schema already passed).

### KNOWN + NOT GRANTED

`policy_id=executive-restricted`

Structurally valid. In catalog. Not in grant.

- Defended → **DENY** `resource_not_granted`
- Vulnerable → labeled fail-open ALLOW `vulnerable_profile_fail_open:resource_not_granted`

Do **not** call this `malformed_arguments`. Do **not** call this `unknown_resource`.

### UNKNOWN RESOURCE

`policy_id=does-not-exist`

Structurally valid (string, required key). **Not** in the tool catalog.

→ **ERROR** `unknown_resource`

Reasoning (MCP-003 consistency):

| Object | Unknown | Known, ungranted |
|--------|---------|------------------|
| Tool | ERROR `unknown_tool` | DENY `tool_not_granted` |
| Scope | ERROR `unknown_scope` | DENY `scope_not_granted` |
| Resource | ERROR `unknown_resource` | DENY `resource_not_granted` |

ERROR means the request is not a well-defined grant question. DENY means a **defined** authority was requested and refused.

Unknown does **not** fail-open in `vulnerable` (same as unknown_scope / unknown_tool).

### Enumeration

Distinct telemetry reasons let an observer infer catalog membership. That is **required for teaching**.

- **Internal telemetry** (`decision`, `reason`, proposed `resource.id`): precise.
- **Client-facing error text:** do not add “this id exists” vs “this id is unknown” copy, catalog dumps, or “did you mean…”.
- No `list_policies` API.
- Handler must **not** run on ERROR/DENY, so restricted snippet text is not the leak channel.

Lab HTTP already returns control fields to learners. Treat Splunk / `events.jsonl` as the teaching surface. Do not worsen enumeration with extra public APIs.

---

## Authorization order

After the existing HTTP closed contract (`tool`, `arguments`, `requested_scope`, `user_id`):

1. Tool exists (registry)
2. Tool granted (`allowed_tools`)
3. Requested scope valid (∈ tool `valid_scopes`)
4. Requested scope granted (∈ `allowed_scopes`)
5. Argument **schema** valid (keys/types; existing `malformed_arguments`)
6. Referenced resource exists in **server catalog**
7. Referenced resource is **granted** to the agent
8. ALLOW
9. Handler starts (`mcp.started` only after this)

Resource authorization is **before** handler execution.

**OBSERVED gap today:** steps 1–4 live in `authorize_tool`; step 5 runs after that function already returned ALLOW; steps 6–7 do not exist; unknown ids execute in the handler.

MCP-004 implementation (later) must make 5–7 part of the **same control decision** that mints the ticket. Do not treat handler `found:false` as DENY.

---

## Schema vs authorization examples

| Arguments | Schema | Catalog | Grant | Defended |
|-----------|--------|---------|-------|----------|
| `{}` | fail | — | — | ERROR `malformed_arguments` |
| `{"policy_id": 123}` | fail (not str) | — | — | ERROR `malformed_arguments` |
| `{"policy_id": ["lending-basics"]}` | fail | — | — | ERROR `malformed_arguments` |
| extra keys / nested objects | fail | — | — | ERROR `malformed_arguments` |
| `{"policy_id": "does-not-exist"}` | pass | no | — | ERROR `unknown_resource` |
| `{"policy_id": "executive-restricted"}` | pass | yes | no | DENY `resource_not_granted` |
| `{"policy_id": "lending-basics"}` | pass | yes | yes | ALLOW `tool_granted` |

Whitespace-only `policy_id` stays **malformed** (existing emptiness check). `"lending-basics "` (trailing space) is a **different** string: schema-valid, not in catalog → ERROR `unknown_resource`. Do not trim into ALLOW.

---

## Identity matching

Exact string equality on the parser’s `arguments["policy_id"]` value.

| Input | Result (defended, tool+scope already OK) |
|-------|------------------------------------------|
| `lending-basics` | ALLOW |
| `LENDING-BASICS` | ERROR `unknown_resource` |
| `lending-basics ` / ` lending-basics` | ERROR `unknown_resource` |
| `lending-basics%00` (literal those characters) | ERROR `unknown_resource` |
| homoglyph / other Unicode | ERROR `unknown_resource` |
| duplicate JSON keys | 5A lean: last-wins of one parse. **5B:** `POST /mcp/invoke` **rejects** duplicate keys (`duplicate_json_keys`) before authorize; not last-wins. |

Do not silently normalize authorization identifiers.

---

## TOCTOU / check-use

Principle: the identifier **authorized** is the identifier **used** by the handler.

Reuse existing `AllowTicket` (already minted only after ALLOW). **Proposed** additive ticket field (not implemented in 5A):

`resource_id: str` — the exact `policy_id` string that passed catalog + grant.

Handler uses `ticket.resource_id` (or the ticket’s frozen argument dict, which is the same parse). Do not re-read HTTP. Do not re-parse JSON. No cryptographic tickets.

**5B:** `AllowTicket.resource_id` is implemented. `execute()` supplies `{policy_id: ticket.resource_id}` to the handler. Mutating the request dict after ALLOW cannot substitute the resource.

Fail-open **must not** rewrite `allowed_policy_ids`. Telemetry keeps requested `executive-restricted` vs coded grant `lending-basics`.

---

## Principal vs agent

v1 grant is **agent-only**: `acme-agent-mcp-001` → `allowed_policy_ids={lending-basics}`.

Principal `applicant-web` is attributed (INV-004) but does not have a separate resource ACL in this lab.

This is a **lab simplification**, not production IAM, not OAuth scopes, not row-level security, and not MCP-006 confused-deputy.

---

## Why not infer resource from scope

`policy:restricted:read` is a **scope token**. `executive-restricted` is a **resource id**. Mixing them would retcon LAB-MCP-003 and hide IDOR behind scope. MCP-004 holds tool and scope constant.
