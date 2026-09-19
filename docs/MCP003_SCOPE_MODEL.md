# MCP-003 scope model

**Status:** Phase 4A **DESIGN**. Phase 4B **IMPLEMENTED** `valid_scopes` on `ToolSpec`.  
**Lab:** LAB-MCP-003. Do not modify LAB-MCP-001 specimens.  
**Evidence class:** **DOCUMENTED** design. Runtime matching is **MEASURED** in Phase 4B.

---

## Security property

LAB-MCP-001: **May this agent call this tool?**

LAB-MCP-003: **May this agent call this tool with this requested scope?**

Keep those questions separate. A granted tool name is not a grant of every scope that tool can name.

---

## Final model (exact set membership)

### Tool

`lookup_policy` — existing harmless fixture. No shell. No OS privilege. Same `policy_id` arguments as LAB-MCP-001 BASELINE.

### Tool-valid scopes (catalog)

These are scopes the **tool is allowed to name**. Not the agent grant.

| Token | Meaning in the lab |
|-------|--------------------|
| `policy:read` | Public lab lending snippet |
| `policy:restricted:read` | Restricted lab corpus **token**. Still a read. Still a stub. Not admin, not write, not RCE |

Colons are **labels**, not a tree. Matching does **not** walk parents.

### Agent grant (server-owned)

`acme-agent-mcp-001`:

- `allowed_tools = {lookup_policy}`
- `allowed_scopes = {policy:read}`

HTTP cannot supply `allowed_scope` / `allowed_tools`. Coded policy only.

### Comparison

**Exact set membership.**

```text
requested_scope ∈ tool.valid_scopes     else ERROR unknown_scope
requested_scope ∈ agent.allowed_scopes  else DENY scope_not_granted
```

No regex, no substring, no `startsWith`, no wildcards, no “`policy:read` implies `policy:restricted:read`.”

Rejected alternatives:

| Approach | Why not for lab 1 |
|----------|-------------------|
| `policy:write` as the attack token | Sounds like mutation; the handler does not write. Teaches the wrong metaphor. |
| Hierarchical prefix (`policy:` matches all) | **BLOCKER** if used as authorization. `policy:read` would allow `policy:restricted:read`. |
| `startsWith` / wildcard IAM | Same class of bug. Out of scope. |

`docs/MCP_LAB_PLAN.md` mentioned `policy:write` as a sketch. This document **supersedes** that example for LAB-MCP-003.

---

## Why this fits the current implementation

Today (`authorize.py`, OBSERVED):

- `scope_ok = requested_scope in policy.allowed_scopes`
- Granted + not `scope_ok` → `DENY` `scope_not_granted` **even when `profile=vulnerable`**
- Vulnerable fail-open is only `tool not in allowed_tools`

So:

- Defended MCP-003 is a **small explicit catalog + tests**, not a new comparison algorithm.
- Vulnerable MCP-003 is a **new labeled fail-open branch** for granted tool + catalog-valid + ungranted scope.
- Do **not** rewrite `allowed_scope` on fail-open. Telemetry must keep requested=`policy:restricted:read`, allowed=`policy:read`.

`ToolSpec` now has `valid_scopes: frozenset[str]` in addition to `required_scope`. Handler still must **not** read scope. Phase 4B matching is exact membership; no strip/lowercase.

---

## Single requested_scope

First lab: one string field `requested_scope` (already on `POST /mcp/invoke`).

- List / object → HTTP `malformed` / `unknown_fields` **ERROR** (existing closed contract).
- Missing / blank → existing `missing_requested_scope` ERROR (before control).
- No comma-separated multi-scope in v1.

---

## What the handler returns

Same arguments as BASELINE (`policy_id=lending-basics`). After ALLOW, `lookup_policy` returns the same lab snippet. Scope does not select a different database. Result remains `untrusted_data`. This is not a confidentiality lab.
