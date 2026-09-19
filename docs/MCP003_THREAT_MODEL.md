# MCP-003 threat model

**Status:** Phase 4A **DESIGN**. Phase 4B runtime implemented.  
**Attack id:** MCP-003 (scope escalation).  
**Lab:** LAB-MCP-003.  
**Primary invariant:** INV-001.  
**Control:** CTRL-MCP-001 (extend; do not invent CTRL-MCP-003).  
**Evidence class:** **DOCUMENTED**.

Extends `docs/MCP_THREAT_MODEL.md` T-MCP-003. Does not replace LAB-MCP-001 threats.

---

## Asset

The agent’s **scope grant** `policy:read` for tool `lookup_policy`. The restricted scope token `policy:restricted:read` is a second logical authority the agent does **not** have.

## Attacker

Lab operator / untrusted HTTP client on `POST /mcp/invoke`. Controls `tool`, `arguments`, `requested_scope`, `user_id`, and extra JSON.

Cannot set profile, coded policy, `run.id`, or `control.decision`.

## Trust boundary

`acmebank.mcp.authorize` **before** `mcp.tool.execute`. Same boundary as LAB-MCP-001.

## Security question

Is this agent authorized to perform this action **at this scope**?

## Attack

Same granted tool `lookup_policy`, same arguments, `requested_scope=policy:restricted:read`.

Not RCE. Not OS privilege escalation. Not a malicious tool name (that was MCP-002).

## Expected results

| Profile | Decision | Handler | Terminal MCP |
|---------|----------|---------|--------------|
| vulnerable / ATTACK | ALLOW `vulnerable_profile_fail_open:scope_not_granted` | count=1 | `mcp.completed` |
| defended / RETEST | DENY `scope_not_granted` | count=0 | none |

`allowed_scope` stays `policy:read` on both.

## Invariants

| ID | How MCP-003 uses it |
|----|---------------------|
| **INV-001** | Primary. Delegated authority is tool **and** scope. Agent must not exercise `policy:restricted:read`. |
| INV-002 | Tool result still cannot grant the missing scope. Not the attack. |
| INV-004 | Control event still names principal + agent + tool + scopes. |
| INV-007 | Sequence reconstructible: DENY before any `mcp.started`. |
| INV-008 | Missing/malformed scope → ERROR, not ALLOW. Unknown scope token → ERROR. Control evaluation failure → ERROR. Vulnerable fail-open is **labeled** and only the known catalog-valid excess scope. |

No new invariant.

---

## What the attacker might try (design tests)

| Input | Defended result |
|-------|-----------------|
| Extra JSON `allowed_scope` | ERROR `unknown_fields` (existing closed contract) |
| `requested_scope` only inside `arguments` | HTTP uses top-level field; missing top-level → ERROR `missing_requested_scope`. Authorize must not read arguments for scope. |
| `policy:read ` / case variants | Strip already at parse; `policy:Read` / `POLICY:READ` not in catalog → ERROR `unknown_scope` |
| `policy:*`, `policy:` | Not in catalog → ERROR `unknown_scope` |
| `lookup_customer_tier` + restricted policy scope | Tool not granted → `tool_not_granted` (MCP-002), not MCP-003 |
| Unknown tool | ERROR `unknown_tool` |
| Scope in tool **result** on a later call | INV-002; grant unchanged |

---

## Vulnerable profile (intentional)

When:

- tool is registered **and** granted
- `requested_scope` ∈ tool `valid_scopes`
- `requested_scope` ∉ agent `allowed_scopes`
- `profile=vulnerable`

Then ALLOW with explicit reason `vulnerable_profile_fail_open:scope_not_granted`. Handler runs.

Do **not** fail-open:

- unknown tool
- unknown scope token
- missing scope
- control evaluation failure
- ungranted tool (that remains the MCP-002 fail-open)

Do **not** copy requested into allowed in telemetry.
