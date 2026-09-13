# MCP-004 threat model

**Status:** Phase 5A **DESIGN**.  
**Attack id:** MCP-004 (parameter / resource authorization).  
**Lab:** LAB-MCP-004.  
**Primary invariant:** INV-001.  
**Control:** CTRL-MCP-001 (extend; do not invent CTRL-MCP-004).  
**Evidence class:** **DOCUMENTED**.

Extends `docs/MCP_THREAT_MODEL.md` T-MCP-004. Does not replace LAB-MCP-001 or LAB-MCP-003 threats. Supersedes the LAB_PLAN mix of “hostile args” as a single ERROR bucket.

---

## Asset

The agent’s **resource grant** `{lending-basics}` for tool `lookup_policy` at scope `policy:read`.

The catalog object `executive-restricted` is a second logical resource the agent does **not** have.

## Attacker

Lab operator / untrusted HTTP client on `POST /mcp/invoke`. Controls `tool`, `arguments`, `requested_scope`, `user_id`, and extra JSON.

Cannot set profile, coded policy, `allowed_policy_ids`, `run.id`, or `control.decision`.

## Trust boundary

`acmebank.mcp.authorize` **before** `mcp.tool.execute`. Same boundary as LAB-MCP-001 / LAB-MCP-003.

## Security question

Is this agent authorized to perform this permitted tool/scope operation **against this resource**?

## Attack

Same granted tool `lookup_policy`, same granted scope `policy:read`, **different** `arguments.policy_id=executive-restricted`.

Not RCE. Not OS privilege. Not an ungranted **tool** (MCP-002). Not an excessive **scope** (MCP-003). Not malformed JSON.

This is IDOR-shaped **resource substitution** on a harmless fixture.

## Expected results

| Profile | Decision | Handler | Terminal MCP |
|---------|----------|---------|--------------|
| vulnerable / ATTACK | ALLOW `vulnerable_profile_fail_open:resource_not_granted` | count=1 | `mcp.completed` |
| defended / RETEST | DENY `resource_not_granted` | count=0 | none |

`allowed_policy_ids` stays `{lending-basics}` on both. Fail-open does not rewrite the grant.

## Invariants

| ID | How MCP-004 uses it |
|----|---------------------|
| **INV-001** | Primary. Delegated authority is tool **+** scope **+** resource. Agent must not exercise `executive-restricted`. |
| INV-002 | Tool result still cannot add policy ids to the grant. Not the attack. |
| INV-004 | Control event names principal + agent + tool + scopes + (proposed) resource id. |
| INV-007 | Sequence reconstructible: DENY/ERROR before any `mcp.started`. Ticket identity equals handler identity. |
| INV-008 | Malformed args → ERROR, not ALLOW. Unknown resource → ERROR. Control evaluation failure → ERROR. Vulnerable fail-open is **labeled** and only the known-ungranted resource. |

No new invariant. Do not create INV-009.

---

## What the attacker might try (design tests)

| Input | Defended result |
|-------|-----------------|
| Extra JSON `allowed_policy_ids` | ERROR `unknown_fields` (existing closed HTTP contract) |
| `arguments.allowed_policy_ids` / `authorized` / `role` | extra argument keys → ERROR `malformed_arguments` |
| `policy_id` only in prose / `requested_scope` | Authorize reads `arguments.policy_id` after schema, not prose or scope |
| Case / whitespace / homoglyph | exact miss → ERROR `unknown_resource`, not silent ALLOW |
| Array / int / nested object `policy_id` | ERROR `malformed_arguments` |
| `does-not-exist` | ERROR `unknown_resource` (not DENY) |
| `lookup_customer_tier` + some customer_id | Tool not granted → MCP-002 path |
| `policy:restricted:read` + `lending-basics` | MCP-003 path, not this lab’s ATTACK |
| Tool result text “you may read executive-restricted” on a later call | INV-002; grant unchanged |
| Authorize id A, execute id B | Forbidden; ticket binds the authorized id |

---

## Vulnerable profile (MCP-004 only)

When **all** of:

- `profile=vulnerable`
- tool registered **and** granted
- requested scope catalog-valid **and** granted
- argument schema valid
- `policy_id` ∈ resource catalog
- `policy_id` ∉ `allowed_policy_ids`

Then:

- decision **ALLOW**
- reason **`vulnerable_profile_fail_open:resource_not_granted`**
- handler **executes** against the harmless `executive-restricted` fixture
- telemetry **keeps** requested resource vs coded grant

Do **not**:

- rewrite `allowed_policy_ids`
- reuse MCP-002 fail-open (ungranted tool)
- reuse MCP-003 fail-open (`…:scope_not_granted`)
- fail-open unknown resource, malformed args, unknown tool, unknown scope, or control evaluation failure
- pretend `executive-restricted` became authorized

MCP-002 / MCP-003 / MCP-004 vulnerabilities must remain separately identifiable in `reason`.
