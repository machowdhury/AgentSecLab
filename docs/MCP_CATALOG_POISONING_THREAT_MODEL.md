# MCP catalog poisoning — threat model

**Status:** Phase 8B DESIGN.  
**Attacker:** Compromised or malicious MCP **server operator** (or anyone who can set `Tool.description` on a still-registered tool). Not the HTTP client minting grants.

---

## Assets

| Asset | Trust |
|-------|--------|
| Coded `McpPolicy` | Server-owned |
| Tool registry (names/handlers) | Server-owned |
| Tool `description` / `inputSchema` text | **Untrusted data** even if the server is “the lab MCP server” |
| Scanner findings | Untrusted **evidence**, not policy |
| Follow-on `lookup_customer_tier` | Registered; **not** granted |

---

## Threats in scope (8B)

| Threat | Mechanism | Out of scope if |
|--------|-----------|-----------------|
| Static description TPA | Instruction-like text in `description` causes follow-on **request** | Handler is rewritten |
| Metadata as grant | Vulnerable overlay treats intent as authority | Client JSON `allowed_tools` (already rejected) |
| Confusion with MCP-005 | Learner thinks result and description are the same channel | — |

## Threats deferred

| Threat | Why deferred |
|--------|----------------|
| Rug-pull / list_changed | Phase 9. Different property (integrity over time). |
| Cross-server shadowing | Needs two MCP servers. |
| `inputSchema` property-description poison | Same INV-002; keep 8B variable = Tool.`description` only. Document as residual. |
| `annotations` treated as trusted | MCP spec: clients MUST consider annotations untrusted. Teaching note; not the A/B/C variable. |
| Real SSH/key exfil | Unsafe. Lab uses harmless `lookup_customer_tier`. |

---

## Trust boundary

**Boundary:** catalog metadata → planner/interpreter → authorization.

Attacker controls: `description` string on `lookup_policy`.

Attacker does **not** control: coded grants, profile (except via lab settings), `run.id`, agent id, scanner-as-DENY (must not exist).

---

## Expected results

| Profile | Malicious description | Follow-on |
|---------|----------------------|-----------|
| defended | Still data | CTRL-MCP-001 DENY `tool_not_granted`; handler 0 |
| vulnerable | Overlay minted | CTRL-MCP-001 ALLOW with metadata fail-open reason; handler 1 |

First `lookup_policy` remains ALLOW+execute when granted in both profiles.
