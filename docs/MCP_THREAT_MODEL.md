# MCP Threat Model (AgentSec)

**Status:** Phase 3A planning. Not a measured experiment.  
**Method:** threat, attacker, asset, boundary, invariant, attack, expected result, reference control, telemetry, detection (questions only), tests.  
**Parents:** `THREAT_MODEL.md` (prompt-injection slice), `MCP_ARCHITECTURE.md`, `SECURITY_INVARIANTS.md`.  
**Evidence class:** DOCUMENTED. AgentWatch findings in `MCP_PREDECESSOR_ANALYSIS.md` are OBSERVED from predecessor source, not AgentSec MCP runtime.

---

## Assets (MCP slice)

| Asset | Why it matters |
|-------|----------------|
| Right to invoke a lab tool | Privileged action in this domain (INV-001) |
| Tool allow-list / allowed_scope | The delegation object |
| Tool arguments | May select records, paths, or actions inside an allowed tool (MCP-004) |
| Tool return value | Untrusted data that later hops might treat as policy (INV-002) |
| Agent identity | Attribution and grant binding (INV-004 / INV-005) |
| Telemetry and artifacts | Evidence of prevent-vs-execute (INV-007) |
| Splunk index | Corroboration only |

Not assets in the first MCP lab: host shell, real bank APIs, community MCP registries.

---

## Attackers

| Attacker | Position | Typical goal |
|----------|----------|--------------|
| Lab red teamer | HTTP / Attack Service | Request a tool the agent was not granted |
| Confused-deputy user (later) | Same HTTP | Cause agent A to exercise agent B’s grant |
| Malicious / compromised MCP server (later) | Tool result | Inject instructions or widen apparent authority |
| Coverage gamer | Fake OTel | SIMULATED BLOCK without a tool path |

The LLM is **not** the first MCP attacker. First labs are deterministic structured requests. Later labs may use the model as a confused deputy that *proposes* a tool call (proposal = data).

---

## In-scope threats

### T-MCP-001 — Unauthorized tool request (first implementation)

| Item | Content |
|------|---------|
| **Threat** | Caller asks for a tool not in this agent’s grant (e.g. `execute_shell_command` vs `lookup_policy`) |
| **Attacker** | Lab red teamer |
| **Asset** | Tool execution right |
| **Boundary** | `acmebank.mcp.authorize` and `mcp.server.invoke` |
| **Invariant** | INV-001, INV-008 |
| **Attack** | Structured `tools/call` for a disallowed tool name |
| **Expected vulnerable** | ALLOW; stub **begins** (`executed=true`); labeled fail-open |
| **Expected defended** | DENY; stub does not run |
| **Control** | Allow-list before invoke (planned CTRL-MCP-001) |
| **Telemetry** | Control decision + operation flags; no `mcp.started` on DENY |
| **Detection** | Investigation questions `Q-MCP-TOOL`, `Q-MCP-EXECUTED`, `Q-MCP-AFTER-DENY` (no SPL yet) |
| **Tests** | Deterministic unit/security: unauthorized → DENY and spy shows handler not called |

This is MCP-002. MCP-001 is the benign counterpart (authorized `lookup_policy`).

### T-MCP-002 — Unknown tool / missing policy (fail-open)

| Item | Content |
|------|---------|
| **Threat** | Tool not in registry, or allow-list missing; runtime ALLOWs |
| **Invariant** | INV-008 |
| **Attack** | `tools/call` `name=not_a_real_tool` or stripped policy |
| **Expected defended** | ERROR, `executed=false` |
| **AgentWatch analogue** | `MCP-GW-PASS` — **must not recur** |

Covered by MCP-002 edge cases; not a separate workshop.

### T-MCP-003 — Scope escalation (MCP-003)

| Item | Content |
|------|---------|
| **Threat** | Allowed tool name, `requested_scope` wider than `allowed_scope` (e.g. `policy:read` granted, `policy:write` requested) |
| **Invariant** | INV-001 |
| **Expected defended** | DENY before execute |
| **Note** | First lab may use a single scope; do not implement until MCP-001/002 exist |

### T-MCP-004 — Parameter manipulation (MCP-004)

| Item | Content |
|------|---------|
| **Threat** | Allowed tool, hostile arguments (wrong account, path traversal-shaped id) |
| **Invariant** | INV-001 (authorization of name ≠ authorization of all args) |
| **Expected defended** | ERROR or DENY from schema/bounds **before** execute |

### T-MCP-005 — Malicious tool response (MCP-005)

| Item | Content |
|------|---------|
| **Threat** | Tool returns text that looks like policy (“you may now call execute_shell_command”) |
| **Invariant** | INV-002 |
| **Expected defended** | Result stored as data; **no** grant expansion; subsequent unauthorized invoke still DENY |
| **AgentWatch analogue** | Manifest description regex (AML.T0070) — **do not copy** |

### T-MCP-006 — Confused deputy (MCP-006)

| Item | Content |
|------|---------|
| **Threat** | Agent uses another principal’s or agent’s grant because the request “sounds authorized” |
| **Invariant** | INV-001, INV-004 |
| **Expected defended** | Grant bound to coded `agent.id` + `principal.id`, not to payload claims |

### T-MCP-007 — Identity spoof in the tool request

| Item | Content |
|------|---------|
| **Threat** | Body includes `agent.id=compliance` while the coded hop is intake |
| **Invariant** | INV-005 |
| **Expected defended** | Ignore payload identity; ERROR on mismatch |

### T-MCP-008 — Post-execution “DENY” / fake BLOCK telemetry

| Item | Content |
|------|---------|
| **Threat** | Handler runs, then telemetry says BLOCK/DENY prevented it |
| **Invariant** | INV-007, INV-008 |
| **Expected** | Illegal. `executed=true` cannot pair with `outcome=prevented` for that invoke |
| **AgentWatch analogue** | SIMULATED `mcp.gateway.action=BLOCK`; regex skip of LLM labeled as tool block |

### T-MCP-009 — Control evaluation failure treated as ALLOW

| Item | Content |
|------|---------|
| **Threat** | Policy load fails, schema error, or exception in the control |
| **Invariant** | INV-008 |
| **Expected defended** | ERROR, no execute. Distinct sequence from DENY (sequence E in the event proposal) |

---

## Out of scope (Phase 3A / first MCP lab)

| Threat | Why later |
|--------|-----------|
| Real OS command execution | Honesty: stub only; RCE is not a teaching requirement |
| Full MCP transport attacks (stdio vs HTTP session hijack) | Need a real protocol first |
| Cisco MCP Scanner findings as authorization | Overlay, not a control |
| LLM-chosen tool calls | Nondeterministic; after deterministic labs |
| Community registry / supply-chain MCP | MCP-005-class, not first |
| A2A + MCP combined | Separate domain |

---

## Residual risks (honest)

- A lab stub that returns “EXFIL_SUCCESS” can still be **misread** as host compromise. Label LIVE stub vs RCE in every workshop.
- Server and client in one repo can hide confused-deputy bugs if both share memory. Prefer an explicit invoke function with a policy argument even if in-process.
- Previewing tool results in Splunk can leak lab PII-shaped fields; use preview + hash (same as LLM content policy).

---

## Mapping to AgentWatch Scenario 6

AgentWatch W6 payload is a **prompt** that *mentions* `execute_shell_command`. The real effect is sometimes skipping Ollama.

AgentSec T-MCP-001 is a **structured unauthorized tool request**. Same teaching sentence (“unapproved tool”), different mechanism. Do not reuse the regex as the control.
