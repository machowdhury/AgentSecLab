# LAB-MCP-003 Scope escalation in MCP tool authorization

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.1.0  
**Invariant:** INV-001 (delegated authorization); INV-007 (evidence); INV-008 (fail-safe)  
**Attack:** MCP-003 (excessive catalog-valid scope on a granted tool)  
**Control:** CTRL-MCP-001 (same control as LAB-MCP-001; no CTRL-MCP-003)  
**Status:** Phase 4D Dashboard Studio workshop (`ws_lab_mcp_003`). DET-MCP-001 reused, disabled. No DET-MCP-003.

This lab teaches one idea: a granted MCP tool is not authorized **at every scope the tool can name**. Splunk is where you hunt a copy of the telemetry. Splunk does not ALLOW or DENY a tool.

LAB-MCP-001 asked: **May this agent call this tool?**  
LAB-MCP-003 asks: **May this agent call this tool at this requested scope?**

The tool is authorized. The excessive scope is not.

## Learner objectives

After this lab you should be able to:

1. Distinguish tool grant from scope grant.
2. Explain three states: granted (`policy:read`), known-but-ungranted (`policy:restricted:read`), unknown (`policy:write`).
3. Explain why known-but-ungranted is DENY and unknown catalog tokens are ERROR.
4. Explain why ALLOW is not execution and why fail-open does not rewrite `allowed_scope`.
5. Explain why arguments cannot grant a broader scope.
6. Reuse Q-MCP-SCOPE / Q-MCP-AUTHZ without inventing Q-MCP-003.
7. Explain why DET-MCP-001 can be reused and why 0 detector rows is not non-execution proof.
8. Treat runtime handler count as authoritative for non-execution.

## Prerequisite knowledge

- LAB-MCP-001 tool grant (`docs/PHASE3D_MCP_WORKSHOP.md`).
- Phase 4B runtime (`docs/PHASE4B_MCP003_RUNTIME_VALIDATION.md`).
- Phase 4C Splunk (`docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`).

Not required: MCP-004, Cisco, MLTK, attack chains.

## Lab architecture

```text
User
 → MCP Policy Agent (acme-agent-mcp-001)
 → MCP Client
 → CTRL-MCP-001 (tool exists → granted → scope valid → scope granted → args)
 → MCP Server
 → Tool Handler (ALLOW ticket only)
 → Result (untrusted_data)
 → OTel
 → Splunk (observe only)
```

## Validated LIVE specimens (Phase 4C)

- BASELINE `5b089682-1d5a-49a7-ac43-967265fd6bc6` — `lookup_policy` + `policy:read`, ALLOW, handler=1
- ATTACK `b466ad12-72ec-44b7-be28-aacfaf2c25b1` — `policy:restricted:read`, fail-open ALLOW, handler=1
- RETEST `f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5` — same excessive scope, DENY `scope_not_granted`, handler=0
- UNKNOWN `6ce19813-6cb5-4aae-a3a0-aa59386a82dd` — `policy:write`, ERROR `unknown_scope`, handler=0

## How to run the workshop

Open Splunk → AgentSec → **LAB-MCP-003 Scope escalation in MCP tool authorization**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

## Files

| File | Purpose |
|------|---------|
| `workshop.md` | Ten-step instructor/learner flow |
| `dashboard.md` | How to use `ws_lab_mcp_003` |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `dashboard.definition.json` | Studio source; rebuild with `python scripts/build_lab_mcp_003_dashboard.py` |

Searches are reused from `../LAB-MCP-001/searches/`. Do not rewrite them here.
