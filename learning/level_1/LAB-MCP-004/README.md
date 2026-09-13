# LAB-MCP-004 Parameter and Resource Authorization

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.2.0  
**Invariant:** INV-001 (delegated authorization); INV-007 (evidence); INV-008 (fail-safe)  
**Attack:** MCP-004 (catalog-valid ungranted resource on a granted tool and granted scope)  
**Control:** CTRL-MCP-001 (same control as LAB-MCP-001 / LAB-MCP-003; no CTRL-MCP-004)  
**Status:** Phase 5D Dashboard Studio workshop (`ws_lab_mcp_004`). DET-MCP-001 reused, disabled. No DET-MCP-004.

This lab teaches one idea: a granted MCP tool at a granted scope is not authorized **against every resource that tool can name**. Splunk is where you hunt a copy of the telemetry. Splunk does not ALLOW or DENY a resource.

LAB-MCP-001 asked: **May the agent call this tool?**  
LAB-MCP-003 asked: **May the agent call this tool at this requested scope?**  
LAB-MCP-004 asks: **May the agent call this tool at this scope for this resource?**

The tool is authorized. The scope is authorized. The excessive resource is not.

tool authorization ≠ scope authorization  
scope authorization ≠ resource authorization  
syntactically valid arguments ≠ authorized arguments

## Learner objectives

After this lab you should be able to:

1. Distinguish tool grant, scope grant, and resource grant.
2. Explain three resource states: granted (`lending-basics`), known-but-ungranted (`executive-restricted`), unknown (`does-not-exist`).
3. Explain why known-but-ungranted is DENY and unknown catalog tokens are ERROR.
4. Explain why a valid `policy_id` string is not automatically authorized.
5. Explain why ALLOW is not execution and why fail-open does not rewrite `allowed_resource.ids`.
6. Explain why arguments identify a resource and cannot widen the grant.
7. Explain AllowTicket check/use: resource authorized = resource used.
8. Reuse Q-MCP-RESOURCE-AUTHZ / Q-MCP-AUTHZ without inventing DET-MCP-004.
9. Explain why DET-MCP-001 can be reused and why 0 detector rows is not non-execution proof.
10. Treat runtime handler count as authoritative for non-execution.

## Prerequisite knowledge

- LAB-MCP-001 tool grant (`docs/PHASE3D_MCP_WORKSHOP.md`).
- LAB-MCP-003 scope grant (`docs/PHASE4D_MCP003_WORKSHOP.md`).
- Phase 5B runtime (`docs/PHASE5B_MCP004_RUNTIME_VALIDATION.md`).
- Phase 5C Splunk (`docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md`).

Not required: MCP-005, Cisco, MLTK, attack chains.

## Lab architecture

```text
User
 → MCP Policy Agent (acme-agent-mcp-001)
 → MCP Client
 → CTRL-MCP-001 (tool → scope → args → resource exists → resource granted → AllowTicket)
 → MCP Server
 → Tool Handler (ticket.resource_id only)
 → Result (untrusted_data)
 → OTel
 → Splunk (observe only)
```

## Validated LIVE specimens (Phase 5C)

- BASELINE `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` — `lookup_policy` + `policy:read` + `lending-basics`, ALLOW, handler=1
- ATTACK `5ab59fc7-303e-4eea-84e7-ae0b2f405146` — `executive-restricted`, fail-open ALLOW, handler=1
- RETEST `0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd` — same ungranted resource, DENY `resource_not_granted`, handler=0
- UNKNOWN `0e4e0051-528d-4bf3-8773-d1fb55a5864f` — `does-not-exist`, ERROR `unknown_resource`, handler=0

## How to run the workshop

Open Splunk → AgentSec → **LAB-MCP-004 Parameter and Resource Authorization**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

## Files

| File | Purpose |
|------|---------|
| `workshop.md` | Ten-step instructor/learner flow |
| `dashboard.md` | How to use `ws_lab_mcp_004` |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `dashboard.definition.json` | Studio source; rebuild with `python scripts/build_lab_mcp_004_dashboard.py` |
| `searches/Q-MCP-RESOURCE-AUTHZ.spl` | Primary MCP-004 hunt (validated in Phase 5C) |

Existing Q-MCP searches are reused from `../LAB-MCP-001/searches/`. Do not rewrite them here.
