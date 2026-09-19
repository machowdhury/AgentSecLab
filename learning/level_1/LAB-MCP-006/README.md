# LAB-MCP-006 Confused Deputy / Delegated Authority

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.4.0  
**Invariant:** INV-001 (Delegated Authorization)  
**Attack:** MCP-006 (confused deputy — ambient authority substitution)  
**Control:** CTRL-DELEGATION-001 (delegated authority) then CTRL-MCP-001 (MCP authorization)  
**Status:** Phase 7D Dashboard Studio workshop (`ws_lab_mcp_006`). DET-MCP-001 reused, disabled. **No DET-MCP-006.** Detection: **DETECTION ANALYZED — NO NEW DETECTOR**.

This lab teaches one idea: the deputy may possess authority, but that is not proof the caller delegated that authority for this operation. Splunk is where you hunt a copy of the telemetry. Splunk does not ALLOW or DENY a deputy call.

LAB-MCP-001 asked: **Can this agent call this tool?**  
LAB-MCP-003 asked: **Can this agent call the tool at this scope?**  
LAB-MCP-004 asked: **Can this agent operate on this resource?**  
LAB-MCP-005 asked: **Can tool-result data widen later authority?**  
LAB-MCP-006 asks: **Can a deputy use authority the caller did not delegate?**

DEPUTY AUTHORITY ≠ CALLER AUTHORITY  
DEPUTY AUTHORITY ≠ DELEGATED AUTHORITY

Not every delegated-agent workflow is a confused-deputy attack. BASELINE is legitimate delegation.

## Learner objectives

After this lab you should be able to:

1. Name the caller, the deputy, and the requested operation from indexed evidence.
2. Separate delegated authority from ambient deputy authority.
3. Name INV-001 as the MCP-006 invariant.
4. Explain why ATTACK CTRL-DELEGATION-001 ALLOW is fail-open, not caller grant.
5. Explain why RETEST DENYs the same request.
6. Explain why DET-MCP-001 stays silent on the preferred ATTACK.
7. Treat runtime handler count as authoritative non-execution proof.
8. Treat missing Splunk `mcp.started` as corroboration only.
9. Explain why downstream MCP ALLOW is not caller authorization.
10. Explain why this lab is not a general MCP confused-deputy detector.

## Prerequisite knowledge

- LAB-MCP-001 tool grant (`docs/PHASE3D_MCP_WORKSHOP.md`).
- LAB-MCP-003 scope grant (`docs/PHASE4D_MCP003_WORKSHOP.md`).
- LAB-MCP-004 resource grant (`docs/PHASE5D_MCP004_WORKSHOP.md`).
- LAB-MCP-005 result trust (`docs/PHASE6D_MCP005_WORKSHOP.md`).
- Phase 7B runtime (`docs/PHASE7B_MCP006_RUNTIME_VALIDATION.md`).
- Phase 7C Splunk (`docs/MCP006_SPLUNK_VALIDATION.md`).

Not required: MCP-007, A2A, Cisco, MLTK, attack chains, RAG, memory.

## Lab architecture

```text
Caller (Credit Agent)
 → request
Deputy (Compliance Agent)
 → CTRL-DELEGATION-001
 → only if ALLOW
CTRL-MCP-001
 → only if ALLOW
Tool handler
 → OTel
 → Splunk (observe only)
```

## Validated LIVE specimens (Phase 7C)

- BASELINE `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2` — defended, `lookup_policy` / `policy:read` / `lending-basics`, source=`delegated`, ALLOW `delegation_granted`, policy handler=1 / tier=0
- ATTACK `d7524a4e-8da6-4171-8867-d2a2168128ac` — vulnerable, `lookup_customer_tier` / `customer:read` / `cust-001`, source=`ambient_deputy`, ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority`, tier handler=1
- RETEST `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4` — defended, **same request as ATTACK**, DENY `delegated_authority_not_granted`, handler=0

ATTACK/RETEST request hash: `sha256:ea33191fceeb105e47270f6839bb98addfb7245a32534138192b23e1fab9a419`

Canonical identities: caller `acme-agent-credit-002`, deputy `acme-agent-compliance-004`, principal `applicant-web`.

## How to run the workshop

Open Splunk → AgentSec → **LAB-MCP-006 Confused Deputy**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

## Files

| File | Purpose |
|------|---------|
| `workshop.md` | Ten-step instructor/learner flow |
| `dashboard.md` | How to use `ws_lab_mcp_006` |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `dashboard.definition.json` | Studio source; rebuild with `python3 scripts/build_lab_mcp_006_dashboard.py` |
| `searches/Q-MCP-DELEGATION.spl` | Primary MCP-006 hunt (validated in Phase 7C) |

Existing Q-MCP searches are reused from `../LAB-MCP-001/searches/`. Do not rewrite them here. Do not publish `Q-MCP-AMBIENT-USE`. Do not create `DET-MCP-006`.
