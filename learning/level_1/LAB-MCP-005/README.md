# LAB-MCP-005 Tool Result Trust

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.3.0  
**Invariant:** INV-002 (Data Cannot Grant Authority)  
**Attack:** MCP-005 (malicious tool-result content used as result-derived authority)  
**Control:** CTRL-MCP-001 (follow-on tool grant) + CTRL-MCP-RESULT-001 (classify only; does not grant)  
**Status:** Phase 6D Dashboard Studio workshop (`ws_lab_mcp_005`). DET-MCP-001 reused, disabled. **No DET-MCP-005.** Detection: **DETECTION ANALYZED — NO NEW DETECTOR**.

This lab teaches one idea: an **authorized tool** is not an **authoritative result**. Data returned by a legitimate invoke cannot create permission. Splunk is where you hunt a copy of the telemetry. Splunk does not ALLOW or DENY a follow-on tool.

LAB-MCP-001 asked: **May the agent call this tool?**  
LAB-MCP-003 asked: **May the agent call this tool at this requested scope?**  
LAB-MCP-004 asked: **May the agent call this tool at this scope for this resource?**  
LAB-MCP-005 asks: **Can data returned by the authorized tool alter future authority?**

MCP-005 begins **after** a legitimate tool execution.

AUTHORIZED TOOL ≠ AUTHORITATIVE RESULT  
DATA ≠ AUTHORITY  
PROVENANCE ≠ AUTHORITY

## Learner objectives

After this lab you should be able to:

1. Explain why an authorized tool does not make its result authoritative.
2. Separate provenance, content, and authority.
3. Name INV-002 as the MCP-005 invariant.
4. Explain why ATTACK follow-on is labeled ALLOW (overlay, not server grant).
5. Explain why RETEST DENYs the same follow-on.
6. Explain why DET-MCP-001 stays silent on the preferred ATTACK.
7. Treat a matching result hash as content identity, not trust.
8. Treat runtime handler count as authoritative non-execution proof.
9. Explain why this lab is not prompt-injection resistance.
10. Explain why repeated same-tool invocations would need stronger correlation.

## Prerequisite knowledge

- LAB-MCP-001 tool grant (`docs/PHASE3D_MCP_WORKSHOP.md`).
- LAB-MCP-003 scope grant (`docs/PHASE4D_MCP003_WORKSHOP.md`).
- LAB-MCP-004 resource grant (`docs/PHASE5D_MCP004_WORKSHOP.md`).
- Phase 6B runtime (`docs/PHASE6B_MCP005_RUNTIME_VALIDATION.md`).
- Phase 6C Splunk (`docs/MCP005_SPLUNK_VALIDATION.md`).

Not required: MCP-006, Cisco, MLTK, attack chains, RAG, memory.

## Lab architecture

```text
User
 → MCP Policy Agent
 → MCP Client
 → CTRL-MCP-001 (hop 0: lookup_policy)
 → Tool Handler
 → TOOL RESULT = DATA
 → CTRL-MCP-RESULT-001 (classify)
 → RESULT / DATA TRUST BOUNDARY
 → follow-on intent (if any)
 → CTRL-MCP-001 (hop 1)
 → FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION
 → OTel
 → Splunk (observe only)
```

## Validated LIVE specimens (Phase 6C)

- BASELINE `3013aa39-fe08-4b58-9898-f3abb092ac06` — defended, NORMAL, RESULT-001 OBSERVE, no follow-on, policy handler=1 / tier=0
- ATTACK `f3f48182-df57-4b38-b069-17a199dc4939` — vulnerable, MALICIOUS, overlay ALLOW, follow-on handler=1
- RETEST `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` — defended, **same MALICIOUS hash**, DENY `tool_not_granted`, follow-on handler=0

MALICIOUS hash (ATTACK = RETEST): `sha256:f7d67b151741ef7c7efb60242b96f8325996709128293da424f53a547230c358`

## How to run the workshop

Open Splunk → AgentSec → **LAB-MCP-005 Tool Result Trust**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

## Files

| File | Purpose |
|------|---------|
| `workshop.md` | Ten-step instructor/learner flow |
| `dashboard.md` | How to use `ws_lab_mcp_005` |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `dashboard.definition.json` | Studio source; rebuild with `python3 scripts/build_lab_mcp_005_dashboard.py` |
| `searches/Q-MCP-RESULT-AUTHORITY.spl` | Primary MCP-005 hunt (validated in Phase 6C) |

Existing Q-MCP searches are reused from `../LAB-MCP-001/searches/`. Do not rewrite them here. Do not publish `Q-MCP-RESULT-FOLLOWON`. Do not create `DET-MCP-005`.
