# LAB-MCP-CATALOG Tool Description / Catalog Metadata

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.5.0  
**Invariant:** INV-002 (Data Cannot Grant Authority)  
**Attack:** MCP-CATALOG-001 (static tool-description poisoning)  
**Control:** CTRL-MCP-METADATA-001 (OBSERVE) then CTRL-MCP-001 (MCP authorization)  
**Status:** Phase 8E Dashboard Studio workshop (`ws_lab_mcp_catalog`). DET-MCP-001 reused, disabled. **No DET-MCP-CATALOG.** Detection: **DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN**. Scanner integration **NOT STARTED**.

This lab teaches one idea: a tool can be legitimate, its first call can be properly authorized, and its catalog metadata can still contain manipulative content. Metadata is DATA. Metadata may influence what an agent REQUESTS next. Metadata must not determine what authority the server GRANTS next.

LAB-MCP-001 asked: **May this agent call this TOOL?**  
LAB-MCP-003 asked: **May this agent call it at this SCOPE?**  
LAB-MCP-004 asked: **May it operate on this RESOURCE?**  
LAB-MCP-005 asked: **Can TOOL RESULT DATA change later authority?**  
LAB-MCP-006 asked: **Can a DEPUTY exercise authority belonging to another caller?**  
LAB-MCP-CATALOG asks: **Can TOOL METADATA influence a request and improperly become authority?**

REQUEST ≠ GRANT  
OBSERVE ≠ ALLOW  
METADATA PROVENANCE ≠ CONTENT TRUST  
AUTHORIZED TOOL ≠ TRUSTED DESCRIPTION

This is not “malicious MCP tool,” malware detection, “Splunk blocked the attack,” or “scanner blocked the tool.”

## Learner objectives

After this lab you should be able to:

1. Separate catalog metadata from the tool itself.
2. Read METADATA-001 OBSERVE as classification, not authorization.
3. Explain why the first `lookup_policy` ALLOW is legitimate on A/B/C.
4. Show ATTACK and RETEST used the same description **hash**.
5. Explain the vulnerable hop-1 ALLOW as overlay, not description grant.
6. Treat runtime handler count as authoritative non-execution proof.
7. Treat missing Splunk hop-1 `mcp.started` as corroboration only.
8. Explain why DET-MCP-001 stays silent on the preferred ATTACK.
9. Explain why Q-MCP-EXECUTED may show an extra OBSERVE row.
10. Explain why scanner output would still not be authorization.

## Prerequisite knowledge

- LAB-MCP-001–006 workshops.
- Phase 8C runtime (`docs/PHASE8C_MCP_CATALOG_RUNTIME_VALIDATION.md`).
- Phase 8D Splunk (`docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md`).

Not required: scanners, rug-pull, A2A, MLTK.

## Lab architecture

```text
MCP catalog
 → Tool metadata
 → Agent observes metadata
 → Agent may form a request
 → CTRL-MCP-001
 → Handler only after ALLOW
 → OTel
 → Splunk (observe only)
```

## Validated LIVE specimens (Phase 8D)

- BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` — defended, NORMAL hash `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`, METADATA OBSERVE, `lookup_policy` ALLOW, no follow-on, handlers 1/0
- ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4` — vulnerable, MALICIOUS hash `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`, METADATA still OBSERVE, follow-on ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`, handlers 1/1
- RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` — defended, **same MALICIOUS hash as ATTACK**, follow-on DENY `tool_not_granted`, follow-on handler **0**

## How to run the workshop

Open Splunk → AgentSec → **LAB-MCP-CATALOG Tool Description**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

## Files

| File | Purpose |
|------|---------|
| `workshop.md` | Ten-step instructor/learner flow |
| `dashboard.md` | How to use `ws_lab_mcp_catalog` |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `dashboard.definition.json` | Studio source; rebuild with `python3 scripts/build_lab_mcp_catalog_dashboard.py` |
| `searches/Q-MCP-CATALOG-AUTHORITY.spl` | Primary catalog hunt (validated in Phase 8D) |

Existing Q-MCP searches are reused from `../LAB-MCP-001/searches/`. Do not rewrite them here. Do not publish extra Q-MCP-CATALOG-* hunts. Do not create `DET-MCP-CATALOG`.
