# MCP detection engineering 101

**Status:** Phase 3E `DET-MCP-001` (disabled saved search).  
**Parents:** `docs/PHASE3E_MCP_DETECTION.md`, `learning/level_1/LAB-MCP-001/searches/DET-MCP-001.md`.

---

## WHAT IS IT?

One Splunk saved search that looks for MCP tool execution after an authorization DENY for the same run and tool. Lab id `DET-MCP-001`. Display name `AgentSec - MCP Execution After Authorization Deny`.

It is the operational form of the investigation query `Q-MCP-AFTER-DENY`.

## WHY DOES IT EXIST?

HUNT answers “did this happen on this `run.id`?” DETECTION answers “is this invariant being violated anywhere in the window?” Phase 3D taught the hunt. Phase 3E packages one continuous check. Splunk still does not ALLOW or DENY the tool.

## HOW DOES IT WORK?

1. Read `control.decision` and `mcp.started` from `index=agentsec_telemetry`.
2. Collapse duplicated JSON fields.
3. Per `run_id` + tool, find the earliest DENY sequence.
4. Keep `mcp.started` rows with a greater sequence.
5. Copy identity and scope from the DENY event onto that row.

## WHERE DOES IT SIT IN AGENTSEC?

After CTRL-MCP-001 (runtime), OTel, HEC, and Q-MCP hunts. In `savedsearches.conf`, disabled. The workshop DETECT tab explains it; it does not enable it.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` then `mcp.tool.execute`. The detection watches a **copy** of telemetry after the fact.

## WHAT COULD AN ATTACKER CONTROL?

The HTTP body (tool, arguments, requested scope). Not the saved search. Not the profile. A real bypass would have to make the server emit DENY and still run the handler — that is the invariant. This lab’s defended path does not do that.

## WHAT CAN GO WRONG?

- Alerting on DENY alone (RETEST is supposed to DENY).
- Alerting on fail-open ALLOW (ATTACK).
- Treating ERROR as DENY.
- Treating `mcp.failed` after ALLOW as prevention.
- Treating 0 Splunk rows as “the handler never ran.”
- Treating the SIMULATED fixture as a live incident.

## WHAT TELEMETRY SHOULD EXIST?

DENY: `event.name=agentsec.control.decision`, `agentsec.control.decision=DENY`. Violation: later `event.name=agentsec.mcp.started` same `agentsec.run.id` and `gen_ai.tool.name`.

## HOW WILL SPLUNK SHOW IT?

Disabled saved search. DETECT left table: hunt 0 rows on LIVE specimens. DETECT right table: SIMULATED 1 row. Live CLI: 0 rows on A–F; 1 SIMULATED row.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-MCP-001 on the server. Enabling the saved search only changes whether Splunk would alert. It cannot stop the handler.

## WHAT TEST PROVES THE LOGIC?

Pytest: packaging, field contract, disabled flag, SIMULATED core matches detection SPL. Live Splunk CLI: 0 rows on specimens, 1 SIMULATED row (`docs/PHASE3E_MCP_DETECTION.md`). Pytest does not execute Splunk.

---

## What I should now be able to explain

1. What invariant DET-MCP-001 monitors.
2. Why DENY alone is not suspicious.
3. Why `mcp.started` after DENY is different.
4. Why `mcp.failed` after ALLOW is not the same condition.
5. Why ERROR is not DENY.
6. Why Splunk detects a copy but does not enforce authorization.
7. Why the detection is HIGH.
8. Why the positive control is SIMULATED.
9. Why 0 detections is not independent proof of non-execution.
10. Why this is not a general MCP bypass detector.
