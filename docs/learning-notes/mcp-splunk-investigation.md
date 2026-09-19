# MCP Splunk investigation

**Status:** Phase 3C validated on live Splunk. Dashboard Studio is **not** built yet.  
**Parents:** `docs/PHASE3C_MCP_SPLUNK_VALIDATION.md`, `docs/MCP_SPLUNK_FIELD_CONTRACT.md`, `docs/MCP_SEARCH_CONTRACT.md`.  
**SPL:** `learning/level_1/LAB-MCP-001/searches/`.

---

## WHAT IS IT?

Investigation searches that answer **who asked**, **what the control decided**, **whether the tool actually started**, and **whether a DENY was followed by execution telemetry** — using events already in `index=agentsec_telemetry`.

They are questions, not detections.

## WHY DOES IT EXIST?

The runtime already proved CTRL-MCP-001 with a handler spy. Splunk is where you **hunt and reconstruct** after the fact. If the fields are wrong, or you treat missing events as prevention, you will learn the wrong lesson.

## HOW DOES IT WORK?

1. AcmeBank emits JSON security events over OTLP.
2. The collector sends them to Splunk HEC.
3. Splunk extracts JSON fields. Some scalars appear **three times** (indexed JSON + search-time JSON + OTLP attributes). SPL collapses copies with `mvindex(mvdedup('field'),0)`.
4. Each Q-MCP query filters `event.name` and one `agentsec.run.id`, then tables the indexed names that actually exist.

## WHERE DOES IT SIT IN AGENTSEC?

After LEARN → BASELINE → ATTACK → OBSERVE. Splunk is **HUNT / DETECT-question / MEASURE** for MCP, not the enforcement point.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` then `mcp.tool.execute`. Splunk cannot ALLOW or DENY a tool. A Dashboard will not change that.

## WHAT COULD AN ATTACKER CONTROL?

Still only `tool`, `arguments`, `requested_scope`, `user_id` on the HTTP body. They cannot pick `run.id`, profile, or `control.decision`. They also cannot make Splunk invent `mcp.started`.

## WHAT CAN GO WRONG?

- Hunting `session.id` (not used).
- Treating ALLOW as execution (control `executed=false` even when the handler later runs).
- Collapsing ERROR into DENY (`unknown_tool` vs `tool_not_granted`).
- Treating Q-MCP-AFTER-DENY = 0 as proof the handler never ran.
- Dumping `_raw` to “see arguments” instead of preview/hash.

## WHAT TELEMETRY SHOULD EXIST?

Control row always (if authorize ran). `mcp.started` only after ALLOW. `mcp.completed` or `mcp.failed` after start. Scopes on the control row: requested vs **coded** allowed (`policy:read`). Result trust `untrusted_data` on completed only.

## HOW WILL SPLUNK SHOW IT?

`Q-MCP-WHO` / `AUTHZ` / `TOOL` / `SCOPE` / `PARAMS` / `EXECUTED` / `AFTER-DENY` / `RESULT` / `RESULT-TRUST`. Replace `__RUN_ID__`. Compare three runs: BASELINE ALLOW+completed, ATTACK fail-open ALLOW+completed, RETEST DENY with **runtime** handler count 0.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE=defended` vs `vulnerable` on the same `lookup_customer_tier` request. Splunk will show DENY vs labeled ALLOW. The allow-list in code does not change.

## WHAT TEST PROVES THE LOGIC?

Live Splunk CSV in `docs/PHASE3C_MCP_SPLUNK_VALIDATION.md`. Pytest only checks that the `.spl` files mention real field names and that the positive control is `makeresults` **SIMULATED**. The handler spy still proves non-execution for RETEST.

---

## What I should now be able to explain

1. Why `event.name` is the indexed name, not `agentsec.event.name`.
2. Why `mvcount=3` is not three physical events.
3. Why Q-MCP-TOOL filters `mcp.started` instead of ALLOW.
4. Why fail-open ATTACK still shows `allowed_scope=policy:read`.
5. Why ERROR `unknown_tool` must not be reported as DENY.
6. What Q-MCP-AFTER-DENY = 0 does and does not prove.
7. Why the positive control is labeled SIMULATED.
8. Why arguments are preview+hash, not `gen_ai.tool.call.arguments`.
9. Why `untrusted_data` on `mcp.completed` is preparatory, not MCP-005.
10. Why HTTP `arguments` as a string never produces Q-MCP-AUTHZ rows.
