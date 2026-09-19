# LAB-MCP-006 Dashboard Studio (WS-MCP-006)

**View:** `ws_lab_mcp_006` in the `agentsec` app  
**Layout:** Dashboard Studio GRID, one dashboard, ten tabs  
**SPL:** Phase 7C validated Q-MCP searches from LAB-MCP-001 plus `Q-MCP-DELEGATION`. Token bind only (`__RUN_ID__` → `"$token$"`).  
**Not:** a notable-event pack, DET-MCP-006, MCP-007, or Cisco overlay. Saved search `DET-MCP-001` is packaged **disabled**; this dashboard does not enable it.

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_006.xml` (what Splunk loads). Rebuild both with `python3 scripts/build_lab_mcp_006_dashboard.py`.

## WHAT IS IT?

A tabbed GRID workshop that walks LEARN → PROVE using tables bound to validated Q-MCP queries. Markdown teaches DEPUTY AUTHORITY ≠ CALLER AUTHORITY. Tables show telemetry. What Happened is `Q-MCP-DELEGATION` (one indexed row per run), not LLM prose. Empty teaching is Studio `noDataMessage`, not the populated caption.

## Tokens

| Token | Purpose | Default |
|-------|---------|---------|
| `run_id` | Hunt / OBSERVE / HUNT / DETECT / PROVE What Happened | `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2` (BASELINE) |
| `baseline_run_id` | BASELINE tab | `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2` |
| `attack_run_id` | ATTACK tab | `d7524a4e-8da6-4171-8867-d2a2168128ac` |
| `retest_run_id` | RETEST tab | `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4` |

Hunt defaults to BASELINE so the dashboard does not open in an error state. Specimen tabs bind their own tokens so BASELINE / ATTACK / RETEST show real data without pasting ids. Changing Hunt drives OBSERVE, HUNT, DETECT left table, and PROVE What Happened.

## How to use it

1. Open Splunk → AgentSec → **LAB-MCP-006 Confused Deputy**.
2. Submit if needed (`submitOnDashboardLoad` is on).
3. Walk the ten tabs. DETECT teaches **DETECTION ANALYZED — NO NEW DETECTOR**. Right table is **SIMULATED** `DET-MCP-001-POSITIVE-CONTROL`.
4. Paste another complete `run.id` into Hunt to explore OBSERVE / HUNT / DETECT.

Splunk does not invoke tools and does not switch `AGENTSEC_SECURITY_PROFILE`.

## Empty states

Tables stay visible when empty (`hideWhenNoData` is false). Studio `description` is the populated caption. Empty teaching is `noDataMessage` plus the tab markdown. Empty means no matching indexed events for that token. Examples (empty only):

- “No indexed MCP execution-start event was found for this run.” — not “The operation was blocked.”
- “No indexed control.decision was found for this run. That is not DENY.”
- “No indexed detection rows matched this run.”
- Q-MCP-AFTER-DENY empty: no indexed DENY-then-start found; not “the attack did not occur.”
- Q-MCP-DELEGATION empty: not safe, not DENY, not proof delegated authority was refused.

Do not read a populated table’s caption as “no events found.”

What Happened is `Q-MCP-DELEGATION`. Fields not in that hunt are **not observed** on that table. Q-MCP-EXECUTED control `executed` is not handler execution; read `has_started` and `execution_state`. Extra EXECUTED rows for two control events on the same tool are expected; they are not hidden.

## Searches bound

| Query ID | Source | Tokens |
|----------|--------|--------|
| Q-MCP-WHO | LAB-MCP-001 | Hunt, BASELINE |
| Q-MCP-AUTHZ | LAB-MCP-001 | Hunt, BASELINE, ATTACK, RETEST |
| Q-MCP-TOOL | LAB-MCP-001 | Hunt, ATTACK, RETEST |
| Q-MCP-EXECUTED | LAB-MCP-001 | Hunt, BASELINE, ATTACK, RETEST |
| Q-MCP-AFTER-DENY | LAB-MCP-001 | Hunt |
| Q-MCP-DELEGATION | LAB-MCP-006 | Hunt, BASELINE, ATTACK, RETEST |
| DET-MCP-001-POSITIVE-CONTROL | LAB-MCP-001 | none (`makeresults`, SIMULATED) |
| observe sequence | helper using Phase 7C indexed fields | Hunt |

Not bound: Q-MCP-SCOPE, Q-MCP-PARAMS, Q-MCP-RESOURCE-AUTHZ, Q-MCP-AMBIENT-USE (rejected), DET-MCP-001.spl (not rewritten; not enabled).

## What this dashboard is not allowed to claim

- Splunk as the enforcer (it indexes; it does not authorize)
- A detector that “caught MCP-006” (none exists)
- Treating deputy authority as caller authority
- Treating ambient authority as delegated authority
- Treating ALLOW as proof of execution
- Treating missing `mcp.started` as proof the handler never ran
- Treating MCP ALLOW as a caller grant of `lookup_customer_tier`
- Treating zero hunt rows as “the control worked”
- Treating no DET-MCP-001 match as “no security violation occurred”
- Treating the SIMULATED positive control as OBSERVED runtime evidence
- Reading runtime handler count from Splunk
- Treating 0 detector hits as “the system is secure”
- An indexed `allowed_tools` field
- A `gen_ai.tool.call.id`
- Inventing RETEST hop-1 deputy when Q-MCP-DELEGATION says `deputy_not_on_indexed_hop1`
