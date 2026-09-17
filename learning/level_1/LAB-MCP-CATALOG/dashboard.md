# LAB-MCP-CATALOG Dashboard Studio (WS-MCP-CATALOG)

**View:** `ws_lab_mcp_catalog` in the `agentsec` app  
**Layout:** Dashboard Studio GRID, one dashboard, ten tabs  
**SPL:** Phase 8D validated Q-MCP searches from LAB-MCP-001 plus `Q-MCP-CATALOG-AUTHORITY`. Token bind only (`__RUN_ID__` → `"$token$"`).  
**Not:** a notable-event pack, DET-MCP-CATALOG, scanner overlay, or rug-pull. Saved search `DET-MCP-001` is packaged **disabled**; this dashboard does not enable it.

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_catalog.xml` (what Splunk loads). Rebuild both with `python3 scripts/build_lab_mcp_catalog_dashboard.py`.

## WHAT IS IT?

A tabbed GRID workshop that walks LEARN → PROVE using tables bound to validated Q-MCP queries. Markdown teaches REQUEST ≠ GRANT and OBSERVE ≠ ALLOW. Tables show telemetry. What Happened is `Q-MCP-CATALOG-AUTHORITY` (one indexed row per run), not LLM prose. Empty teaching is Studio `noDataMessage`, not the populated caption.

## Tokens

| Token | Purpose | Default |
|-------|---------|---------|
| `run_id` | Hunt / OBSERVE / HUNT / DETECT / PROVE What Happened | `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` (BASELINE) |
| `baseline_run_id` | BASELINE tab | `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` |
| `attack_run_id` | ATTACK tab | `a0937bff-31a5-453a-99bf-47d7b5148ce4` |
| `retest_run_id` | RETEST tab | `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` |

Hunt defaults to BASELINE so the dashboard does not open in an error state. Changing Hunt drives OBSERVE, HUNT, DETECT left table, and PROVE What Happened.

## How to use it

1. Open Splunk → AgentSec → **LAB-MCP-CATALOG Tool Description**.
2. Submit if needed (`submitOnDashboardLoad` is on).
3. Walk the ten tabs. DETECT teaches **DETECTION GAP** and labels **SIMULATED**.
4. Paste another complete `run.id` into Hunt to explore OBSERVE / HUNT / DETECT.

Splunk does not invoke tools and does not switch `AGENTSEC_SECURITY_PROFILE`.

## Empty states

Tables stay visible when empty (`hideWhenNoData` is false). Empty means no matching indexed events for that token. Examples:

- “No indexed follow-on MCP execution event was found for this run.” — not “The operation was blocked.”
- “No indexed DENY followed later by mcp.started was found.”
- “No indexed CTRL-MCP-METADATA-001 was found for this run.”

Never: “Attack blocked,” “Tool safe,” “No attack,” “Authorization succeeded,” unless the evidence supports that exact statement.

## Q-MCP-EXECUTED

An extra METADATA-001 OBSERVE row may inherit `lookup_policy` execution_state. Do not teach “metadata executed.”
