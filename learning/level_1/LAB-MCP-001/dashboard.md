# LAB-MCP-001 Dashboard Studio (WS-MCP-001)

**View:** `ws_lab_mcp_001` in the `agentsec` app  
**Layout:** Dashboard Studio GRID, one dashboard, ten tabs  
**SPL:** Phase 3C validated Q-MCP searches. Token bind only (`__RUN_ID__` → `"$token$"`).  
**Not:** a notable-event pack, MCP-003+, or Cisco overlay. Saved search `DET-MCP-001` is packaged **disabled**; this dashboard does not enable it.

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_001.xml` (what Splunk loads). Rebuild both with `python scripts/build_lab_mcp_001_dashboard.py`.

## WHAT IS IT?

A tabbed GRID workshop that walks LEARN → PROVE using tables bound to validated Q-MCP queries. Markdown teaches. Tables show telemetry. What Happened is two indexed-field tables (identity + decision), not LLM prose. Empty teaching is Studio `noDataMessage`, not the populated caption.

## Tokens

| Token | Purpose | Default |
|-------|---------|---------|
| `run_id` | Hunt / OBSERVE / HUNT / DETECT / PROVE What Happened | `163d11e2-e751-4282-9406-19b490542ed4` (BASELINE) |
| `baseline_run_id` | BASELINE tab + COMPARE | `163d11e2-e751-4282-9406-19b490542ed4` |
| `attack_run_id` | ATTACK tab + COMPARE | `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` |
| `retest_run_id` | RETEST tab + COMPARE | `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` |

Hunt defaults to BASELINE so the dashboard does not open in an error state. Specimen tabs bind their own tokens so BASELINE / ATTACK / RETEST show real data without pasting ids.

## How to use it

1. Open Splunk → AgentSec → **LAB-MCP-001 MCP tool authorization**.
2. Submit if needed (`submitOnDashboardLoad` is on).
3. Walk the ten tabs. DETECT teaches hunt (`Q-MCP-AFTER-DENY`) and operational detection (`DET-MCP-001`, disabled). Right table is **SIMULATED** `DET-MCP-001-POSITIVE-CONTROL`.
4. Paste another complete `run.id` into Hunt to explore OBSERVE / HUNT / DETECT.

Splunk does not invoke tools and does not switch `AGENTSEC_SECURITY_PROFILE`.

## Empty states

Tables stay visible when empty (`hideWhenNoData` is false). Studio `description` is the populated caption. Empty teaching is `noDataMessage` plus the tab markdown. Empty means no matching indexed events for that token. Examples (empty only):

- “No indexed MCP execution event was found for this run.” — not “Tool was blocked.”
- “No indexed control.decision was found for this run. That is not DENY.”
- Q-MCP-AFTER-DENY empty: no indexed violation found; not independent prevention proof. DET-MCP-001 also did not fire on validated LIVE runs.

Do not read a populated table’s caption as “no events found.”

What Happened is two tables: identity (`run_id`, profile, mode, agent, tool) and decision (`decision`, reason, scopes, `execution_state`, outcome, `result_trust`). Q-MCP-EXECUTED control `executed` is not handler execution; read `has_started` and `execution_state`.

## What this dashboard is not allowed to claim

- ALLOW means the handler executed
- `mcp.started` means success
- `mcp.failed` means prevented
- No Splunk row means DENY
- Unknown tool is DENY
- Known-ungranted tool is ERROR
- Splunk authorized the action
- SIMULATED positive control is OBSERVED runtime evidence
- Runtime handler count can be read from Splunk
