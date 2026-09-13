# LAB-MCP-003 Dashboard Studio (WS-MCP-003)

**View:** `ws_lab_mcp_003` in the `agentsec` app  
**Layout:** Dashboard Studio GRID, one dashboard, ten tabs  
**SPL:** Phase 4C validated Q-MCP searches from LAB-MCP-001. Token bind only (`__RUN_ID__` → `"$token$"`).  
**Not:** a notable-event pack, DET-MCP-003, MCP-004, or Cisco overlay. Saved search `DET-MCP-001` is packaged **disabled**; this dashboard does not enable it.

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_003.xml` (what Splunk loads). Rebuild both with `python scripts/build_lab_mcp_003_dashboard.py`.

## WHAT IS IT?

A tabbed GRID workshop that walks LEARN → PROVE using tables bound to validated Q-MCP queries. Markdown teaches tool grant vs scope grant. Tables show telemetry. What Happened is two indexed-field tables (identity + decision), not LLM prose. Empty teaching is Studio `noDataMessage`, not the populated caption.

## Tokens

| Token | Purpose | Default |
|-------|---------|---------|
| `run_id` | Hunt / OBSERVE / HUNT / DETECT / PROVE What Happened | `5b089682-1d5a-49a7-ac43-967265fd6bc6` (BASELINE) |
| `baseline_run_id` | BASELINE tab + COMPARE | `5b089682-1d5a-49a7-ac43-967265fd6bc6` |
| `attack_run_id` | ATTACK tab + COMPARE | `b466ad12-72ec-44b7-be28-aacfaf2c25b1` |
| `retest_run_id` | RETEST tab + COMPARE | `f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5` |
| `unknown_run_id` | DEFEND unknown-scope teaching | `6ce19813-6cb5-4aae-a3a0-aa59386a82dd` |

Hunt defaults to BASELINE so the dashboard does not open in an error state. Specimen tabs bind their own tokens so BASELINE / ATTACK / RETEST / UNKNOWN show real data without pasting ids.

## How to use it

1. Open Splunk → AgentSec → **LAB-MCP-003 Scope escalation in MCP tool authorization**.
2. Submit if needed (`submitOnDashboardLoad` is on).
3. Walk the ten tabs. DETECT teaches hunt (`Q-MCP-AFTER-DENY`) and reuse of `DET-MCP-001`. Right table is **SIMULATED** `DET-MCP-001-SCOPE-POSITIVE-CONTROL`.
4. Paste another complete `run.id` into Hunt to explore OBSERVE / HUNT / DETECT.

Splunk does not invoke tools and does not switch `AGENTSEC_SECURITY_PROFILE`.

## Empty states

Tables stay visible when empty (`hideWhenNoData` is false). Studio `description` is the populated caption. Empty teaching is `noDataMessage` plus the tab markdown. Empty means no matching indexed events for that token. Examples (empty only):

- “No indexed MCP execution event was found for this run.” — not “Scope escalation was blocked.”
- “No indexed control.decision was found for this run. That is not DENY.”
- Q-MCP-AFTER-DENY empty: no indexed violation found; not independent prevention proof.

Do not read a populated table’s caption as “no events found.”

What Happened is two tables: identity (`run_id`, profile, mode, agent, tool) and decision (`decision`, reason, scopes, `execution_state`, outcome, `result_trust`). Q-MCP-EXECUTED control `executed` is not handler execution; read `has_started` and `execution_state`.

## What this dashboard is not allowed to claim

- Tool granted means scope granted
- Known-but-ungranted is the same as unknown
- Unknown is DENY
- ALLOW means the handler executed
- `mcp.started` means success
- `mcp.failed` means prevented
- No Splunk row means blocked
- `allowed_scope` changed during fail-open
- Splunk authorized the action
- SIMULATED positive control is OBSERVED runtime evidence
- Runtime handler count can be read from Splunk
