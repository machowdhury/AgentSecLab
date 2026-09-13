# LAB-MCP-004 Dashboard Studio (WS-MCP-004)

**View:** `ws_lab_mcp_004` in the `agentsec` app  
**Layout:** Dashboard Studio GRID, one dashboard, ten tabs  
**SPL:** Phase 5C validated Q-MCP searches from LAB-MCP-001 plus `Q-MCP-RESOURCE-AUTHZ`. Token bind only (`__RUN_ID__` → `"$token$"`).  
**Not:** a notable-event pack, DET-MCP-004, MCP-005, or Cisco overlay. Saved search `DET-MCP-001` is packaged **disabled**; this dashboard does not enable it.

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_004.xml` (what Splunk loads). Rebuild both with `python scripts/build_lab_mcp_004_dashboard.py`.

## WHAT IS IT?

A tabbed GRID workshop that walks LEARN → PROVE using tables bound to validated Q-MCP queries. Markdown teaches tool grant vs scope grant vs resource grant. Tables show telemetry. What Happened is two indexed-field tables (identity + decision), not LLM prose. Empty teaching is Studio `noDataMessage`, not the populated caption.

## Tokens

| Token | Purpose | Default |
|-------|---------|---------|
| `run_id` | Hunt / OBSERVE / HUNT / DETECT / PROVE What Happened | `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` (BASELINE) |
| `baseline_run_id` | BASELINE tab + COMPARE | `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` |
| `attack_run_id` | ATTACK tab + COMPARE | `5ab59fc7-303e-4eea-84e7-ae0b2f405146` |
| `retest_run_id` | RETEST tab + COMPARE | `0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd` |
| `unknown_run_id` | DEFEND unknown-resource teaching | `0e4e0051-528d-4bf3-8773-d1fb55a5864f` |

Hunt defaults to BASELINE so the dashboard does not open in an error state. Specimen tabs bind their own tokens so BASELINE / ATTACK / RETEST / UNKNOWN show real data without pasting ids.

Malformed-argument and duplicate-key teaching is markdown (Phase 5C `9ea63448-bf6a-4619-b313-b152f4d94bb6` and `ffafb62e-a6c6-42c0-837d-094cbfb3f795`). Duplicate-key has no control.decision token because none was emitted.

## How to use it

1. Open Splunk → AgentSec → **LAB-MCP-004 Parameter and Resource Authorization**.
2. Submit if needed (`submitOnDashboardLoad` is on).
3. Walk the ten tabs. DETECT teaches hunt (`Q-MCP-AFTER-DENY`) and reuse of `DET-MCP-001`. Right table is **SIMULATED** `DET-MCP-001-RESOURCE-POSITIVE-CONTROL`.
4. Paste another complete `run.id` into Hunt to explore OBSERVE / HUNT / DETECT.

Splunk does not invoke tools and does not switch `AGENTSEC_SECURITY_PROFILE`.

## Empty states

Tables stay visible when empty (`hideWhenNoData` is false). Studio `description` is the populated caption. Empty teaching is `noDataMessage` plus the tab markdown. Empty means no matching indexed events for that token. Examples (empty only):

- “No indexed MCP execution event was found for this run.” — not “Resource attack blocked.”
- “No indexed control.decision was found for this run. That is not DENY.”
- “No indexed DENY followed later by mcp.started was found for this run.”
- Q-MCP-AFTER-DENY empty: no indexed violation found; not independent prevention proof.

Do not read a populated table’s caption as “no events found.”

What Happened is two tables: identity (`run_id`, profile, mode, agent, tool) and decision (`decision`, reason, scopes, `resource_id`, `allowed_resource_ids`, `execution_state`, outcome, `result_trust`). Q-MCP-EXECUTED control `executed` is not handler execution; read `has_started` and `execution_state`.

## What this dashboard is not allowed to claim

- Valid argument means authorized resource
- Tool granted means resource granted
- Scope granted means resource granted
- Known-but-ungranted is the same as unknown
- Unknown is DENY
- ALLOW means the handler executed
- ALLOW fail-open means the resource grant changed
- `mcp.started` means success
- `mcp.failed` means prevented
- No Splunk row means blocked
- `allowed_resource.ids` changed during fail-open
- Splunk authorized the resource
- SIMULATED positive control is OBSERVED runtime evidence
- Runtime handler count can be read from Splunk
- 0 detector hits means the system is secure
