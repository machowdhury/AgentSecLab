# LAB-MCP-005 Dashboard Studio (WS-MCP-005)

**View:** `ws_lab_mcp_005` in the `agentsec` app  
**Layout:** Dashboard Studio GRID, one dashboard, ten tabs  
**SPL:** Phase 6C validated Q-MCP searches from LAB-MCP-001 plus `Q-MCP-RESULT-AUTHORITY`. Token bind only (`__RUN_ID__` → `"$token$"`).  
**Not:** a notable-event pack, DET-MCP-005, MCP-006, or Cisco overlay. Saved search `DET-MCP-001` is packaged **disabled**; this dashboard does not enable it.

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_005.xml` (what Splunk loads). Rebuild both with `python3 scripts/build_lab_mcp_005_dashboard.py`.

## WHAT IS IT?

A tabbed GRID workshop that walks LEARN → PROVE using tables bound to validated Q-MCP queries. Markdown teaches AUTHORIZED TOOL ≠ AUTHORITATIVE RESULT. Tables show telemetry. What Happened is `Q-MCP-RESULT-AUTHORITY` (one indexed row per run), not LLM prose. Empty teaching is Studio `noDataMessage`, not the populated caption.

## Tokens

| Token | Purpose | Default |
|-------|---------|---------|
| `run_id` | Hunt / OBSERVE / HUNT / DETECT / PROVE What Happened | `3013aa39-fe08-4b58-9898-f3abb092ac06` (BASELINE) |
| `baseline_run_id` | BASELINE tab + COMPARE | `3013aa39-fe08-4b58-9898-f3abb092ac06` |
| `attack_run_id` | ATTACK tab + COMPARE | `f3f48182-df57-4b38-b069-17a199dc4939` |
| `retest_run_id` | RETEST tab + COMPARE | `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` |

Hunt defaults to BASELINE so the dashboard does not open in an error state. Specimen tabs bind their own tokens so BASELINE / ATTACK / RETEST show real data without pasting ids. Changing Hunt drives OBSERVE, HUNT, DETECT left table, and PROVE What Happened.

## How to use it

1. Open Splunk → AgentSec → **LAB-MCP-005 Tool Result Trust**.
2. Submit if needed (`submitOnDashboardLoad` is on).
3. Walk the ten tabs. DETECT teaches **DETECTION ANALYZED — NO NEW DETECTOR**. Right table is **SIMULATED** `DET-MCP-001-POSITIVE-CONTROL`.
4. Paste another complete `run.id` into Hunt to explore OBSERVE / HUNT / DETECT.

Splunk does not invoke tools and does not switch `AGENTSEC_SECURITY_PROFILE`.

## Empty states

Tables stay visible when empty (`hideWhenNoData` is false). Studio `description` is the populated caption. Empty teaching is `noDataMessage` plus the tab markdown. Empty means no matching indexed events for that token. Examples (empty only):

- “No indexed MCP execution event was found for this run.” — not “The handler definitely never executed.”
- “No indexed control.decision was found for this run. That is not DENY.”
- “No indexed DENY followed later by mcp.started was found for this run.”
- Q-MCP-AFTER-DENY empty: no indexed DENY-then-start found; not “no security violation occurred.”
- Q-MCP-RESULT-AUTHORITY empty: not safe, not DENY, not proof derived authority was refused.

Do not read a populated table’s caption as “no events found.”

What Happened is `Q-MCP-RESULT-AUTHORITY`. Fields not in that hunt are **not observed** on that table. Q-MCP-EXECUTED control `executed` is not handler execution; read `has_started` and `execution_state`. Extra RESULT-001 rows on EXECUTED / AUTHZ are expected; they are not hidden.

## Searches bound

| Query ID | Source | Tokens |
|----------|--------|--------|
| Q-MCP-WHO | LAB-MCP-001 | Hunt |
| Q-MCP-AUTHZ | LAB-MCP-001 | Hunt, BASELINE, ATTACK, RETEST |
| Q-MCP-TOOL | LAB-MCP-001 | Hunt, BASELINE, ATTACK, RETEST |
| Q-MCP-EXECUTED | LAB-MCP-001 | Hunt, BASELINE, ATTACK, RETEST |
| Q-MCP-AFTER-DENY | LAB-MCP-001 | Hunt |
| Q-MCP-RESULT | LAB-MCP-001 | Hunt |
| Q-MCP-RESULT-TRUST | LAB-MCP-001 | Hunt |
| Q-MCP-RESULT-AUTHORITY | LAB-MCP-005 | Hunt, BASELINE, ATTACK, RETEST |
| DET-MCP-001-POSITIVE-CONTROL | LAB-MCP-001 | none (`makeresults`, SIMULATED) |
| observe sequence | helper using Phase 6C indexed fields | Hunt |

Not bound: Q-MCP-SCOPE, Q-MCP-PARAMS, Q-MCP-RESOURCE-AUTHZ, Q-MCP-RESULT-FOLLOWON (rejected), DET-MCP-001.spl (not rewritten; not enabled).

## What this dashboard is not allowed to claim

- Splunk as the enforcer (it indexes; it does not authorize)
- A detector that “caught MCP-005” (none exists)
- Treating result content as trusted
- Treating a matching hash as safety or authority
- Treating ALLOW as proof of execution
- Treating missing `mcp.started` as proof the handler never ran
- Treating overlay ALLOW as a server grant of `lookup_customer_tier`
- Treating zero hunt rows as “the control worked”
- Treating no DET-MCP-001 match as “no security violation occurred”
- Treating the SIMULATED positive control as OBSERVED runtime evidence
- Reading runtime handler count from Splunk
- Treating 0 detector hits as “the system is secure”
- An indexed `allowed_tools` field
- A `gen_ai.tool.call.id`
- Reconstructing truncated preview (`lookup_customer_tie` → full tool name)
