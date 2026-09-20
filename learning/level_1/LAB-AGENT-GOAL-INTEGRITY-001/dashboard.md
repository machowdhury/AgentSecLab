# Dashboard — `ws_lab_agent_goal_integrity`

**View:** `ws_lab_agent_goal_integrity` in the `agentsec` app  
**URL:** `http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_agent_goal_integrity`

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_agent_goal_integrity.xml` (what Splunk loads). Rebuild both with `python3 scripts/build_lab_agent_goal_integrity_dashboard.py`.

GRID 1440 / 12.

GRID 1440 / 12.

Learner hunt control: **Investigate specimen** dropdown (`run_id`). Canonical BASELINE / ATTACK / RETEST pages bind Phase 13C LIVE IDs as literals (not editable fields). Submit is not required.

| Dropdown label | Token value (Phase 13C LIVE) |
|----------------|------------------------------|
| Baseline — defended / normal | `0aced342-1295-4820-b807-9a8718d9e847` |
| Attack — vulnerable / malicious | `fd994587-7e1c-4a70-8013-54cb2c85254d` |
| Retest — defended / malicious | `605ba7c1-449b-4338-92df-7da3b704b08e` |

Full UUIDs remain on LEARN / specimen / COMPARE / PROVE cards. Custom run.id is an advanced Search workflow (Studio cannot safely share one hunt token with a free-text field).

Searches reused (bind only): `Q-GOAL-INTEGRITY-AUTHORITY`, `Q-MCP-WHO`, `Q-MCP-AUTHZ`, `Q-MCP-TOOL`, `Q-MCP-EXECUTED`, `Q-MCP-AFTER-DENY`, `DET-MCP-001-POSITIVE-CONTROL` (SIMULATED). OBSERVE sequence is a Studio view of already-indexed fields, not a new hunt file.

Empty tables stay visible. No-data copy: “No indexed event matched this evidence question.”

Do not treat truncated token boxes as the only copy of a UUID or hash. LEARN, COMPARE, and PROVE show full values.

No DET-GOAL. DET-MCP-001 packaged disabled. Splunk does not ALLOW or DENY a tool or a task.
