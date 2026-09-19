# Dashboard — `ws_lab_memory_security`

**View:** `ws_lab_memory_security` in the `agentsec` app  
**URL:** `http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_memory_security`

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_memory_security.xml` (what Splunk loads). Rebuild both with `python3 scripts/build_lab_memory_security_dashboard.py`.

GRID 1440 / 12.

Tokens (eight — Hunt is a write+recall pair because Q-MEMORY needs both `run.id` values; all six specimen IDs remain labeled):

| Token title | Token | Default (Phase 11C LIVE) |
|-------------|-------|--------------------------|
| Hunt write | `write_run_id` | BASELINE WRITE |
| Hunt recall | `run_id` | BASELINE RECALL |
| BASELINE WRITE | `baseline_write_run_id` | `a8407246-7992-4ad8-bd02-cb701e150f30` |
| BASELINE RECALL | `baseline_recall_run_id` | `914c41ce-5123-49eb-892c-c948295dbc46` |
| ATTACK WRITE | `attack_write_run_id` | `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` |
| ATTACK RECALL | `attack_recall_run_id` | `b8737cd9-9b6b-48f2-acfa-178ae1446ddc` |
| RETEST WRITE | `retest_write_run_id` | `060a0a72-ceb5-4b99-8330-98de81d8ae5e` |
| RETEST RECALL | `retest_recall_run_id` | `5d5b9d1b-092d-4ddb-8422-4092d289cd49` |

Q-MCP tables bind **recall** tokens. Q-MEMORY binds write + recall.

Searches reused (bind only): `Q-MEMORY-CONTEXT-AUTHORITY`, `Q-MCP-WHO`, `Q-MCP-AUTHZ`, `Q-MCP-TOOL`, `Q-MCP-EXECUTED`, `Q-MCP-AFTER-DENY`, `DET-MCP-001-POSITIVE-CONTROL` (SIMULATED). OBSERVE sequences are Studio views of already-indexed fields, not new hunt files.

Empty tables stay visible. No-data copy: “No indexed event matched this evidence question.”

Do not treat truncated token boxes as the only copy of a UUID or hash. LEARN, COMPARE, and PROVE show full values.

No DET-MEMORY. DET-MCP-001 packaged disabled. Splunk does not ALLOW or DENY a tool.
