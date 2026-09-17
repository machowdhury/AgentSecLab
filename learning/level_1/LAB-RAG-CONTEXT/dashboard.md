# Dashboard — `ws_lab_rag_context`

**View:** `ws_lab_rag_context` in the `agentsec` app  
**URL:** `http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_rag_context`

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_rag_context.xml` (what Splunk loads). Rebuild both with `python3 scripts/build_lab_rag_context_dashboard.py`.

GRID 1440 / 12. Tokens: Hunt (defaults BASELINE), BASELINE, ATTACK, RETEST.

Searches reused (bind only): `Q-RAG-CONTEXT-AUTHORITY`, `Q-MCP-WHO`, `Q-MCP-AUTHZ`, `Q-MCP-TOOL`, `Q-MCP-EXECUTED`, `Q-MCP-AFTER-DENY`, `DET-MCP-001-POSITIVE-CONTROL` (SIMULATED). OBSERVE sequence is a Studio view of already-indexed fields, not a new hunt file.

Empty tables stay visible. No-data copy: “No indexed event matched this evidence question.”

Do not treat truncated token boxes as the only copy of a UUID or hash. LEARN and COMPARE show full values.

No DET-RAG. DET-MCP-001 packaged disabled. Splunk does not ALLOW or DENY a tool.
