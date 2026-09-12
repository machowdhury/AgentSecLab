# LAB-MCP-001 searches

Foundational investigation SPL for LAB-MCP-001 (MCP tool invoke). Not detections. No Dashboard Studio in Phase 3C.

Replace `__RUN_ID__` with a concrete `agentsec.run.id` before running.

Validated 2026-09-12 against live Splunk CLI (`index=agentsec_telemetry`, `sourcetype=otel:agentic:json`):

| Role | run.id |
|------|--------|
| BASELINE defended `lookup_policy` ALLOW | `163d11e2-e751-4282-9406-19b490542ed4` |
| ATTACK vulnerable `lookup_customer_tier` labeled ALLOW | `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` |
| RETEST defended `lookup_customer_tier` DENY | `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` |
| Unknown tool ERROR | `2e804c0d-eb86-405a-ab8d-360616df0ef9` |
| Malformed arguments ERROR | `f2ef017e-d66c-4712-bacd-07138a30d2e6` |
| HTTP schema malformed (no control event) | `a701403a-d146-4473-b7cf-881c1fa92229` |
| Handler failure after ALLOW | `5b83b6e4-f8c4-4989-8ef5-b76614b49ca5` |

Q-MCP-AFTER-DENY positive control is **SIMULATED** (`makeresults`, not indexed). See `Q-MCP-AFTER-DENY-POSITIVE-CONTROL.spl`.

See `docs/PHASE3C_MCP_SPLUNK_VALIDATION.md`, `docs/MCP_SPLUNK_FIELD_CONTRACT.md`, `docs/MCP_SEARCH_CONTRACT.md`.
