# Evidence Register

Evidence class: `REPLAY` unless a command is explicitly recorded as live-measured.

## Canonical packet

- ATTACK retrieve `2a248113-7436-46a7-9b1d-0243489ac000` — 5 local events
- ATTACK write `348c8f18-fdfb-4501-ad8a-3f1bcda64c34` — 5
- ATTACK recall `2437f64a-fff4-424f-8a83-0f04285662e4` — 11
- RETEST retrieve `f9015037-651d-4207-ac57-4f3ea1abc673` — 5
- RETEST write `3f8d6305-2d3b-4988-9e65-dc99b7ac10de` — 5
- RETEST recall `8d2c016f-cadc-4463-939a-23a183221b3d` — 10

Shared canonical malicious content fingerprint:

`sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`

## Established by validated runtime evidence

- ATTACK recall: memory `OBSERVE`, then `CTRL-MCP-001 ALLOW`, handler invocation count 1, `mcp.started`, and `mcp.completed`.
- RETEST recall: same memory fingerprint and requested tool, memory `OBSERVE`, then `CTRL-MCP-001 DENY tool_not_granted`, handler invocation count 0.
- Coded authority remains `lookup_policy` / `policy:read`.

Authoritative repository evidence:

- Runtime implementation: `src/agentsec/bank_app.py`, capstone recall route and MCP authorization call.
- PDP: `src/agentsec/mcp/policy.py`, `authorize_tool`; it receives no external-evidence argument.
- Producer/count reconciliation: `docs/PHASE16B_CAPSTONE_LIVE_VALIDATION.md` and `docs/PHASE16B_CAPSTONE_SPLUNK_VALIDATION.md`.
- Live reconciliation: `docs/PHASE16B_CAPSTONE_SPLUNK_VALIDATION.md`.
- Existing runtime searches: `Q-RAG-CONTEXT-AUTHORITY`, `Q-MEMORY-CONTEXT-AUTHORITY`, `Q-MCP-AUTHZ`, and `Q-MCP-EXECUTED`.

## Not established

- Direct retrieve-output-to-write causality: `NOT MODELED`.
- Authentication or workload identity: `NOT MODELED`.
- Goal or Identity control failure in this packet: `NOT OBSERVED`.
- External scanner/evaluation causation: `NOT OBSERVED`.
- Universal resistance after RETEST: `NOT PROVEN`.
- Splunk prevention: incorrect; Splunk is downstream.
