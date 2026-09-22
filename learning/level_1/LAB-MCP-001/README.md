# LAB-MCP-001 MCP tool authorization

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.1.0  
**Invariant:** INV-001 (delegated authorization); INV-002 (data cannot grant authority); INV-007 (evidence); INV-008 (fail-safe)  
**Attack:** MCP-002 (known-ungranted `lookup_customer_tier`)  
**Control:** CTRL-MCP-001  
**Status:** Phase 3D Dashboard Studio workshop (`ws_lab_mcp_001`). No detections.

This lab teaches one idea: a named MCP `tools/call` must be **authorized on the server before the handler runs**. Splunk is where you hunt a copy of the telemetry. Splunk does not ALLOW or DENY a tool.

`lookup_customer_tier` is not malicious by itself. The problem is **unauthorized invocation**.

## Learner objectives

After this lab you should be able to:

1. Explain what JSON-RPC `tools/call` represents in this lab (in-process, not a full remote MCP product).
2. Distinguish tool **existence** (registered) from **authorization** (granted).
3. Explain why known-but-ungranted is DENY and unknown is ERROR.
4. Explain why ALLOW is not execution, why runtime handler count is authoritative, why indexed `mcp.started` only corroborates a complete copy, and why `mcp.failed` is not prevention.
5. Explain why the control must run before the handler.
6. Treat Splunk as evidence, not the authorization layer.
7. Classify tool results as `untrusted_data`.
8. Explain why missing Splunk events alone cannot prove prevention. Runtime handler count is authoritative.

## Prerequisite knowledge

- Phase 3B runtime: `POST /mcp/invoke`, CTRL-MCP-001, spy registry (`docs/PHASE3B_MCP_RUNTIME_VALIDATION.md`).
- Phase 3C transport + Q-MCP searches (`docs/PHASE3C_MCP_SPLUNK_VALIDATION.md`).
- Indexed field `event.name`. Profile `agentsec.security.profile`. Do not hunt `session.id`.

Not required: MCP-003+, detections, Cisco, MLTK, A2A, RAG.

## Lab architecture

```text
User
 → MCP Policy Agent (acme-agent-mcp-001)
 → MCP Client
 → CTRL-MCP-001
 → MCP Server
 → Tool Handler (ALLOW ticket only)
 → Result (untrusted_data)
 → OTel
 → Splunk (observe only)
```

## Validated LIVE specimens (Phase 3C)

- BASELINE `163d11e2-e751-4282-9406-19b490542ed4` — `lookup_policy`, ALLOW, handler=1, `mcp.completed`
- ATTACK `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` — `lookup_customer_tier`, labeled fail-open ALLOW, handler=1
- RETEST `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` — same ungranted tool, DENY, handler=0

## How to run the workshop

Open Splunk → AgentSec → **LAB-MCP-001 MCP tool authorization**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

## Files

| File | Purpose |
|------|---------|
| `workshop.md` | Ten-step instructor/learner flow |
| `dashboard.md` | How to use `ws_lab_mcp_001` |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `searches/` | Validated Q-MCP SPL (do not rewrite) |
| `dashboard.definition.json` | Studio source; rebuild with `python scripts/build_lab_mcp_001_dashboard.py` |
