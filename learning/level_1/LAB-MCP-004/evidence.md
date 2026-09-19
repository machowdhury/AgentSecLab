# LAB-MCP-004 evidence

Prevention and reconstruction use a **hierarchy**. A later layer cannot overrule an earlier one.

```text
1. Runtime          did the handler run? (handler_invoke_count)
2. Local pack       artifacts/<run-id>/events.jsonl
3. Export           export.json (lossy; otlp.ok ≠ Splunk)
4. Splunk indexed   corroborating copy of what arrived
5. Search           analytical interpretation of that copy (Q-MCP-* + Q-MCP-RESOURCE-AUTHZ)
6. Detection        DET-MCP-001: no indexed DENY→mcp.started found
```

Do not skip to Splunk and declare the lab proven.

Runtime handler count is authoritative proof of non-execution.

Splunk corroborates.

Q-MCP-RESOURCE-AUTHZ is investigation context for requested vs granted resource.

DET-MCP-001 proves only that no indexed DENY→execution invariant violation was found.

0 detector hits is not: system is secure.

## What each layer proves

| Layer | What it can prove | What it cannot prove |
|-------|-------------------|----------------------|
| **Runtime** | Handler began or did not (`invoke_counts`) | Whether Splunk stored a copy |
| **Local** | Sequence and event contract for this process | Downstream HEC/index health |
| **Export** | SDK emit+flush attempted (`export.json`) | Collector, HEC, or index success. `splunk.verified` stays false until a search ran |
| **Splunk indexed** | A complete or partial copy arrived (`dc(_raw)` vs local count) | That the handler never ran, if the copy is incomplete |
| **Search** | How that copy answers Q-MCP-* / Q-MCP-RESOURCE-AUTHZ | Authorization. Splunk does not ALLOW or DENY |
| **Detection** | No indexed DENY then later `mcp.started` for that window | The handler never ran. Fail-open ALLOW is not this detector. The system is not proven secure |

## Phase 5C completeness (MEASURED)

- BASELINE `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` — 7=7, handler=1
- ATTACK `5ab59fc7-303e-4eea-84e7-ae0b2f405146` — 7=7, handler=1
- RETEST `0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd` — 6=6, handler=0
- UNKNOWN `0e4e0051-528d-4bf3-8773-d1fb55a5864f` — 6=6, handler=0
- MALFORMED `9ea63448-bf6a-4619-b313-b152f4d94bb6` — 6=6, handler=0, no `resource.id`
- DUPLICATE KEYS `ffafb62e-a6c6-42c0-837d-094cbfb3f795` — 2=2, handler=0, **no** control.decision

## SIMULATED fixture

`searches/DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl` uses `| makeresults`. Index leak check for `simulated-det-mcp-001-resource-0001` was **0**. Evidence class **SIMULATED**. It must not appear in a PROVE block as runtime behavior.

## Duplicate-key evidence layer

HTTP-boundary rejection (`duplicate_json_keys`) is a schema/parse failure **before** CTRL-MCP-001. Phase 5C emitted `run.failed` only. Do not claim a DENY, ERROR resource hunt, or AllowTicket for that copy.
