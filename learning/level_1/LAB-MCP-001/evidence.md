# LAB-MCP-001 evidence

Prevention and reconstruction use a **hierarchy**. A later layer cannot overrule an earlier one.

```text
1. Runtime          did the handler run? (handler_invoke_count)
2. Local pack       artifacts/<run-id>/events.jsonl
3. OTLP export      export.json (lossy; otlp.ok ≠ Splunk)
4. Splunk indexed   corroborating copy of what arrived
5. SPL query        analytical interpretation of that copy
```

Do not skip to Splunk and declare the lab proven.

Runtime handler count is authoritative proof of non-execution.

## What each layer proves

| Layer | What it can prove | What it cannot prove |
|-------|-------------------|----------------------|
| **Runtime** | Handler began or did not (`invoke_counts`) | Whether Splunk stored a copy |
| **Local** | Sequence and event contract for this process | Downstream HEC/index health |
| **OTLP export** | SDK emit+flush attempted (`export.json`) | Collector, HEC, or index success. `splunk.verified` stays false until a search ran |
| **Splunk indexed** | A complete or partial copy arrived (`dc(_raw)` vs local count) | That the handler never ran, if the copy is incomplete |
| **SPL query result** | How that copy answers Q-MCP-* | Authorization. Splunk does not ALLOW or DENY |

## Phase 3C completeness (MEASURED)

- BASELINE `163d11e2-e751-4282-9406-19b490542ed4` — 7=7, handler=1
- ATTACK `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` — 7=7, handler=1
- RETEST `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` — 6=6, handler=0

## SIMULATED fixture

`searches/Q-MCP-AFTER-DENY-POSITIVE-CONTROL.spl` uses `| makeresults`. Index leak check for `simulated-q-mcp-after-deny-0001` was **0**. Evidence class **SIMULATED**. It must not appear in a PROVE block as runtime behavior.
