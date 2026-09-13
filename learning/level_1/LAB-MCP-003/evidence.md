# LAB-MCP-003 evidence

Prevention and reconstruction use a **hierarchy**. A later layer cannot overrule an earlier one.

```text
1. Runtime          did the handler run? (handler_invoke_count)
2. Local pack       artifacts/<run-id>/events.jsonl
3. Export           export.json (lossy; otlp.ok ≠ Splunk)
4. Splunk indexed   corroborating copy of what arrived
5. Search           analytical interpretation of that copy (Q-MCP-*)
6. Detection        DET-MCP-001: no indexed DENY→mcp.started found
```

Do not skip to Splunk and declare the lab proven.

Runtime handler count is authoritative proof of non-execution.

Splunk corroborates.

DET-MCP-001 proves only that no indexed DENY→execution invariant violation was found.

## What each layer proves

| Layer | What it can prove | What it cannot prove |
|-------|-------------------|----------------------|
| **Runtime** | Handler began or did not (`invoke_counts`) | Whether Splunk stored a copy |
| **Local** | Sequence and event contract for this process | Downstream HEC/index health |
| **Export** | SDK emit+flush attempted (`export.json`) | Collector, HEC, or index success. `splunk.verified` stays false until a search ran |
| **Splunk indexed** | A complete or partial copy arrived (`dc(_raw)` vs local count) | That the handler never ran, if the copy is incomplete |
| **Search** | How that copy answers Q-MCP-* | Authorization. Splunk does not ALLOW or DENY |
| **Detection** | No indexed DENY then later `mcp.started` for that window | The handler never ran. Fail-open ALLOW is not this detector |

## Phase 4C completeness (MEASURED)

- BASELINE `5b089682-1d5a-49a7-ac43-967265fd6bc6` — 7=7, handler=1
- ATTACK `b466ad12-72ec-44b7-be28-aacfaf2c25b1` — 7=7, handler=1
- RETEST `f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5` — 6=6, handler=0
- UNKNOWN `6ce19813-6cb5-4aae-a3a0-aa59386a82dd` — 6=6, handler=0

## SIMULATED fixture

`../LAB-MCP-001/searches/DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl` uses `| makeresults`. Index leak check for `simulated-det-mcp-001-scope-0001` was **0**. Evidence class **SIMULATED**. It must not appear in a PROVE block as runtime behavior.
