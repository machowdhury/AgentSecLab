# LAB-MCP-CATALOG evidence

Prevention and reconstruction use a **hierarchy**. A later layer cannot overrule an earlier one.

```text
1. Runtime          did each handler run? (handler_invoke_count)
2. Local pack       artifacts/<run-id>/events.jsonl
3. Export           export.json (lossy; otlp.ok ≠ Splunk)
4. Splunk indexed   corroborating copy of what arrived
5. Search           analytical interpretation (Q-MCP-* + Q-MCP-CATALOG-AUTHORITY)
6. Detection        DET-MCP-001: no indexed DENY→mcp.started found
                    DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN
                    No DET-MCP-CATALOG
```

Do not skip to Splunk and declare the lab proven.

Runtime handler count is authoritative proof of non-execution.

Splunk corroborates. Correct wording: “no indexed follow-on MCP execution event observed.” Incorrect: “Splunk proves it was blocked.”

Q-MCP-CATALOG-AUTHORITY is investigation context for metadata classification, description hash, first grant, follow-on decision, and execution observation.

DET-MCP-001 proves only that no indexed DENY→execution invariant violation was found.

0 detector hits is not: system is secure. 0 detector hits is not: catalog poisoning was caught.

## What each layer proves

| Layer | What it can prove | What it cannot prove |
|-------|-------------------|----------------------|
| **Runtime** | Handler began or did not (`invoke_counts`) | Whether Splunk stored a copy |
| **Local** | Sequence and event contract for this process | Downstream HEC/index health |
| **Export** | SDK emit+flush attempted (`export.json`) | Collector, HEC, or index success. `splunk.verified` stays false until a search ran |
| **Splunk indexed** | A complete or partial copy arrived (`dc(_raw)` vs local count) | That the handler never ran, if the copy is incomplete |
| **Search** | How that copy answers Q-MCP-* / Q-MCP-CATALOG-AUTHORITY | Authorization. Splunk does not ALLOW or DENY |
| **Detection** | No indexed DENY then later `mcp.started` for that window | The handler never ran. Vulnerable ALLOW is not this detector. The system is not proven secure |

## Phase 8D completeness (MEASURED)

- BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` — 8=8, policy handler=1, tier=0
- ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4` — 13=13, policy handler=1, tier=1
- RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` — 12=12, policy handler=1, tier=0

ATTACK/RETEST description hash: `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`

## Evidence classes

LIVE catalog A/B/C runs: **OBSERVED** / **MEASURED**.  
DET-MCP-001 positive control: **SIMULATED**. Never mix LIVE and SIMULATED without labels.

## SIMULATED fixture

`../LAB-MCP-001/searches/DET-MCP-001-POSITIVE-CONTROL.spl` uses `| makeresults`. Evidence class **SIMULATED**. It must not appear in a PROVE block as runtime behavior.

## Known limitations (must stay visible)

- no indexed `allowed_tools`
- no full advertised catalog list
- Q-MCP-EXECUTED extra OBSERVE row
- bounded preview (hash is the fingerprint)
- no `gen_ai.tool.call.id`
- scanners not ingested
- `splunk.verified` stays false on the evidence pack
