# LAB-MCP-006 evidence

Prevention and reconstruction use a **hierarchy**. A later layer cannot overrule an earlier one.

```text
1. Runtime          did each handler run? (handler_invoke_count)
2. Local pack       artifacts/<run-id>/events.jsonl
3. Export           export.json (lossy; otlp.ok ≠ Splunk)
4. Splunk indexed   corroborating copy of what arrived
5. Search           analytical interpretation (Q-MCP-* + Q-MCP-DELEGATION)
6. Detection        DET-MCP-001: no indexed DENY→mcp.started found
                    DETECTION ANALYZED — NO NEW DETECTOR
```

Do not skip to Splunk and declare the lab proven.

Runtime handler count is authoritative proof of non-execution.

Splunk corroborates. Correct wording: “no indexed MCP execution event observed.” Incorrect: “Splunk proves the handler never ran.”

Q-MCP-DELEGATION is investigation context for caller/deputy, `authority.source`, CTRL-DELEGATION-001, downstream MCP, and execution observation.

DET-MCP-001 proves only that no indexed DENY→execution invariant violation was found.

0 detector hits is not: system is secure. 0 detector hits is not: MCP-006 was caught.

## What each layer proves

| Layer | What it can prove | What it cannot prove |
|-------|-------------------|----------------------|
| **Runtime** | Handler began or did not (`invoke_counts`) | Whether Splunk stored a copy |
| **Local** | Sequence and event contract for this process | Downstream HEC/index health |
| **Export** | SDK emit+flush attempted (`export.json`) | Collector, HEC, or index success. `splunk.verified` stays false until a search ran |
| **Splunk indexed** | A complete or partial copy arrived (`dc(_raw)` vs local count) | That the handler never ran, if the copy is incomplete |
| **Search** | How that copy answers Q-MCP-* / Q-MCP-DELEGATION | Authorization. Splunk does not ALLOW or DENY |
| **Detection** | No indexed DENY then later `mcp.started` for that window | The handler never ran. Vulnerable ALLOW is not this detector. The system is not proven secure |

## Phase 7C completeness (MEASURED)

- BASELINE `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2` — 10=10, policy handler=1, tier=0
- ATTACK `d7524a4e-8da6-4171-8867-d2a2168128ac` — 10=10, policy handler=0, tier=1
- RETEST `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4` — 6=6, policy handler=0, tier=0

ATTACK/RETEST request hash: `sha256:ea33191fceeb105e47270f6839bb98addfb7245a32534138192b23e1fab9a419`

Indexed `authority.source` is what the control consulted. It is not a dump of Compliance’s ambient grant list.

## Evidence classes

LIVE MCP-006 A/B/C runs: **OBSERVED** / **MEASURED**.  
DET-MCP-001 positive control: **SIMULATED**. Never mix LIVE and SIMULATED without labels.

## SIMULATED fixture

`../LAB-MCP-001/searches/DET-MCP-001-POSITIVE-CONTROL.spl` uses `| makeresults`. Evidence class **SIMULATED**. It must not appear in a PROVE block as runtime behavior. It is not a LIVE MCP-006 attack.

## Known limitations (must stay visible)

- no indexed `allowed_tools` — SERVER AUTHORITY EVIDENCE — LIMITED
- RETEST deputy not first-class on hop 1 (`deputy_not_on_indexed_hop1`)
- 200-character bounded preview (not used as grant proof)
- no `gen_ai.tool.call.id`
- Q-MCP-EXECUTED may show two control rows for one tool
- Splunk absence of `mcp.started` is corroborating evidence only
- runtime handler count is authoritative for controlled non-execution proof
- no new MCP-006 detector
- unsupported candidate SPL `Q-MCP-AMBIENT-USE` was rejected
- Q-MCP-WHO does not label caller vs deputy; RETEST has one WHO row (caller only)
