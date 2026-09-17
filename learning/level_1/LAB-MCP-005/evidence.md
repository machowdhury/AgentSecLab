# LAB-MCP-005 evidence

Prevention and reconstruction use a **hierarchy**. A later layer cannot overrule an earlier one.

```text
1. Runtime          did each handler run? (handler_invoke_count)
2. Local pack       artifacts/<run-id>/events.jsonl
3. Export           export.json (lossy; otlp.ok ≠ Splunk)
4. Splunk indexed   corroborating copy of what arrived
5. Search           analytical interpretation (Q-MCP-* + Q-MCP-RESULT-AUTHORITY)
6. Detection        DET-MCP-001: no indexed DENY→mcp.started found
                    DETECTION ANALYZED — NO NEW DETECTOR
```

Do not skip to Splunk and declare the lab proven.

Runtime handler count is authoritative proof of non-execution.

Splunk corroborates. Correct wording: “no indexed follow-on execution event observed.” Incorrect: “Splunk proves the follow-on handler never ran.”

Q-MCP-RESULT-AUTHORITY is investigation context for result-derived vs server-owned authority.

DET-MCP-001 proves only that no indexed DENY→execution invariant violation was found.

0 detector hits is not: system is secure. 0 detector hits is not: MCP-005 was caught.

## What each layer proves

| Layer | What it can prove | What it cannot prove |
|-------|-------------------|----------------------|
| **Runtime** | Handler began or did not (`invoke_counts`) | Whether Splunk stored a copy |
| **Local** | Sequence and event contract for this process | Downstream HEC/index health |
| **Export** | SDK emit+flush attempted (`export.json`) | Collector, HEC, or index success. `splunk.verified` stays false until a search ran |
| **Splunk indexed** | A complete or partial copy arrived (`dc(_raw)` vs local count) | That the handler never ran, if the copy is incomplete |
| **Search** | How that copy answers Q-MCP-* / Q-MCP-RESULT-AUTHORITY | Authorization. Splunk does not ALLOW or DENY |
| **Detection** | No indexed DENY then later `mcp.started` for that window | The handler never ran. Overlay ALLOW is not this detector. The system is not proven secure |

## Phase 6C completeness (MEASURED)

- BASELINE `3013aa39-fe08-4b58-9898-f3abb092ac06` — 8=8, policy handler=1, tier=0
- ATTACK `f3f48182-df57-4b38-b069-17a199dc4939` — 13=13, policy handler=1, tier=1
- RETEST `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` — 12=12, policy handler=1, tier=0
- INITIAL HANDLER FAIL `6fe7370c-a288-4634-91a5-d6c78b52bd01` — 8=8 (supporting; not a workshop default)

MALICIOUS hash (ATTACK = RETEST): `sha256:f7d67b151741ef7c7efb60242b96f8325996709128293da424f53a547230c358`  
NORMAL hash (BASELINE): `sha256:2c258a80464ede4113e7721119bc6a908951b8b723c61489ac27b737cdbeb68e`

Hash = content identity. Hash ≠ trust. Hash ≠ authority.

## Evidence classes

LIVE MCP-005 A/B/C runs: **OBSERVED** / **MEASURED**.  
DET-MCP-001 positive control: **SIMULATED**. Never mix LIVE and SIMULATED without labels.

## SIMULATED fixture

`../LAB-MCP-001/searches/DET-MCP-001-POSITIVE-CONTROL.spl` uses `| makeresults`. Evidence class **SIMULATED**. It must not appear in a PROVE block as runtime behavior. It is not a LIVE MCP-005 attack.

## Known limitations (must stay visible)

- no indexed `allowed_tools` — SERVER AUTHORITY EVIDENCE — LIMITED
- 200-character bounded preview (ATTACK hop-1 may show `lookup_customer_tie`)
- no `gen_ai.tool.call.id`
- Q-MCP-EXECUTED extra RESULT-001 rows
- Q-MCP-RESOURCE-AUTHZ extra RESULT-001 rows (that hunt is not bound on this dashboard)
- Splunk absence of `mcp.started` is corroborating evidence only
- runtime handler count is authoritative for controlled non-execution proof
- no new MCP-005 detector
- unsupported candidate SPL `Q-MCP-RESULT-FOLLOWON` was rejected
- same-tool repeated invocation correlation remains limited
