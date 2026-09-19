# Evidence — LAB-MEMORY-001

Splunk does not manufacture runtime truth.

```text
RUNTIME  →  LOCAL EVIDENCE  →  OTLP  →  SPLUNK  →  HUNT  →  SECURITY EVIDENCE
```

## Runtime

Phase 11B packs. Handler counts are **authoritative** for execution / non-execution. Phase 11C LIVE IDs are the Splunk-validated specimens used in this workshop.

| Specimen | Write run.id | Recall run.id | Follow-on handler |
|----------|--------------|---------------|-------------------|
| BASELINE | `a8407246-7992-4ad8-bd02-cb701e150f30` | `914c41ce-5123-49eb-892c-c948295dbc46` | 0 |
| ATTACK | `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` | `b8737cd9-9b6b-48f2-acfa-178ae1446ddc` | 1 |
| RETEST | `060a0a72-ceb5-4b99-8330-98de81d8ae5e` | `5d5b9d1b-092d-4ddb-8422-4092d289cd49` | 0 |

ATTACK and RETEST share memory.id `mem.lending-preference.malicious` and hash `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9`.

Do not substitute Phase 11B local IDs.

## Local

`artifacts/<run-id>/` when present. Schema `agentsec.security_event` **1.7.0**.

## Export

`export.json`. `otlp.ok` is not Splunk success. Packs keep `splunk.verified=false` until a named Splunk phase measures completeness.

## Splunk

Phase 11C LIVE transport COMPLETE. Index `agentsec_telemetry`. Sourcetype `otel:agentic:json`. Completeness = local count vs `dc(_raw)`.

Missing `mcp.started` on a COMPLETE copy is **corroboration**. It is not independent prevention proof.

## Search

Primary hunt: `Q-MEMORY-CONTEXT-AUTHORITY` (write + recall tokens).

Reuse: `Q-MCP-WHO`, `Q-MCP-AUTHZ`, `Q-MCP-TOOL`, `Q-MCP-EXECUTED`, `Q-MCP-AFTER-DENY` on the **recall** run.

Zero rows = no indexed event matched that evidence question. Not SAFE. Not DENY. Not blocked.

## Detection

**DETECTION ANALYZED — NO NEW MEMORY DETECTOR.**

DET-MCP-001 unchanged. LIVE A/B/C recall runs: 0 / 0 / 0. Silence is correct. Silence is not SAFE. No DET-MEMORY.

`allowed_tools` is not indexed. That gap blocks a defensible “unauthorized execution after untrusted recall” notable.
