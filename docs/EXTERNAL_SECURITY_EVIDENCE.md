# External security evidence layer

**Status:** IMPLEMENTED for Cisco mcp-scanner static findings and garak adversarial evaluations.
**Runtime schema:** 1.9.0 — unchanged.  
**External contract:** 1.0.0 — independent.  
**Sourcetypes:** `agentsec:scanner:finding` and `agentsec:external:evaluation`.

This is not a second PDP. External findings do not enter CTRL-MCP-001.

## Architecture

```text
AGENTSEC RUNTIME
      │
      ├──────────────► Runtime telemetry  (otel:agentic:json, schema 1.9.0)
      │
      ▼
CTRL-MCP-001
      │
      ▼
EXECUTION / OUTCOME


INDEPENDENT SECURITY TOOLS
      │
      ▼
EXTERNAL EVIDENCE ADAPTER
      │
      ▼
NORMALIZED EXTERNAL EVIDENCE
      │
      ▼
EVIDENCE PACK → HEC → SPLUNK
      │
      ▼
CORRELATION / INVESTIGATION
```

Splunk is not the PDP. Indexed detections are not the PDP.

## Plugin boundary

A future adapter should:

1. Read external output
2. Normalize onto `ExternalEvidence`
3. Preserve raw evidence (`raw_evidence_ref`, `raw_evidence_sha256`)
4. Record provenance when known
5. Record correlation data when known
6. Emit a pack / HEC payload

It must not import CTRL-MCP-001, Attack Service internals, Academy internals, or runtime authorization.

Cisco implementation: `src/agentsec/external_evidence/cisco.py` maps `NormalizedScan` → `ExternalEvidence`. Native Cisco fields stay under `native`.

garak implementation: `src/agentsec/external_evidence/garak.py` reads native
garak JSONL `eval` rows and emits class `evaluation`. It preserves model, probe,
detector, counts, intents, and upstream tags under `native`.

## Evidence classes

The contract can represent `finding`, `evaluation`, `inventory`, `assessment`.

P0 Cisco mcp-scanner records use **`finding`**. Zero findings is still class `finding` with `finding_count=0`. That is not SAFE.

P1A garak records use **`evaluation`**. A PASS is not SAFE, and a FAIL is not
confirmed exploitation. No inventory or assessment adapters exist.

Honesty producer label `OBSERVED_SCANNER` remains on pack/HEC `evidence_class` for compatibility with Q-SCANNER-WHO. Nested `external.evidence_class` is the contract class.

## Semantics

```text
FINDING != AUTHORIZATION
EVALUATION != AUTHORIZATION
INVENTORY != TRUST
SCANNER HIGH != DENY
SCANNER LOW != ALLOW
ZERO FINDINGS != SAFE
PASSING EVALUATION != SAFE
EXTERNAL TOOL != PDP
SPLUNK != PDP
```

Cisco hash join:

```text
correlation.method = hash_join
correlation.key = description_sha256/content.hash
```

HASH MATCH = the compared canonical content matched. It does **not** automatically prove same process, runtime, request, execution, security decision, or causality.

garak uses a different, truthful relationship:

```text
correlation.method = identity_tuple
correlation.key = garak.run/probe/detector/model
```

It links the normalized record to its native evaluation context, not to an
AgentSec runtime request. Different evidence sources require different
correlation strategies.

Do not attach `agentsec.run.id` to scanner events unless the scanner produced or inherited that id. Canonical packs set it null and omit it from HEC.

## Provenance

When present: provider, tool, tool version, scan time (`source_timestamp` from pack `created_at`), subject, artifact fingerprint (`description_sha256`, algorithm sha256), native finding id, raw evidence reference `raw/scanner-output.json`, raw SHA-256, correlation method.

Unknown values are omitted. Committed packs use pack-relative `input/tools.json` and CLI names, not host-absolute paths.

## Classification of this checkpoint

| Claim | Class |
|-------|--------|
| Adapter mapping and unit tests | TESTED |
| Canonical pack raw SHA-256 vs file | TESTED |
| MCP modules do not import ExternalEvidence | TESTED (AST) |
| Canonical Cisco and garak pack → HEC → indexed searchable fields | E2E VERIFIED on 2026-09-24; see `docs/EXTERNAL_EVIDENCE_E2E_ACADEMY_VALIDATION.md` |
| Exact `Q-EXTERNAL-EVIDENCE-PLANES.spl` execution | E2E VERIFIED on 2026-09-24 |
| Live mcp-scanner CLI re-run during the E2E phase | NOT PROVEN; canonical pack events were used |
| Fresh garak/Ollama execution during the E2E phase | NOT PROVEN; canonical native report was used |
| AI-BOM / other vendors | NOT MODELED |

The Academy publishes `External Security Toolbox` as a REPLAY investigation.
Curriculum registration and a dashboard do not independently prove external
tool execution; they expose the E2E-validated indexed evidence and its limits.
