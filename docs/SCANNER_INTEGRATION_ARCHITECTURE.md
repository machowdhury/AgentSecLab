# Scanner integration architecture

**Status:** Phase 9A DESIGN. Phase **9B IMPLEMENTED** for Cisco mcp-scanner static YARA only. No Splunk ingest. No runtime authorization change.  
**Parents:** `docs/EXTERNAL_AGENT_SECURITY_TOOL_LANDSCAPE.md`, `docs/MCP_CATALOG_POISONING_SCANNER_INTEGRATION.md`, `docs/CISCO_MCP_SCANNER_INTEGRATION.md`.

---

## Locked principle

```text
SCANNER FINDING ≠ AUTHORIZATION DECISION
```

| Scanner may | Scanner must not become |
|-------------|-------------------------|
| discover | CTRL-MCP-001 |
| inspect | CTRL-MCP-METADATA-001 |
| classify | AllowTicket issuer |
| flag | IAM system |
| score | execution gate |
| fingerprint | proof execution occurred |
| report | proof execution did not occur |

Scanner PASS ≠ trusted. Scanner FAIL ≠ DENY. Scanner silence ≠ safe.

AgentSec **runtime** remains authoritative for execution and control behavior.  
**Splunk** remains evidence and investigation.

---

## Pipeline (9B implemented for Cisco static)

```text
AgentSec catalog export (build_catalog_snapshot)
      ↓
tools.json + SHA-256 of exact bytes
      ↓
Pinned mcp-scanner static --tools --analyzers yara
      ↓
Raw stdout JSON (preserved)
      ↓
AgentSec adapter (OBSERVED_SCANNER pack; no DENY)
      ↓
artifacts/scanners/<scan-id>/  (Splunk ingest is Phase 9C — not started)
```

Do **not** mix scanner findings into `mcp.started` or `control.decision` events.

**Phase 9B observation (does not rewrite 9A):** live `--format raw` JSON includes a default `server_url` even when argv is `static --tools` only. That field is scanner-native output, not AgentSec MCP connection evidence.

Schema 1.5.0 already forbids scanner fields on `otel:agentic:json` (`docs/SCHEMA_1_5_0.md`). Phases 9A and 9B do **not** bump schema.

---

## Adapter responsibilities (AgentSec BUILD)

The adapter is the differentiation layer. It does not re-implement YARA or LLM analysis.

1. Record scanner identity (name, version, repo, release, binary hash if available).
2. Record scan context (when, against which artifact, SHA-256 of input bytes).
3. Preserve **scanner-native** severity and confidence without silent remapping.
4. Attach the raw artifact path/hash.
5. Label evidence class `OBSERVED_SCANNER` (design name; not a schema enum in 9A).
6. Record whether LLM, network, or code execution were involved.
7. Record that AgentSec transformed the finding (adapter version).
8. **Never** call CTRL-MCP-001 or CTRL-MCP-METADATA-001.

Runtime continues: BASELINE / ATTACK / RETEST independently of whether a scan ran.

---

## Build vs integrate (this layer)

| Capability | Decision | Why |
|------------|----------|-----|
| YARA / LLM MCP catalog analysis | **INTEGRATE** Cisco mcp-scanner | Mature, static `--tools`, Apache-2.0, active |
| Agent/MCP live scan + TPA research lineage | **INTEGRATE** Snyk Agent Scan (second) | Successor of Invariant mcp-scan; higher exec risk |
| Evidence normalization / provenance | **BUILD** | Scanners do not emit AgentSec honesty labels |
| Correlation with runtime hashes | **BUILD** | Unique to the lab (catalog fingerprint ↔ METADATA-001) |
| FP/FN teaching (scan vs execute) | **BUILD** | Scanners do not know AgentSec controls |
| Splunk investigation of findings | **BUILD** | After field discovery; not invented SPL in 9A |
| Using scanner FAIL as DENY | **DROP** | Collapses the teaching property |
| DefenseClaw as AcmeBank | **DROP** | It is an admission gateway |
| Rebuilding mcp-scanner inside Python runtime | **DROP** | Unnecessary |

---

## First correlation target: LAB-MCP-CATALOG

Desired future story (Phase 9B+, not this phase):

1. Export the same catalog bytes the runtime used (NORMAL / MALICIOUS fixtures).
2. Scanner examines the **static** catalog artifact.
3. AgentSec records scanner evidence with SHA-256 of that artifact.
4. AgentSec runtime independently executes BASELINE / ATTACK / RETEST.
5. Splunk later correlates:
   - catalog fingerprint (`agentsec.content.hash` already on METADATA-001)
   - scanner finding (separate sourcetype)
   - metadata trust event
   - follow-on authorization
   - execution evidence (`mcp.started` or its absence)

Learner question: **What did the scanner predict?** versus **What actually happened at runtime?**

Canonical 8D LIVE hashes remain the correlation keys once a scanner runs:

| Run | Catalog | Description SHA-256 |
|-----|---------|---------------------|
| BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` | NORMAL | `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3` |
| ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4` | MALICIOUS | `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1` |
| RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` | same MALICIOUS | same hash |

Hash equality proves **artifact equality**, not security equivalence.

---

## False positive / false negative teaching model

These are educational outcomes, not product bugs.

| Case | Scanner | Runtime | Teaching point |
|------|---------|---------|----------------|
| FP-control | Flags malicious description | CTRL-MCP-001 DENY; handler never runs | Scanner predicted risk; runtime prevented execution |
| FN-metadata | Does not flag metadata | METADATA-001 still OBSERVE untrusted_data; overlay may ALLOW follow-on | Scanner silence ≠ safe catalog |
| PASS but invariant fail | Scanner PASS / empty | Runtime violates INV-002 (ATTACK fail-open) | Scanner PASS ≠ trusted |
| FAIL but no execution | Scanner FAIL | RETEST DENY; no `mcp.started` | Scanner FAIL ≠ proof of execution; also ≠ AgentSec DENY |
| Disagreement | Scanner A flags, scanner B does not | Runtime still authoritative | Cross-tool comparison is evidence, not a vote for DENY |

Do not “fix” these by wiring the scanner into authorization.

---

## Ingestion boundary

Phase 9B first slice should prefer **files in the evidence bundle** over OTel. Reasons:

- Schema 1.5.0 has no scanner fields and must not be bumped automatically.
- Mixing findings into `security_event` would collapse evidence classes.
- Splunk can ingest a **new sourcetype** later without touching runtime emitters.

If later ingestion is justified: HEC → same index `agentsec_telemetry` → sourcetype `agentsec:scanner:finding` (candidate name, not implemented). See `docs/SCANNER_SPLUNK_INTEGRATION_DESIGN.md`.

---

## Non-goals (this phase and automatic follow-ons)

- Scanner execution
- Runtime / CTRL-MCP-001 / CTRL-MCP-METADATA-001 changes
- Schema bump
- SPL, detections, Dashboard Studio
- Rug-pull / `tools/list_changed`
- A2A
- Phase 9B automatic start
