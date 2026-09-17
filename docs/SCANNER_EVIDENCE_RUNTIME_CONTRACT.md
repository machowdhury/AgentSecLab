# Scanner evidence runtime contract

**Status:** Phase 9B IMPLEMENTED. Separate from `agentsec.security_event` **1.5.0**.  
**Evidence class:** `OBSERVED_SCANNER` (pack field, **not** a schema enum).

Parents: `docs/SCANNER_EVIDENCE_MODEL.md`, `docs/CISCO_MCP_SCANNER_INTEGRATION.md`.

---

## WHAT IS IT?

A file-backed evidence object for one static catalog scan. It is not a control decision and not a runtime event.

## WHY DOES IT EXIST?

So a learner can compare **what a scanner predicted** with **what AgentSec runtime did**, without mixing those bytes into `mcp.started` or CTRL-MCP-001.

## HOW DOES IT WORK?

1. Export catalog JSON from `build_catalog_snapshot`.
2. SHA-256 the exact file bytes.
3. Run pinned `mcp-scanner` static YARA.
4. Preserve stdout/stderr unmodified.
5. Normalize allow-listed fields only.
6. Write `manifest.json` + `limitations.json`.

Runtime invoke paths do not import `agentsec.scanners`.

## WHERE DOES IT SIT?

`src/agentsec/scanners/` beside the MCP runtime, not inside it. Splunk ingest is Phase **9C** (not started).

## TRUST BOUNDARY

Scanner output is untrusted data (INV-002). Finding text is never executed and never becomes a grant.

## AUTHORITY

| Authoritative | Not authoritative |
|---------------|-------------------|
| CTRL-MCP-001 / CTRL-MCP-METADATA-001 | Scanner severity |
| `coded_policy()` | `is_safe` in scanner JSON |
| Handler counts / `mcp.started` | Empty finding list |

## HASH SEMANTICS

| Field | Meaning |
|-------|---------|
| `artifact.sha256` | Equality of the exported JSON file |
| `description_sha256` | Equality of the `lookup_policy` description string |
| Hash match | Artifact equality only — not safety |

## CLASSIFICATION (MALICIOUS fixture only)

`DETECTED_BY_SCANNER` | `NOT_DETECTED_BY_SCANNER` | `SCANNER_ERROR` | `UNSUPPORTED`

Forbidden labels: BLOCKED, PREVENTED, SAFE, AUTHORIZED, DENIED.

NORMAL scans have `classification: null`. Finding count is still recorded.

## SCHEMA GAP (unchanged)

Do not add scanner fields to `otel:agentic:json` 1.5.0. Future indexed shape is a 9C proposal only.
