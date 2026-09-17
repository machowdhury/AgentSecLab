# Scanner evidence vs runtime evidence in Splunk

Phase 9C ingested the real Phase 9B Cisco mcp-scanner packs into Splunk as an **independent** evidence source, then correlated them with LAB-MCP-CATALOG runtime events.

## What is it?

A second sourcetype. Runtime still speaks `otel:agentic:json` (schema 1.5.0). Scanner speaks `agentsec:scanner:finding`. Splunk can put both in the same index without mixing their meanings.

## Why does it exist?

SOCs already collect vendor scanner output. The teaching risk is treating a YARA hit as an authorization decision, or treating a clean scan as a grant. AgentSec keeps those dimensions separate on purpose.

## How does it work?

1. Phase 9B writes an evidence pack (manifest + findings + raw stdout file).
2. Phase 9C copies a **normalized** subset to HEC: scan summary always, finding events only when findings exist.
3. Splunk extracts JSON fields. Raw stdout stays on disk, linked by SHA-256.
4. Correlation uses **description** SHA-256, the same bytes as `agentsec.content.hash`, not the whole `tools.json` file hash.

## Where does it sit in AgentSec?

Downstream of the MCP runtime. CTRL-MCP-001 and CTRL-MCP-METADATA-001 do not read scanner fields. Splunk does not call `coded_policy()`.

## What is the trust boundary?

Scanner process / adapter / HEC vs MCP authorization. A finding is a claim about an artifact. An ALLOW/DENY is a claim about a request.

## What could an attacker control?

Catalog `description` text (already the 8D story). Scanner rule quality. Transport loss. A missing scan event looks like silence, which is not safety.

## What can go wrong?

- Equating `tools.json` SHA-256 with description hash (MEASURED: 0 correlation rows).
- Collapsing zero findings into PASS.
- Mapping native `HIGH` to DENY.
- Putting scanner JSON on `otel:agentic:json`.

## What telemetry should exist?

Scan identity, scanner pin, artifact hashes, finding_count, native rule/severity when present, raw-output SHA-256. Not full descriptions. Not argv.

## How will Splunk show it?

`Q-SCANNER-WHO` / `ARTIFACT` / `FINDINGS` for the scanner side. `Q-SCANNER-RUNTIME-CORRELATION` for the hash. `Q-MCP-AUTHZ` and `Q-MCP-CATALOG-AUTHORITY` for ATTACK vs RETEST.

## What control could change the result?

Runtime overlay / coded policy on RETEST DENY. The scanner result for the same malicious description stayed `DETECTED_BY_SCANNER` either way.

## What test proves the logic?

LIVE: NORMAL `scan_executed_zero_findings`; MALICIOUS native HIGH; description-hash correlation to BASELINE vs ATTACK+RETEST; file-hash correlation empty; `dc(_raw)` completeness 3/3.

## What I should now be able to explain

1. Why a successful scan with zero findings still needs a Splunk event.
2. Why `SCANNER FINDING != AUTHORIZATION DECISION`.
3. Why `artifact.sha256` and `artifact.description_sha256` are different.
4. How ATTACK ALLOW and RETEST DENY can share one malicious description hash.
5. Why native `HIGH` was not mapped to AgentSec severity.
6. Why scanner events are not schema 1.5.0.
7. How `dc(_raw)` differs from `stats count`.
8. Why CIM was recorded NOT APPLICABLE.
9. What 0 rows on `Q-SCANNER-WHO` means — and what it does not mean.
10. Why Phase 9C published no detector and no Dashboard Studio view.
