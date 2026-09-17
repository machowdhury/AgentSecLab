# Scanner vs runtime evidence

**Status:** Phase 9B learning note. Live Cisco mcp-scanner static YARA was executed.  
**Parents:** `docs/PHASE9B_CISCO_MCP_SCANNER_VALIDATION.md`, `docs/CISCO_MCP_SCANNER_INTEGRATION.md`.

---

## WHAT IS IT?

Two independent evidence streams about the same catalog description: an external scanner finding, and AgentSec runtime control/execution telemetry.

## WHY DOES IT EXIST?

A SOC learner will be offered scanner dashboards that look like “blocked.” AgentSec’s job is to keep that from collapsing into authorization.

## HOW DOES IT WORK?

Export the catalog the lab actually uses. Hash the file and the description separately. Scan the file with YARA-only mcp-scanner. Runtime still runs BASELINE/ATTACK/RETEST without reading the pack.

## WHERE DOES IT SIT IN AGENTSEC?

`src/agentsec/scanners/` and `docs/phase9b-evidence/`. Not in `authorize.py`. Schema stays 1.5.0.

## WHAT IS THE TRUST BOUNDARY?

```text
SCANNER FINDING != AUTHORIZATION DECISION
```

## WHAT COULD AN ATTACKER CONTROL?

Catalog descriptions (already taught). Scanner JSON body (untrusted). A default `server_url` string in scanner output (do not treat as connection proof).

## WHAT CAN GO WRONG?

- Calling DETECTED_BY_SCANNER a DENY
- Equating artifact SHA-256 with description SHA-256
- Mixing findings into `mcp.started`
- Assuming YARA silence means INV-002 held

## WHAT TELEMETRY SHOULD EXIST?

Today: file packs classified OBSERVED_SCANNER. Runtime events unchanged. Splunk ingest is 9C.

## HOW WILL SPLUNK SHOW IT?

Not in 9B. Future join on `description_sha256` = `agentsec.content.hash` after field discovery.

## WHAT CONTROL COULD CHANGE THE RESULT?

Only CTRL-MCP-001 / profile overlay. The scanner cannot.

## WHAT TEST PROVES THE LOGIC?

Live scans: NORMAL 0 findings; MALICIOUS DETECTED_BY_SCANNER HIGH PROMPT INJECTION. Isolation tests: MCP modules do not import scanners. 8D ATTACK still executed follow-on; RETEST still DENY `tool_not_granted` — cited, not re-run.

---

## What I should now be able to explain

1. Why scanner FAIL is not AgentSec DENY.
2. Why this lab’s YARA hit still coexists with ATTACK execution.
3. Why RETEST DENY is `tool_not_granted`, not “scanner blocked it.”
4. Why `artifact.sha256` ≠ `description_sha256`.
5. Why `scan_id` is not `agentsec.run.id`.
6. Why a `server_url` in scanner JSON is not proof of a live MCP connect.
7. Why YARA-only needs no API key.
8. What Phase 9C still has to prove before SPL.
9. Why we did not rewrite the MALICIOUS fixture to force a finding (and that it fired anyway).
10. What AgentSec built (adapter/provenance) vs what Cisco built (YARA engines).
