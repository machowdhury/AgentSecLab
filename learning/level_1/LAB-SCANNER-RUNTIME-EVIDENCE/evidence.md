# Evidence hierarchy

Do not collapse planes. Do not treat empty Splunk tables as security outcomes.

## PLANE 1 — Artifact evidence

**Source:** Cisco mcp-scanner static YARA via the Cisco external-evidence adapter, sourcetype `agentsec:scanner:finding`  
**Producer class:** OBSERVED_SCANNER (Phase 9B packs; Phase 9C ingest MEASURED)  
**Contract class:** finding (external evidence 1.0.0; not an authorization result)

Questions: What artifact was scanned? Did the scan execute? Were findings produced? What was the native severity? What description SHA-256 was scanned? How is this correlated (`hash_join`)? Did the scanner authorize anything (no)?

NORMAL `b3061c4e-7a81-445c-8fd8-3108dd14c419`: scan executed, finding_count=0.  
MALICIOUS `7ae3ea64-4e7a-40fe-943f-3e582bce5ee8`: scan executed, finding_count=1, native HIGH, PROMPT INJECTION.

Native HIGH is scanner-native severity, not incident HIGH.

## PLANE 2 — Runtime trust / request

**Source:** CTRL-MCP-METADATA-001 + catalog telemetry, sourcetype `otel:agentic:json`  
**Class:** OBSERVED_RUNTIME (Phase 8D)

Questions: Did the runtime observe the same metadata? What description hash was observed? Was it `untrusted_data`? Did it influence a follow-on request?

METADATA-001 stays OBSERVE. OBSERVE is classification, not authorization.

NORMAL hash `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`  
MALICIOUS hash `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`

Correlation key: `artifact.description_sha256` ↔ `agentsec.content.hash`.  
`artifact.sha256` hashes the exported catalog file. It is not the runtime join key.

## PLANE 3 — Authorization / execution

**Source:** CTRL-MCP-001 + MCP execution telemetry  
**Class:** OBSERVED_RUNTIME (Phase 8D)

Questions: ALLOW or DENY? Why? Did mcp.started occur? Did the handler complete or fail?

ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4`: ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`, handler 1.  
RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`: DENY `tool_not_granted`, handler 0.

Runtime handler count is authoritative non-execution proof. Missing Splunk mcp.started is corroboration on a complete copy.

## Provenance vs trust vs grant

- Provenance: where the bytes came from (`mcp.catalog.snapshot`).
- Trust: how they are classified (`untrusted_data`).
- Grant: whether CTRL-MCP-001 ALLOW or DENY the requested tool.

## Empty tables

"No indexed finding row was returned for this scan."  
"No indexed follow-on execution event was found for this run."  
"No matching runtime event was found for this description hash."

Empty is not SAFE, blocked, prevented, trusted, or scanner PASS.

## What this evidence is not

Scanner HIGH != exploit. Scanner finding != execution. ZERO FINDINGS != SAFE. SIMULATED != LIVE. Splunk != enforcement.
