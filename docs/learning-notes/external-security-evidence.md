# External security evidence adapters

## WHAT IS IT?

A small vendor-neutral contract for security evidence produced **outside** the AgentSec runtime. Cisco mcp-scanner is the first adapter. The contract is not schema 1.9.0 and is not an authorization API.

## WHY DOES IT EXIST?

Runtime telemetry answers what the agent did and what CTRL-MCP-001 decided. Independent tools answer what they observed about an artifact. Mixing those into one event, or feeding scanner HIGH into DENY, hides the lesson.

## HOW DOES IT WORK?

```text
External Tool → Adapter → Normalized External Evidence → Pack → HEC → Splunk
```

The Cisco adapter copies native fields (rule id, severity, analyzer) into `native` and sets contract `evidence_class=finding`. Raw stdout stays in `raw/scanner-output.json` and is linked by SHA-256.

## WHERE DOES IT SIT IN AGENTSEC?

Beside the runtime, not inside it. Packs live under `docs/phase9b-evidence/`. HEC sourcetype remains `agentsec:scanner:finding`. Investigation is LAB-SCANNER-RUNTIME-EVIDENCE (REPLAY specimens).

## WHAT IS THE TRUST BOUNDARY?

Catalog bytes and scanner JSON are untrusted investigative context. CTRL-MCP-001 is the grant boundary.

## WHAT COULD AN ATTACKER CONTROL?

Tool description text (and therefore description SHA-256). Not the coded grant list. Not the PDP by inventing a scanner finding.

## WHAT CAN GO WRONG?

Treating FINDING as AUTHORIZATION, HIGH as DENY, zero findings as SAFE, or a hash match as proof of the same request.

## WHAT TELEMETRY SHOULD EXIST?

Scanner scan + finding events with `external.*` and `correlation.*`. Runtime `otel:agentic:json` with `agentsec.content.hash`. No scanner fields on schema 1.9.0.

## HOW WILL SPLUNK SHOW IT?

PLANE 1 = `agentsec:scanner:finding`. PLANES 2–3 = `otel:agentic:json`. Join on hashes. Do not merge scanner findings into native runtime events.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-MCP-001 only. Scanner HIGH is identical on ATTACK and RETEST; authorization is not.

## WHAT TEST PROVES THE LOGIC?

`tests/unit/test_external_evidence.py` and `tests/unit/test_scanner_isolation.py`. AST proof that `src/agentsec/mcp/` does not import `ExternalEvidence`. `authorize_tool` has no finding parameter.

## What I should now be able to explain

1. Why external evidence is a separate contract from schema 1.9.0.
2. Why Cisco output is class `finding` and not a control decision.
3. How raw evidence is linked without indexing paths.
4. What `hash_join` on `description_sha256`/`content.hash` does and does not prove.
5. Why SCANNER HIGH != DENY and ZERO FINDINGS != SAFE.
6. Why the adapter must not import CTRL-MCP-001.
7. Why producer `OBSERVED_SCANNER` and contract `finding` can both be true.
8. Why future evaluation/inventory adapters are capabilities, not existing integrations.
9. Why Splunk is not the PDP.
10. What would be an architectural violation (PDP consuming ExternalEvidence).
