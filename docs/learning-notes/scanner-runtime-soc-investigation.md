# Scanner + runtime SOC investigation

## WHAT IS IT?

A learner-facing Splunk workshop that teaches how to investigate an external scanner finding next to AgentSec runtime evidence. The view is `ws_lab_scanner_runtime_evidence`. It is not a new attack lab and not a new detector.

## WHY DOES IT EXIST?

After Phase 9C, Splunk can show Cisco mcp-scanner findings. After Phase 9D, AgentSec decided not to create DET-SCANNER. Analysts still need a place to practice combining those evidence types without treating scanner HIGH as an incident or as an authorization decision.

## HOW DOES IT WORK?

Three planes stay separate:

1. Artifact evidence from sourcetype `agentsec:scanner:finding`
2. Runtime metadata observation from CTRL-MCP-METADATA-001
3. Authorization and execution from CTRL-MCP-001 and mcp.* events

The join key is description SHA-256 (`artifact.description_sha256` / `agentsec.content.hash`). The exported file hash is not the join key.

## WHERE DOES IT SIT IN AGENTSEC?

After LAB-MCP-CATALOG (runtime poisoning lesson) and after scanner ingest (9C) and detection analysis (9D). Splunk remains the investigation workbench. It does not enforce.

## WHAT IS THE TRUST BOUNDARY?

Catalog metadata is untrusted data. Scanner findings are untrusted investigative context. CTRL-MCP-001 is the grant boundary. Scanner output does not feed that control.

## WHAT COULD AN ATTACKER CONTROL?

Tool description bytes in a catalog snapshot. Not the coded grant list, not Splunk, and not the scanner's authorization (the scanner has none).

## WHAT CAN GO WRONG?

Collapsing planes: treating ZERO FINDINGS as SAFE, native HIGH as incident HIGH, OBSERVE as ALLOW, ALLOW as execution, missing Splunk rows as blocked, or DET-MCP-001 silence as safe.

## WHAT TELEMETRY SHOULD EXIST?

Scanner scan-summary and finding events. METADATA-001 OBSERVE with content hash. CTRL-MCP-001 ALLOW/DENY with reason. mcp.started / completed / failed. Runtime handler counts for non-execution.

## HOW WILL SPLUNK SHOW IT?

Ten tabs LEARN→PROVE. Q-SCANNER-* for plane 1. Q-MCP-CATALOG-AUTHORITY and Q-MCP-AUTHZ for planes 2–3. Q-MCP-AFTER-DENY teaches DET-MCP-001 silence. SIMULATED positive control is labeled SIMULATED.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-MCP-001. ATTACK and RETEST have the same scanner finding; only the authorization profile changes.

## WHAT TEST PROVES THE LOGIC?

Phase 8D runtime copies (ATTACK handler 1, RETEST handler 0). Phase 9C scanner ingest. Dashboard contract tests. Playwright tab/token capture. Not pytest-as-Splunk-rendering.

SCANNER FINDING != AUTHORIZATION DECISION. ZERO FINDINGS != SAFE. DETECTION ANALYZED — NO NEW DETECTOR. No DET-SCANNER. No DET-MCP-CATALOG. No Agent Scan. No rug-pull. No A2A.

## What I should now be able to explain

1. What each of the three evidence planes can and cannot prove.
2. Why zero findings is not a safety proof.
3. Why description SHA-256 is the correlation key and artifact.sha256 is not.
4. Why ATTACK executes and RETEST does not, given the same scanner HIGH.
5. Why DET-MCP-001 is silent on both ATTACK and RETEST and is still correct.
6. Why native HIGH must not auto-promote to incident HIGH.
7. What INV-002 forbids when metadata looks authoritative.
8. Why Splunk absence of mcp.started is corroboration, not independent non-execution proof.
9. What a SOC would still need before creating a production detector.
10. Why this workshop must not overload `ws_lab_mcp_catalog`.
