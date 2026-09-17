# Why a scanner finding is not a detection

Phase 9D asked whether Splunk should grow a new detector now that Cisco mcp-scanner evidence is indexed. The short answer is **no**.

## What is it?

Detection engineering analysis: name the SOC question, name the evidence planes, and refuse to publish a notable that would fire because YARA said HIGH or because the lab overlay used a distinctive reason string.

## Why does it exist?

SOCs are used to “scanner HIGH → ticket.” In agentic systems that shortcut hides the difference between a poisoned **description**, an agent **asking** for another tool, a control **denying**, and a handler **starting**. AgentSec already has those as separate events. A detector that OR-joins them would unteach the lab.

## How does it work?

Three planes:

1. Artifact (scanner sourcetype)
2. Trust/request (METADATA-001 + follow-on request)
3. Authorization/execution (CTRL-MCP-001 + mcp.started)

LIVE 9C: ATTACK and RETEST share Plane 1 and Plane 2. Only Plane 3 differs.

## Where does it sit in AgentSec?

After 9C hunts, before any ES notable. DET-MCP-001 stays the only packaged detector, and only for execution-after-DENY.

## What is the trust boundary?

Scanner output is untrusted **evidence**. Coded policy is the grant. Splunk is investigation.

## What could an attacker control?

Catalog `description` text. Scanner rule quality. Timing: scan at T1, catalog at T2 (rug-pull — not solved here).

## What can go wrong?

Treating native HIGH as incident severity. Detecting the string `vulnerable_profile_fail_open:metadata_derived_authority` in production. Joining on the wrong hash. Calling RETEST “clean” because DET-MCP-001 returned 0 rows.

## What telemetry should exist?

Already indexed: scanner findings, metadata hash, control decisions, mcp.started. **Not** indexed: `allowed_tools` grant snapshot, `gen_ai.tool.call.id`, list_changed pin. That gap blocks a defensible “unauthorized execution + scanner” detector.

## How will Splunk show it?

Use existing hunts. Do not add DET-SCANNER.

## What control could change the result?

Defended CTRL-MCP-001 DENY (RETEST). The scanner finding stays HIGH either way.

## What test proves the logic?

Logic is DOCUMENTED from 8D/9C LIVE contracts. Pytest only preserves “no new detector files.” Pytest does not prove detection effectiveness.

## What I should now be able to explain

1. Why ATTACK and RETEST share a scanner finding.
2. Why DET-MCP-001 is silent on catalog ATTACK, correctly.
3. Why zero findings is not “safe.”
4. Why native HIGH is not SOC HIGH.
5. Why the lab overlay reason is a teaching signal, not a production predicate.
6. Why description SHA-256 is a lab join and a production weakness.
7. What TELEMETRY GAP — QUERY NOT DEFENSIBLE means here.
8. How a later tool (Snyk, AI-BOM, Foundation-Sec) should enter the adapter pipeline without becoming authorization.
9. Why rug-pull is a T1 vs T2 integrity problem, not a 9D detector.
10. When a hunt is allowed to become a detector (the full gate — unmet).
