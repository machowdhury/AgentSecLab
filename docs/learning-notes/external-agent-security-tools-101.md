# External agent-security tools 101

**Status:** Phase 9A learning note. Design/research only. No scanner was run.  
**Parents:** `docs/EXTERNAL_AGENT_SECURITY_TOOL_LANDSCAPE.md`, `docs/SCANNER_INTEGRATION_ARCHITECTURE.md`, `docs/PHASE9A_SCANNER_RESEARCH.md`.

---

## WHAT IS IT?

A way to **import** findings from external MCP/agent scanners as a separate evidence stream — without letting those tools authorize AcmeBank.

## WHY DOES IT EXIST?

LAB-MCP-CATALOG already shows that tool **descriptions are data** (INV-002). Industry scanners (Cisco mcp-scanner, Snyk Agent Scan / Invariant lineage) flag poisoned descriptions. The next mistake is to treat a YARA hit as DENY, or a clean scan as trusted. AgentSec exists to keep those two questions apart: *what did a scanner say?* vs *what did the runtime do?*

## HOW DOES IT WORK?

Future path only:

1. Export a catalog JSON snapshot (same bytes the lab uses).
2. Run a **sandboxed** scanner (first: Cisco mcp-scanner YARA static).
3. Store raw output + SHA-256 + provenance in an evidence pack.
4. Runtime still runs BASELINE / ATTACK / RETEST **without reading** the pack.
5. Splunk later compares hashes (separate sourcetype), after field discovery.

Phase 9A stops at design. Core lab still runs with **zero** scanner binaries.

## WHERE DOES IT SIT IN AGENTSEC?

Beside the runtime, not inside CTRL-MCP-001 or CTRL-MCP-METADATA-001. Schema stays **1.5.0**. Scanner fields are **not** added to `otel:agentic:json`.

## WHAT IS THE TRUST BOUNDARY?

```text
SCANNER FINDING ≠ AUTHORIZATION DECISION
```

Scanner PASS ≠ trusted. Scanner FAIL ≠ DENY. Scanner silence ≠ safe.

## WHAT COULD AN ATTACKER CONTROL?

- Malicious MCP stdio if a dynamic scanner is pointed at an untrusted server
- Scanner JSON/SARIF body (prompt injection into a later LLM assist)
- Dependencies of the scanner itself
- Timing: scan file A, execute file B (TOCTOU)

## WHAT CAN GO WRONG?

- Wiring HIGH → DENY (DefenseClaw does this for OpenClaw; AgentSec must not)
- Running `--dangerously-run-mcp-servers` in the core lab
- Mixing findings into `mcp.started` events
- Inventing Splunk fields before ingest
- Claiming uniqueness for “we scan MCP too”
- Using archived llm-guard or Azure/PyRIT stub as the integration target

## WHAT TELEMETRY SHOULD EXIST?

Today: runtime METADATA-001 + `agentsec.content.hash`.  
Later: `OBSERVED_SCANNER` files; optional sourcetype `agentsec:scanner:finding` in the same index. Not implemented.

## HOW WILL SPLUNK SHOW IT?

Not in 9A. Future hunts only after QUESTION → EVIDENCE → indexed field discovery → field contract → `/splunk-ko-review`. Do not force CIM.

## WHAT CONTROL COULD CHANGE THE RESULT?

Only AgentSec CTRL-* change execution. A scanner cannot. RETEST DENY is still `tool_not_granted`, not “scanner blocked it.”

## WHAT TEST PROVES THE LOGIC?

Phase 9A: documents + contract tests that runtime/schema/SPL did not change.  
Phase 9B (later): adapter tests; runtime does not read findings; optional **executed** scanner producing JSON — not started.

---

## What I should now be able to explain

1. Why a scanner finding is not an authorization decision.
2. Why Cisco mcp-scanner static YARA is the first integration target (and why “Cisco” alone is not the reason).
3. Why Snyk Agent Scan is second, not first.
4. What Invariant mcp-scan is today (`snyk/agent-scan` redirect).
5. Why DefenseClaw must not become the bank.
6. What SHA-256 proves and what it does not prove.
7. Why schema 1.5.0 should not grow scanner fields automatically.
8. Why same index + new sourcetype is preferred over a new index (for now).
9. An example where the scanner flags poison but RETEST never executes.
10. An example where the scanner is silent but ATTACK still violates INV-002.
