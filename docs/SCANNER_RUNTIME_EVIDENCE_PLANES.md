# Scanner vs runtime evidence planes

**Status:** Phase 9D DESIGN / ANALYSIS. No detector. No new SPL.  
**Parents:** `docs/PHASE9C_SCANNER_SPLUNK_VALIDATION.md`, `docs/MCP_CATALOG_POISONING_SECURITY_MODEL.md`.

A SOC question that names only “MCP poisoning” is underspecified. AgentSec splits the same incident into three evidence planes.

---

## The seven states (do not collapse)

| ID | State | Plane | LIVE 9C MALICIOUS ATTACK | LIVE 9C MALICIOUS RETEST | LIVE 9C NORMAL BASELINE |
|----|-------|-------|--------------------------|--------------------------|-------------------------|
| A | Scanner finds suspicious metadata | 1 Artifact | yes (HIGH PROMPT INJECTION) | **same finding** | no (zero findings, scan ran) |
| B | Agent observes that metadata | 2 Trust/request | METADATA-001 OBSERVE `untrusted_data` | **same OBSERVE** | OBSERVE on benign hash |
| C | Follow-on REQUEST is produced | 2 Trust/request | hop-1 `lookup_customer_tier` requested | **same request** | no follow-on |
| D | Follow-on is DENIED | 3 Authz/exec | no | DENY `tool_not_granted` | n/a |
| E | Follow-on is ALLOWED via lab overlay | 3 Authz/exec | ALLOW `vulnerable_profile_fail_open:metadata_derived_authority` | no | n/a |
| F | Follow-on tool **starts** | 3 Authz/exec | `mcp.started` observed | no | n/a |
| G | Follow-on **completes or fails** | 3 Authz/exec | `mcp.completed` observed | no | n/a |

The scanner row is identical for ATTACK and RETEST. **The scanner finding does not distinguish them.** Authorization and execution do.

---

## Plane 1 — Artifact security

**Question:** What did static analysis say about the artifact?

**Evidence:** `sourcetype=agentsec:scanner:finding`, `event.name=agentsec.scanner.scan` / `agentsec.scanner.finding`.

**Authoritative fields (9C LIVE):** `scan_id`, `scanner.name`/`version`/`commit`, `artifact.sha256`, `artifact.description_sha256`, `scan.finding_count`, `finding.native_rule_id`, `finding.native_severity` (native `HIGH`, not remapped), `provenance.raw_output_sha256`.

**Not this plane:** ALLOW/DENY, `mcp.started`, `agentsec.run.id` (intentionally null on scanner events).

**Honest meaning:** a vendor/static claim about bytes. PASS ≠ trusted. FAIL ≠ DENY. No finding ≠ safe. Finding ≠ exploit, execution, or authorization failure.

---

## Plane 2 — Runtime trust / request

**Question:** Did the agent observe the metadata and produce a follow-on request?

**Evidence:** `otel:agentic:json` CTRL-MCP-METADATA-001 (`agentsec.mcp.metadata.trust`, `agentsec.content.hash`, OBSERVE `metadata_is_data`) and hop-1 CTRL-MCP-001 **request** fields (`gen_ai.tool.name`, `agentsec.mcp.requested_scope`) before treating decision as the story.

**Honest meaning:** observation and intent. OBSERVE is classification, not a grant. A follow-on **request** is not ALLOW.

---

## Plane 3 — Authorization / execution

**Question:** Was authority granted, and did execution begin?

**Evidence:** CTRL-MCP-001 decision/reason; `agentsec.mcp.started` / `completed` / `failed`; runtime `handler_invoke_count` remains authoritative for non-execution.

**Honest meaning:** server-owned policy (or the labeled lab overlay) decided. Splunk corroborates. Splunk does not enforce.

---

## Combinations a detector might claim

| Claim | Planes | Distinguishes ATTACK vs RETEST? | Ready to publish? |
|-------|--------|----------------------------------|-------------------|
| Scanner HIGH | 1 | No | No — hunt/context |
| Scanner HIGH + METADATA-001 | 1+2 | No (both OBSERVE) | No — exposure hunt |
| Scanner HIGH + follow-on request | 1+2 | No | No — hunt |
| Scanner HIGH + follow-on ALLOW | 1+3 | Yes in this lab | No — ALLOW may be a real grant; lab overlay string |
| Scanner HIGH + follow-on start | 1+3 | Yes in this lab | No — missing grant snapshot; hash correlation limits |
| Overlay reason string | 3 | Yes in this lab | **REJECT** production — detects AgentSec fixture |
| DENY then `mcp.started` | 3 | Neither fires | Existing DET-MCP-001 only |

---

## Correlation between planes

Lab join key: `artifact.description_sha256` = `agentsec.content.hash` (UTF-8 description bytes).

Not a join key: `artifact.sha256` (whole `tools.json`). 9C MEASURED 0 rows when misused.

Scanner events have no `agentsec.run.id`. Time of scan (9B `created_at`) is not time of invoke. Same description at T1 vs T2 is a **rug-pull / pin** problem, not a 9D detector.
