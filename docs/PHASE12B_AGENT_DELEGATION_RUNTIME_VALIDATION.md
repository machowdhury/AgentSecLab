# Phase 12B — Agent identity / delegation runtime validation

**Status:** IMPLEMENTED + LOCALLY VALIDATED  
**Date:** 2026-09-18  
**Lab:** LAB-AGENT-DELEGATION-001 / A2A-001  
**Schema:** 1.8.0  
**Splunk:** NOT VALIDATED **in this phase**. Live Splunk proof is `docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md` (different run IDs). Do not reuse the local IDs below as Splunk proof.  
**Detection:** NOT STARTED  
**Workshop:** NOT STARTED  
**A2A transport:** NOT IMPLEMENTED

Evidence class: pytest **MEASURED** (**647 passed, 2 deselected**, 2026-09-18). Canonical **local** packs:

| Specimen | run.id | Identity | MCP | Handlers |
|----------|--------|----------|-----|----------|
| A BASELINE | `c4001dd2-ba17-4951-8b2d-f0942104b4a1` | OBSERVE | ALLOW `tool_granted` | policy 1 / tier 0 |
| B ATTACK | `e5d76432-a2e5-42f6-a7e7-a599c75ad6e4` | OBSERVE | ALLOW `vulnerable_profile_fail_open:caller_identity_derived_authority` | policy 0 / tier 1 |
| C RETEST | `73f10e49-89f1-4412-8015-9d92fe545a55` | OBSERVE | DENY `tool_not_granted` | policy 0 / tier 0 |

Packs: `artifacts/<run-id>/` plus `artifacts/lab-agent-delegation-001-{A,B,C}-<run-id>/`. Each `export.json` / `manifest.json` has `splunk.verified=false`.

---

## Local proofs (MEASURED in pytest)

| Id | Proof | Result |
|----|-------|--------|
| A | BASELINE policy tool executes | ALLOW `tool_granted`; `lookup_policy` handler 1 |
| B | BASELINE privileged tool does not execute | `lookup_customer_tier` handler 0 |
| C | ATTACK uses the vulnerable overlay | reason `vulnerable_profile_fail_open:caller_identity_derived_authority` |
| D | ATTACK handler count = 1 | MEASURED |
| E | RETEST uses the same adversarial request | canonical dict equal |
| F | RETEST CTRL-MCP-001 = DENY `tool_not_granted` | MEASURED |
| G | RETEST privileged handler count = 0 | MEASURED; no `mcp.started` |
| H/I | Agent A and B coded grants never contain `customer:read` | MEASURED |
| J | Global `coded_policy()` unchanged before/after ATTACK | MEASURED |
| K | Overlay does not survive into RETEST | `overlay_applied=false` |
| L | CTRL-IDENTITY-001 remains OBSERVE | MEASURED on A/B/C |
| M | Claims do not mint AllowTicket | OBSERVE ≠ ALLOW |
| N | Caller-provided authority keys do not become grants | ERROR `unknown_fields` |
| O | No secret-bearing identity material logged | MEASURED |
| P | Existing MCP/RAG/memory behavior remains intact | full offline pytest |

## Check / use

Parse produces a frozen `A2ADelegationRequest`. Mutating the original dict after parse does not change the follow-on tool. Overlay fingerprint equals the evaluated request fingerprint.

## Identity / authentication limitation

WHO AUTHENTICATED is **NOT PROVEN / NOT MODELED**. Emitters do not set `authenticated=true`, `verified_identity=true`, or `cryptographic_passport_valid=true`.

## Limitations

- No Splunk ingest or field discovery (Phase 12C).
- No detector, no Dashboard Studio, no live A2A.
- Grant snapshot `allowed_tools` remains a telemetry gap.
- In-process model only; not the A2A protocol.
