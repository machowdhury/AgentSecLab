# Security boundary review — Phase 14E

**Date:** 2026-09-19  
**Scope:** Learning-loop generalization + LAB-MCP-001 Attack Service LIVE.

## Verdict

**PASS.** Generalization did not create a second authorization system.

## Checks

| Risk | Result |
|------|--------|
| Client-controlled profile | REJECTED (`unknown_fields` on launch; ignored on lookup) |
| Client-controlled grants / tools / scope / resource | REJECTED on `/api/launch`. Attack Service fills MCP body from ExperimentDefinition. |
| Learning-metadata authorization | Manifests declare `not_authorization=true`. Investigations do not ALLOW/DENY. |
| Studio authorization | Studio binds REPLAY tokens only. No POST. |
| Splunk authorization | Splunk remains evidence. DET-MCP-001 unchanged and disabled. |
| Arbitrary SPL / shell / Python proxy | Launch contract rejects those fields. |
| Environment mutation | `settings_for_experiment` uses `dataclasses.replace`. No env write. |
| Silent vulnerable fallback | Unknown / mismatched `experiment_id` is ERROR. Direct `/mcp/invoke` without experiment_id keeps existing auto-mode (defended process profile). |
| Global grant mutation | `coded_policy()` unchanged. |

LIVE launch with extra `tool` field: HTTP 400 `unknown_fields` (MEASURED). After ATTACK+RETEST, AcmeBank `/health` remained `security.profile=defended` with `testbed.mode.override=null` (OBSERVED).

## Malformed inputs

Empty / duplicate JSON keys / unknown fields / mismatched tool or arguments → ERROR class, HTTP 400. Not reinterpreted as ALLOW.

## What remains untrusted

Attack Service is a LOCAL EDUCATIONAL SERVICE: no production authentication, not multi-tenant, not internet-facing.
