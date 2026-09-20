# AgentSec Attack Service security boundary (Phase 14D)

**Status:** IMPLEMENTED for the local educational service.  
**Do not start Phase 15 from this file.**

---

## What this service is

A closed educational execution client. It posts **catalog** PI specimens to AcmeBank. It does not evaluate INV-008. CTRL-INPUT-001 remains on AcmeBank.

---

## Closed allowlist

allowed lab → allowed specimen → allowed mode → server-owned `ExperimentDefinition` → immutable `ExperimentContext` → `POST /process` with catalog payload + `experiment_id`.

Browser selection is metadata. It is not authorization input.

Rejected (ERROR, not DENY/ALLOW/SAFE/BLOCKED):

- unknown fields (including `profile`, grants, tools, scope, policy, env, SPL, Python)
- unknown lab / specimen / mode / execution
- unknown or mismatched `experiment_id`
- malformed experiment selection
- authority-like fields
- malformed / duplicate JSON
- learner SPL on `/api/compare-handoff`

---

## Must not

- arbitrary shell / Python / SPL execution
- generic MCP proxy
- generic tool invocation API
- coded-policy mutation
- user-supplied grants or security.profile
- process-env mutation during a request
- external targets
- production credentials in source, responses, or screenshots
- logging `Authorization` headers
- new detectors named after the simulator
- schema bump for bookkeeping

---

## Phase 14E

Closed MCP launches are still not a generic MCP proxy. The server owns tool, scope, arguments, and profile for LAB-MCP-001 specimens. Direct `POST /mcp/invoke` without `experiment_id` remains the existing AcmeBank auto-mode path (not the learner launcher).

---

## Localhost status (honest)

| Claim | 14D |
|-------|-----|
| LOCAL EDUCATIONAL SERVICE | Yes |
| NOT PRODUCTION AUTHENTICATION | Yes — none implemented |
| NOT MULTI-TENANT | Yes |
| NOT INTERNET-FACING | Host ports bound to 127.0.0.1. Compose in-container bind is mesh-only |

Future production (not implemented): authentication, authorization, tenancy, CSRF/origin, rate limiting, audit controls beyond access logs, stronger isolation.

---

## Trust

| Actor | Trust |
|-------|--------|
| Learner browser | Untrusted |
| Attack Service | Untrusted relative to AcmeBank |
| AcmeBank | Policy enforcement for the lab |
| Splunk | Observe-only |

An attacker who can reach loopback can fire allowlisted specimens. That is the existing classroom model, not a new guarantee.
