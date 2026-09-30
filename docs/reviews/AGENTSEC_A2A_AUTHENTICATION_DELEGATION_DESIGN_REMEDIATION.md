# A2A authentication and delegated authority — design remediation

Design only. No workshop, runtime, schema, detector, or attack was added.

## Repository state at start

| Item | Value |
| --- | --- |
| Starting HEAD | `1de4f6e6045beb59a18e5dc9ca3951d45b4a4d67` |
| develop | same as HEAD |
| origin/develop | `6cd51e7ca07441a9fa6ca6d2ebe02161915b92c4` |
| Product baseline named by the review | `6cd51e7ca07441a9fa6ca6d2ebe02161915b92c4` |
| main and origin/main | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| v1.0.0-rc2 peeled | `1be214b92f840f843aaf27fb2b9536f764dd7126` |
| v1.0.0-rc3 | no tag |

Local `develop` was one commit ahead of `origin/develop`. That commit already tracks the independent review. The design file was untracked. `docs/plans/` and the older untracked reviews were left untouched.

The independent review’s PARTIAL integrity and PARTIAL remote sync were real: the design was not in git, and the review commit had not been pushed. This remediation tracks the corrected design and this report. The review was already tracked.

## Ending commit

The commit on `develop` that adds the corrected design and this report. The completion message records that hash after `git rev-parse`.

## Findings

Independent review verdict: CONDITIONAL GO. Counts: BLOCKER 0, HIGH 0, MEDIUM 1, LOW 1.

MEDIUM closed. Section 6 no longer says the only change across all three modes is whether the tool PDP honors one mismatch. ATTACK and RETEST request `lookup_customer_tier` / `customer:read` / `cust-001` and share `MISMATCH`. BASELINE requests `lookup_policy` / `policy:read` / `lending-basics` and is `MATCH`. BASELINE does not test the customer-tier call.

LOW closed. The mode table and the learner ledger now include requested resource and delegated resource. Tool scope and resource scope stay separate. A tool grant is not a grant for every resource.

No new Splunk export. Historical counts stay previously measured: ATTACK 6, RETEST 6, BASELINE 1. `who_authenticated` previously measured count 0. `LAB-AGENT-DELEGATION-001` previously measured count 0. That corpus was not reclassified as authentication or delegation.

The teaching packet is labeled SIMULATED AUTHENTICATION RESULT and SIMULATED DELEGATION DECISION. `MATCH` is not ALLOW. `MISMATCH` is not DENY. CTRL-IDENTITY-001 stays claim observation. CTRL-MCP-001 stays the tool PDP. `agentsec.mcp.started` stays execution evidence and does not prove completion or a resource change.

## Files

- Modified and now tracked: `docs/architecture/AGENTSEC_A2A_AUTHENTICATION_DELEGATION_DESIGN.md`
- Added: this report
- Already tracked before this remediation commit: `docs/reviews/AGENTSEC_A2A_AUTHENTICATION_DELEGATION_DESIGN_INDEPENDENT_REVIEW.md`
- Not modified: runtime, schema, ExternalEvidence, detectors, RC2, main

## Validation

`git diff --check` passed. Full offline suite: `1042 passed, 3 deselected, 9.58s`. Those tests do not prove authentication or delegation behavior. No curriculum file changed, so no new workshop contract was exercised. Secret scan of the design found only sentences that forbid passwords, tokens, keys, and certificates. None were added. Codeguard applied by not introducing credentials, certificates, or new cryptography.

## Recommendation

READY FOR INDEPENDENT A2A DESIGN RE-REVIEW. Do not implement the workshop from this file.
