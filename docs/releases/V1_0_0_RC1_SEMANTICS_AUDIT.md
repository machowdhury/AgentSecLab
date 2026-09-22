# AgentSec v1.0.0-rc1 — semantics audit

Principles checked against learner-facing README, QUICKSTART, Academy copy (17C/17D), launch contract, and control matrix.

| Principle | Result |
|-----------|--------|
| REQUEST != GRANT | PASS |
| OBSERVE != ALLOW | PASS |
| ALLOW != EXECUTION | PASS |
| DENY != proof of non-execution alone | PASS |
| MISSING EVENT != PREVENTION | PASS |
| HEC != searchable evidence | PASS (`lab-ready.sh` wording) |
| SPLUNK != ENFORCEMENT | PASS |
| REPLAY != LIVE | PASS |
| UNTRUSTED != MALICIOUS | PASS (17C/Studio) |
| PROVENANCE != TRUST | PASS |
| STORED != TRUSTED | PASS |
| IDENTITY CLAIM != AUTHENTICATION | PASS |
| DELEGATION CLAIM != AUTHORIZATION | PASS |
| AGENT ID != crypto identity | PASS |
| AUTHORIZED TOOL != AUTHORIZED GOAL | PASS (Goal RETEST still MCP ALLOW lookup_policy) |
| A+B != NEW AUTHORITY | PASS (capstone teaching) |
| LEARNING METADATA != POLICY | PASS |
| ONE RETEST != UNIVERSAL SECURITY | PASS |

| Finding | Class |
|---------|--------|
| `docs/PHASE*.md` outdated slice claims | HISTORICAL ONLY |
| `savedsearches.conf` Q-RUN/Q-DENY Phase 2 placeholder | DOC DEFECT (LOW) |
| Studio Path B visible without click | INTENTIONAL LAB ARTIFACT / platform |
| ATLAS AML.T0054 REQUIRES REVALIDATION | PASS (honest) |
| Vulnerable ATTACK overlays | INTENTIONAL LAB ARTIFACT |

No RELEASE BLOCKER semantic contradiction found in current learner path.
