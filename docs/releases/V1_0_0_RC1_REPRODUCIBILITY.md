# AgentSec v1.0.0-rc1 — reproducibility

| Class | Meaning | RC1 |
|-------|---------|-----|
| R1 static | git + docs + schema | YES (after commit/tag) |
| R2 offline tests | pytest excluding live markers | YES — 940 passed, 2 deselected MEASURED |
| R3 local runtime | Docker compose lab | PARTIAL — existing volumes reused |
| R4 LIVE experiment | Attack Service mint | YES — seven labs ATTACK+RETEST MEASURED |
| R5 Splunk reconstruction | local count == dc(_raw) | YES on primary run.ids MEASURED |
| R6 UI workflow | Playwright | YES if capture exit 0 |

Not claimed: FULLY REPRODUCED clean-room VM. Class: **PARTIALLY REPRODUCED / CURRENT-ENVIRONMENT VALIDATED**.
