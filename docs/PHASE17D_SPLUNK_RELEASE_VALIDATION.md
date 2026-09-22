# Phase 17D — Splunk release validation

| Check | Result | Evidence class |
|-------|--------|----------------|
| Splunk login | HTTP 200 | OBSERVED |
| HEC health | HTTP 200 | OBSERVED (not searchability) |
| Home / PI / MCP / Memory / Goal / Capstone / Mastery | HTTP 200 Playwright | OBSERVED |
| HTTP 400 workshop pages | none on captured views | OBSERVED |
| app.conf in volume | 1.0.0-rc1 after `--refresh-app` | OBSERVED |
| Schema on smoke ATTACK | 1.9.0 | MEASURED |
| Q-MCP control.decision smoke | ALLOW vs DENY by run.id | MEASURED |
| DET-* added | no | DOCUMENTED / pytest |
| `lab-ready.sh` full script this session | not completed (tool classifier blocked the wrapper) | LIMITATION |

Props/savedsearches not redesigned. HEC health ≠ indexed evidence. Smoke rows were MEASURED after WAITING_FOR_EVIDENCE.
