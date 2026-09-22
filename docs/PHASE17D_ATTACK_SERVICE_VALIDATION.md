# Phase 17D — Attack Service validation

| Check | Result |
|-------|--------|
| Rebuild | `lab-up.sh --build`; image `agentseclab-attack_service` created 2026-09-22T02:28:52Z |
| HTTP | 200 on `/` and `/health` |
| ATLAS | REQUIRES REVALIDATION + AML.T0054 in running container template and HTML |
| Closed contract | extra `profile` → unknown_fields |
| Allowlisted launch | MCP-002 ATTACK/RETEST, PI ATK-002, RAG-001, GOAL-001 HTTP 200 |
| Fresh run.id | new UUIDs per launch |
| Search handoff | present in launch JSON keys |
| WAITING_FOR_EVIDENCE | default on launch JSON; Splunk later MEASURED rows |
| Localhost | 127.0.0.1:5001 |

Not added: remote access, new labs, new detectors.
