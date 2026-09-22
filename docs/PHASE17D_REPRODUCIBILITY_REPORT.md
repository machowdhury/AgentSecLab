# Phase 17D — Reproducibility report

| Class | Applied? |
|-------|----------|
| FULLY REPRODUCED | NO |
| PARTIALLY REPRODUCED | YES — application images rebuilt; app volume restaged |
| CURRENT-ENVIRONMENT VALIDATED | YES — existing Splunk/Ollama volumes |
| NOT VALIDATED | Clean-room OS install |

Release smoke `run.id` values are **RELEASE VALIDATION EVIDENCE**, not official historical pairs:

| Lab | Mode | run.id | Splunk dc(_raw) |
|-----|------|--------|-----------------|
| LAB-MCP-001 | ATTACK | 39013788-b7d7-453f-ae8d-6f1c28c149e1 | 7 |
| LAB-MCP-001 | RETEST | 52a7ba3a-c765-4399-b9ef-97330f0b62fd | 6 |
| LAB-PI-001 | ATTACK | 716b03a2-168a-41ab-ad4c-9ecd5f35fbf1 | 22 |
| LAB-RAG-CONTEXT | ATTACK | a228bfae-bf89-414b-ad3f-77aaa5de6d13 | 10 |
| LAB-AGENT-GOAL-INTEGRITY-001 | ATTACK | 6e279b64-034c-4ceb-9dd8-3b8c2d358989 | 10 |

Capstone LIVE triple was **not** reminted. Capstone Studio HTTP 200 (Playwright). Official historical capstone ids remain historical.
