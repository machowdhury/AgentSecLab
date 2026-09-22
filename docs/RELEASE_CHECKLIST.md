# Release checklist (v1.0.0-rc1)

Do not mark PASS without evidence.

| Item | Result | Evidence |
|------|--------|----------|
| Tests pass (offline pytest) | PASS | 940 passed, 2 deselected (`not live_ollama and not live_splunk`) |
| Images build | PASS | `lab-up.sh --build` Attack Service + AcmeBank |
| Attack Service healthy | PASS | HTTP 200 `/health`, ATLAS qualifier OBSERVED |
| Splunk Web | PASS | HTTP 200 login |
| HEC health | PASS | HTTP 200 (not searchability) |
| Academy views | PASS | Playwright HTTP 200 Home/PI/MCP/Memory/Goal/Capstone/Mastery |
| LIVE smoke PI/MCP/RAG/Goal | PASS | MEASURED dc(_raw) in reproducibility report |
| MCP ATTACK/RETEST | PASS | ALLOW vs DENY MEASURED |
| Path A | PASS | Search by run.id documented + executed |
| Path B | PASS with known limitation | visible review keys |
| Capstone view | PASS | HTTP 200; LIVE triple not reminted |
| Mastery view | PASS | HTTP 200 |
| README / Quickstart | PASS | rewritten learner entry |
| Architecture / security / LIVE-REPLAY | PASS | canonical docs |
| Troubleshooting / ops | PASS | docs + lab-down |
| Secret audit | PASS | `.env` ignored; no key-pattern hits |
| UI gate | PASS | 0 HIGH/BLOCKER |
| License | PASS | Apache 2.0 already present |
| Version | PASS | product rc1; schema 1.9.0 |
| Changelog | PASS | CHANGELOG.md |
| lab-ready.sh one-shot this session | NOT RUN | see blockers MEDIUM |
| Clean-room install | NOT FULLY CLEAN-ROOM VALIDATED | |
| Git tag v1.0.0 | NOT DONE (correct) | |
