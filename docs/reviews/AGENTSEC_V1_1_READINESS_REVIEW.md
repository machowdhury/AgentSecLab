# AgentSec v1.1 readiness review

This is a candidate review for a future v1.1.0. It does not create that tag, a GitHub Release, or a merge to `main`.

The narrative, commands, and evidence classes are in `AGENTSEC_POST_EXTERNAL_PILOT_IMPROVEMENT_REPORT.md`.

Starting Commit: `07f37e736553689d63d6068b5ed50502218ec6f2`

Ending Commit: recorded in the follow-up line after these review files are committed. Code commit is `496e84917313e41667da5138cccdaf68f9de94f4`.

Origin/Develop: `develop`, pushed through the code commit and again with these reviews.

Main: `15f379e37773f250f70bc43270e64325590525e4`

v1.0.0 Integrity: peels to `537be71a13a5776c42a59ee9a25e2d4051d34ad0`. Not moved.

ATTACK Contract: PASS. Final run `20a3d2e1-91a4-4519-b214-b8f2324e2873`, `completed_allowed`, `ALLOW`, `llm_call_count=4`.

RETEST Contract: PASS. Final run `db8ba6ba-f4df-4016-a6de-a2373b1f18cd`, `completed_denied`, `DENY` `input_pattern_matched`, `llm_call_count=0`.

CTRL-MCP-001: unchanged tool PDP. Splunk is not the PDP.

Authorization vs Execution: reported as separate fields on both runs.

Schema: `1.9.0`

ExternalEvidence: `1.0.0`

DET-MCP-001: disabled (`disabled = 1`, `enableSched = 0`)

REMOTE DEPLOYMENT

Home -> Search: stayed on `3.17.29.24:8000` (login redirect). OBSERVED.

Home -> Attack Service: open-attack script uses the page hostname and has no loopback. Fetched after the final deploy.

Attack Service -> Search: `3.17.29.24:8000`. OBSERVED.

Attack Service -> Academy: `3.17.29.24:8000`. OBSERVED.

Learner-facing loopback defects: 0

ATTACK SERVICE

Prediction UX: browser-only. Not in the launch body. Not graded. Not sent to Splunk.

Launch-state UX: `RUN IN PROGRESS` with `request=accepted` on ATTACK. `RUN DENIED` on RETEST. Completion is not attack success.

run.id UX: shown as an investigation handle. Copy, Search, and Academy actions present.

Search handoff: host in the address bar, port 8000 from the Attack Service.

ATTACK/RETEST comparison: both runs in one session. Compare link uses both ids. No verdict from the history list.

Session history: this browser tab only.

CURRICULUM

Workshops reviewed: A2A, HITL, credential lifetime, provenance.

Workshops diversified: A2A, HITL, credential lifetime.

Answer leakage removed: launcher no longer prints the decision before launch (`496e849`). Path B keys remain after the learner classifies.

Active reasoning added: prediction form, and classify-the-card questions on the three workshops.

Evidence semantics preserved: evidence class and claim strength stay separate. The dependency graph is SIMULATED.

PROVENANCE

Ollama lesson: `ollama/ollama:latest` unpinned. No invented digest.

Generic dependency lesson: SIMULATED `classroom-ledger` → `ledger-client@1.4.2` → `sigil-utils@0.9.1`.

Inventory vs trust: stated in the workshop.

Provenance claims: labeled SIMULATED. Not a registry lookup.

Unverified claims: no Cisco AI-BOM claim.

VISUAL IDENTITY

Gated-A: SVG mark in the app and in `docs/brand/`.

Evidence sequence: claim, delegation/context, control decision, execution. Dashed links are not proof.

README architecture: SVG added. Text diagram kept. CTRL-MCP-001 is the gate. Splunk is downstream.

Accessibility descriptions: SVG text descriptions exist. Not a certification.

DOCUMENTATION

Linux: Docker path documented. EC2 Ubuntu rebuild OBSERVED. Not a from-empty install clock.

macOS: Docker Desktop documented. Minimums not benchmarked.

Windows: NOT VALIDATED.

Prerequisites: documented.

Precheck: WARN exits 0. FAIL exits 1. Neither is a control DENY.

lab-up: `--build`, `--refresh-app`, `--remote` documented. Volumes preserved on the rebuilds that ran.

lab-ready: service health is not searchable evidence, attack success, a digest, or an accessibility certification.

Remote deployment: `--remote` is the documented path. Not an SSH tunnel.

Timing guidance: prior clocks are observations. They are not a promise.

Troubleshooting: empty Search is not DENY. Certificate checks were not disabled.

ACCESSIBILITY

1920: Attack Service, no horizontal overflow. OBSERVED. Academy NOT MEASURED.

1440: same.

1280: same.

1024: same.

200%: CSS zoom on the Attack Service, no horizontal overflow. OBSERVED. Academy NOT MEASURED.

Keyboard: sequential Tab NOT RELIABLY MEASURED in headless Chrome.

Visible Focus: solid 2px outline when Launch ATTACK was focused. OBSERVED.

Screen Reader: NOT TESTED

WCAG Claim: none

LIVE VALIDATION

ATTACK run.id: `20a3d2e1-91a4-4519-b214-b8f2324e2873`

ATTACK searchable: handoff URL OBSERVED. Index lexicon and rawdata contain the id. Splunk Web result row NOT MEASURED.

ATTACK decision: `ALLOW`

ATTACK execution: `llm_call_count=4`, `completed_allowed`, evidence `WAITING_FOR_EVIDENCE`

RETEST run.id: `db8ba6ba-f4df-4016-a6de-a2373b1f18cd`

RETEST searchable: same split as ATTACK.

RETEST decision: `DENY` `input_pattern_matched`

RETEST execution: `llm_call_count=0`, `completed_denied`, evidence `WAITING_FOR_EVIDENCE`

TESTING

Focused tests: 83 passed.

Full suite: 1082 passed, 3 deselected.

Repeated reliability: 11 consecutive clean full suites after the launcher copy fix. One earlier concurrent RAG failure in this program was not reproduced and the assertion was not weakened.

git diff --check: clean for the remediation diff.

Secret hygiene: no secrets, certificates, or new crypto in the committed diff. `.env` not committed.

BLOCKER: 0

HIGH: 0

MEDIUM: 0

LOW: empty `/favicon.ico`; keyboard sequence not reliably measured; Academy viewports not measured; Splunk Web rows not measured.

Accepted Debt: those LOW items. Windows and Podman NOT VALIDATED. Path B answer keys remain.

FINAL VERDICT:

PASS — READY FOR INDEPENDENT v1.1 EXTERNAL LEARNER PILOT

The next step is an independent external learner pilot by a reviewer who did not implement this cycle. Do not merge `develop` into `main`. Do not move `v1.0.0`. Do not create `v1.1.0`.
