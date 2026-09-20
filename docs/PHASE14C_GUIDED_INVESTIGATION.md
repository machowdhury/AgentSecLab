# Phase 14C — Guided investigation framework (LAB-PI-001)

**Date:** 2026-09-19  
**Mode:** IMPLEMENTATION + Splunk learning experience + live validation  
**Reference lab:** LAB-PI-001 / Direct Prompt Injection  
**Schema:** **1.9.0** unchanged. No bump.  
**Do not start Phase 14D from this file.**

---

## Purpose

Turn the Phase 14B execution plane into an interactive learner workflow without replacing investigation with prebuilt answers.

```text
LEARN → PREDICT → LAUNCH → INVESTIGATE
  Path A: try it yourself in Search
  Path B: show solution (copyable Q-* SPL + REPLAY table + explanation)
→ DEFEND → RETEST/COMPARE where supported → PROVE → CONNECT
```

Studio is the syllabus and answer key. Splunk Search is the workbench. Splunk is not enforcement.

HUNT is a **stacked notebook** (Path A question, Hint 1, Hint 2, Path B solution, bound table × six investigations). Studio 10.2 token hide/show placed newly shown Path B visualizations on the same grid origin as the question (OBSERVED). Custom browser scripts are not used.

---

## Live version alignment

Phase 14B live image had emitted `agentsec.schema.version=1.7.0`. 14C rebuilt/restaged AcmeBank + Attack Service from current repository (`SCHEMA_VERSION=1.9.0`).

| Check | Class | Result |
|-------|-------|--------|
| Image / code `SCHEMA_VERSION` | OBSERVED | `1.9.0` |
| LIVE ATTACK `039364cc-94ec-42fd-9976-025701f0d8be` | OBSERVED | runtime 6 events, hop 0 DENY |
| LIVE BASELINE `62cdf141-4e7b-4d55-aa94-eb929a275239` | OBSERVED | runtime 22 events, 4 LLM |
| Launch evidence_state | OBSERVED | `WAITING_FOR_EVIDENCE` until a Splunk probe measures rows (HEC 200 ≠ ready) |
| Splunk ATTACK `dc(_raw)` / schema | LIVE SPLUNK | **6** / **1.9.0**; Q-CONTROL 1 DENY; Q-LLM 0 |
| Splunk BASELINE `dc(_raw)` / schema | LIVE SPLUNK | **22** / **1.9.0**; Q-CONTROL 4; Q-LLM 8 |
| Canonical REPLAY `b3611d56-…` on this volume | LIVE SPLUNK | `dc(_raw)=0` (empty Path B tables ≠ SAFE) |

If restage had not emitted 1.9.0, this phase would have been **BLOCKED**. Schema was not modified to fix drift.

---

## Learning experience

Investigations are JSON metadata (`learning/level_1/LAB-PI-001/investigations.json`) loaded by `agentsec.investigations`. **Not authorization.**

Investigate specimen remains the only hunt token. Fresh LIVE `run.id` is Search handoff, not a Studio token write.

---

## Attack Service

Predict fields and learner evidence words (LAUNCHING / TELEMETRY SENT / WAITING FOR SPLUNK / EVIDENCE READY) are shown only from measured lifecycle/probe. Timeout copy: “Evidence has not appeared in Splunk within the validation window.” LIVE RETEST stays disabled. Allowlist still LAB-PI-001 only.

Browser profile probe is same-origin `GET /api/target-health` (server-side AcmeBank `/health`). Cross-origin fetch to `http://acmebank:5000` is not used.

---

## What 14C did not do

- Phase 14D
- MCP-001 launch
- LIVE RETEST
- Custom JS Studio token writes
- New DET-*
- Schema bump
- Authorization change
- New top-level nav
- New Q-* hunt files

---

## Verdict

**PASS** as guided investigation on LAB-PI-001. Offline pytest **741 passed, 2 deselected**. Live Splunk 1.9.0 measured on fresh BASELINE + ATTACK. UI BLOCKER/HIGH from Path B overlap and cross-origin `/health` were fixed (stacked notebook + `/api/target-health`). Remaining MEDIUM: Studio empty-table chrome; canonical REPLAY ids absent on this volume; token ellipsis.

**Do not start Phase 14D.**
