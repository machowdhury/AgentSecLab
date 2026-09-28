# Splunk Defender Bridge build

**Date:** 2026-09-28
**Starting commit:** `e513cb9e1b42f9b3b5a2554877b8cd470072b6c2`
**Ending commit:** the commit that adds this report. The SHA is recorded in the phase response after `git rev-parse HEAD`. It is not written here in advance.
**RC2 tag:** `v1.0.0-rc2` still peels to `1be214b92f840f843aaf27fb2b9536f764dd7126`. Not moved. No RC3 tag.

## 1. Build Summary

One post-RC2 curriculum checkpoint, the Splunk Defender Bridge, now sits between L5 and L6. It is a REPLAY / static investigation workbench. Learners start from a security question, not a supplied run identifier, and practice discovery, field selection, narrowing, candidate runs, sequence, a stats command, an ATTACK / RETEST / BASELINE comparison, a false lead, and a bounded conclusion.

No new attack, detector, alert, PDP, schema, or ExternalEvidence version was added. Attack Service allowlist is unchanged. L0–L10 ids are unchanged.

## 2. Starting Commit

`e513cb9e1b42f9b3b5a2554877b8cd470072b6c2` on `develop` (the post-RC2 curriculum review). `origin/develop` was still `1be214b92f840f843aaf27fb2b9536f764dd7126` at the start. `main` and `origin/main` were `e6115b6d1c03a1672b4364e84748c7840671fbfc`. That matched the authorized baseline. The review commit was preserved. It was not rewritten.

## 3. Ending Commit

The implementation commit that contains this file. See the phase response for the SHA. `v1.0.0-rc2` was not moved onto it.

## 4. Curriculum Placement

L5 → Splunk Defender Bridge → L6.

The checkpoint is `checkpoints[0]` in `learning/academy/curriculum.json`, id `SPLUNK-DEFENDER-BRIDGE`, lab id `LAB-SPLUNK-DEFENDER-BRIDGE`, view `ws_lab_splunk_defender_bridge`. It is not a member of `levels`, so L0–L10 stay the level ids. `next_lab(LAB-AGENTSEC-CAPSTONE-001)` remains `LAB-BLUE-TEAM-INCIDENT-001`. The Academy nav collection sits after Capstone and before Blue Team. Home copy states the same order. The lab is not in `known_lab_ids()`.

## 5. Learning Problem Addressed

The gap between guided L1–L5 investigations, which often start from a known run identifier, and the independent investigations expected by L6, L9, and L10. The page teaches the process. It does not add another attack.

## 6. Investigation Workflow

security question → hypothesis → discover → narrow → correlate → sequence → compare → challenge → conclude.

Tabs: MISSION, DISCOVER, INVESTIGATE, CHALLENGE, PATH B · REVIEW. Exercises 1–10 are on those tabs. Path B stays a visible review key, which is existing Academy practice. The mission does not state the comparison result.

## 7. SPL Progression

| Stage | Search | Purpose |
|-------|--------|---------|
| Find the data | `Q-BRIDGE-DISCOVER.spl` | Control-decision sample. No run identifier. |
| Discover fields | `Q-BRIDGE-FIELDS.spl` | `fieldsummary` of real decision fields. |
| Narrow | `Q-BRIDGE-NARROW.spl` | Denied CTRL-MCP-001 rows by run and mode. |
| Sequence | `Q-BRIDGE-SEQUENCE.spl` | Event names present per run. Absent names stay absent. |
| Summarize | `Q-BRIDGE-STATS.spl` | Learner completes the same shape on Path A. The finished command is on Path B. |
| Compare | `Q-BRIDGE-COMPARE.spl` | ATTACK, RETEST, BASELINE by event name. |
| Duplicates | `Q-BRIDGE-DUPLICATES.spl` | `count`, `dc(_raw)`, `dc(agentsec.run.id)`. |
| False lead | `Q-BRIDGE-EXTERNAL.spl` | Scanner and garak planes, separate from runtime authorization. |

Time teaching: searches use `earliest=0` so historical lab specimens are in scope. The page tells the learner to set a range and to treat an empty narrower window as NO EVIDENCE FOUND.

## 8. ATTACK / RETEST / BASELINE Model

The comparison filters `agentsec.testbed.mode` IN (ATTACK, RETEST, BASELINE) on CTRL-MCP-001 events. The mission does not print which mode was denied or whether a tool ran. The learner reads the rows. ATTACK is not universal compromise. RETEST is not universal security. BASELINE is not proof of safety. No new attack was generated.

Live row contents on this workstation: NOT MEASURED. Splunk Web was not accepting connections.

## 9. Evidence Semantics

The workshop teaches two vocabularies without renaming the product model.

How evidence was obtained: MEASURED, OBSERVED, DOCUMENTED, REPLAYED, SIMULATED.

What a claim may say: PROVEN, SUPPORTED, OBSERVED, INFERRED, NOT OBSERVED, NOT MODELED, NOT PROVEN, REFUTED.

This checkpoint's own class is REPLAY / static unless a later session measures a fresh launch.

## 10. External Evidence Treatment

`Q-BRIDGE-EXTERNAL.spl` summarizes `agentsec:scanner:finding` and `agentsec:external:evaluation` with `finding.native_severity`, `evaluation.native_result`, `correlation.method`, and `agentsec.run.id` when that field is present. Teaching text: scanner HIGH is not DENY, garak is not a runtime authorization decision, hash correlation is not a fabricated `agentsec.run.id`, and an empty run-id count is CORRELATION NOT ESTABLISHED. Cisco mcp-scanner and garak do not authorize.

## 11. Duplicate Event Treatment

`Q-BRIDGE-DUPLICATES.spl` returns indexed rows, `dc(_raw)`, and distinct run identifiers by testbed mode. The page states that a higher indexed count than distinct raw events means duplicate copies, not extra executions, and that HEC acceptance is not searchable completeness. This volume was not re-measured in this phase.

## 12. Failure States

Learner-facing language on the page and in `noDataMessage`: NO EVIDENCE FOUND, INSUFFICIENT EVIDENCE, CORRELATION NOT ESTABLISHED. The mission and challenge text do not tell the learner the lab is protected or that no hostile activity occurred. Multiple candidate runs and a missing stage are called out as cases to record, not to fill in.

Dependency outages (Splunk down, HEC down) were not injected. Splunk was already unavailable, so those runtime failure states are NOT MEASURED.

## 13. Beginner Experience

MISSION names the beginner path: use DISCOVER in order and read each hint before editing SPL. Hints 1–3 are conceptual direction, where to search, and field structure. The same tables are used for every persona.

## 14. Practitioner Experience

MISSION tells the practitioner to use the security question and objectives and to open a hint only when stuck.

## 15. Advanced Experience

MISSION tells the advanced learner to stay in Search until CHALLENGE. Hints are optional. Evidence and security meaning are the same as for the other personas.

## 16. Splunk Validation

NOT MEASURED.

`http://127.0.0.1:8000/` returned connection failure (`curl` HTTP status `000`). `docker ps` did not show `agentsec_splunk`. Searches were not executed. No rows were invented. Offline SPL contracts were tested: bounded index, no embedded run identifier, no `index=*`, no detector stanza.

## 17. UI / UX Validation

NOT TESTED in a browser. Splunk Web was down, so viewports 1920, 1440, 1280, and 1024 were not observed. The Studio canvas width in the definition is 1440, which is the existing Academy canvas. That is a source fact, not a viewport measurement.

## 18. Accessibility

NOT TESTED. Keyboard navigation and visible focus were not exercised. Screen reader: NOT TESTED. CSS zoom was not applied. This is not a WCAG certification.

## 19. Security Semantics

CTRL-MCP-001 remains the tool policy decision point. Confirmed by `CONTROL_ID` and by workshop text. Splunk remains downstream evidence. External evidence remains non-authoritative. No authorization feedback path was added. No detector was enabled. `savedsearches.conf` still has one `[AgentSec -` stanza.

Codeguard: no credentials, tokens, private keys, or certificates were added. No cryptographic algorithm was implemented. Existing telemetry field names were reused.

## 20. Schema

Runtime schema `1.9.0`. Unchanged. `schemas/security_event.schema.json` still constrains `1.9.0`.

## 21. External Contract

`EXTERNAL_CONTRACT_VERSION` remains `1.0.0`. Unchanged.

## 22. Focused Tests

MEASURED. `uv run --extra test python -m pytest` on the bridge contract plus registration suites (`test_splunk_defender_bridge.py`, UI shell, phase 16D, phase 15A, phase 16C): **43 passed in 0.14s**.

## 23. Full Offline Tests

MEASURED. `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`: **1033 passed, 3 deselected in 9.60s**.

## 24. Secret Hygiene

The diff was checked for AWS-style keys, GitHub tokens, live Stripe keys, JWT prefixes, private-key blocks, `SPLUNK_PASSWORD`, and workstation home paths in the new workshop files. No matches. `.env` was not staged. `docs/plans/` was not staged. `git diff --check` reported no whitespace errors before the commit.

## 25. Known Limitations

- Splunk execution of the new searches is NOT MEASURED on this workstation.
- Browser layout, keyboard focus, and screen reader are NOT TESTED.
- Path B remains visible, consistent with existing Academy practice.
- The bridge does not change L6, L9, or L10 content.
- Duplicate-copy behavior is taught from prior lab experience and from `count` versus `dc(_raw)`. It was not re-counted against a live index here.
- Clean-room install remains unproven. This phase did not claim it.
- An empty search is NO EVIDENCE FOUND, not a control result.

## 26. Git Status

Before the commit, `develop` was one review commit ahead of `origin/develop`. Untracked `docs/plans/` stays untracked. After the commit, the expected leftover untracked path is `docs/plans/`. `main`, `v1.0.0-rc1`, and `v1.0.0-rc2` are unchanged. No GitHub Release.

## 27. Evidence Classification

| Claim | Class |
|-------|--------|
| Mission does not embed a run identifier | MEASURED (pytest) |
| L0–L10 ids unchanged and bridge nav sits between Capstone and Blue Team | MEASURED (pytest) |
| Schema 1.9.0 and ExternalEvidence 1.0.0 unchanged | MEASURED (pytest) |
| No enabled detector added | MEASURED (pytest on `savedsearches.conf`) |
| Offline suite 1033 passed, 3 deselected | MEASURED |
| Search results, candidate run rows, comparison rows, duplicate counts | NOT MEASURED |
| Viewport rendering and keyboard focus | NOT TESTED |
| Screen reader | NOT TESTED |

Runtime modified: NO.
Authorization semantics modified: NO.
Schema modified: NO.
ExternalEvidence modified: NO.
RC2 tag modified: NO.
RC3 created: NO.
