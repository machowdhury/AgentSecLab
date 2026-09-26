# AgentSec independent RC2 validation

**Date:** 2026-09-26
**Mode:** read-only product and release review. No application, test, dashboard, schema, tag, or version change was made to produce this assessment.
**Reviewed commit:** `973bc00e910ed69b03465080e4dd94f1dab9076d` (`develop`, also `origin/develop`)
**Verdict:** GO — CREATE RC2 CANDIDATE

This review does not create `v1.0.0-rc2`.

## 1. Executive Summary

The learner-entry remediation closed the two HIGH findings from the holistic audit. A reader of the README can tell `main` / `v1.0.0-rc1` from `develop`, and can see L0 through L10, including the difference between the L5 Capstone, the L10 Advanced Capstone, and Mastery Check.

The seven LIVE labs match the Attack Service allowlist. CTRL-MCP-001 remains the tool policy decision point. Schema `1.9.0` and ExternalEvidence `1.0.0` are unchanged. Package and Splunk version strings are still RC1, and the README says so. That is the correct state until an authorized RC2 build bumps them.

No release BLOCKER or HIGH issue remains. Early answer cards, visible Path B, the Splunk learning jump, clean-room install, screen-reader coverage, the unpinned Ollama image, and the garak license backlog may ship as bounded debt. Clean-room installation is required before final 1.0, not before creating the RC2 candidate.

## 2. Git / Tag Integrity

MEASURED this session.

| Ref | Value |
|-----|-------|
| Branch | `develop` |
| HEAD | `973bc00e910ed69b03465080e4dd94f1dab9076d` |
| develop | same as HEAD |
| origin/develop | same as HEAD |
| main | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| origin/main | same as main |
| `v1.0.0-rc1` type | annotated tag |
| tag object | `1aafacb02f4429f168fbdce61437dc37d4cfc74b` |
| peeled commit | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| `v1*` tags | `v1.0.0-rc1` only |
| Working tree | untracked `docs/plans/` only |

The tag object SHA differs from the peeled commit. That is expected annotated-tag behavior. The tag was not moved. No RC2 tag exists.

Classification: PASS.

## 3. Remediation Scope Verification

`git diff --name-only 7eece6ba719a60870e0c0cf08cb6729d4b7e3c67..973bc00e910ed69b03465080e4dd94f1dab9076d` lists only:

- `README.md`
- `docs/AGENTSEC_RELEASE_LAB_MATRIX.md`
- `docs/QUICKSTART.md`
- `docs/GETTING_STARTED.md`
- `docs/LIVE_VS_REPLAY.md`
- `docs/AGENTSEC_V1_PRODUCT_BOUNDARY.md`
- `docs/KNOWN_LIMITATIONS.md`
- `docs/INSTRUCTOR_GUIDE.md`
- `docs/reviews/AGENTSEC_RC2_LEARNER_ENTRY_RELEASE_IDENTITY_REMEDIATION.md`

No application, runtime, schema, ExternalEvidence, detector, UI, dashboard, or Splunk search file is in that range. Class: MEASURED. Scope PASS.

## 4. Product Identity

The README’s primary identity is an agentic security academy: a local lab for agentic security, investigation, threat modeling, privacy, and evidence analysis. The product-boundary “is not” list still excludes a production gateway, production PDP, certification, OAuth/OIDC/SPIFFE, and a production RAG or memory system. Class: DOCUMENTED.

No current learner-entry page calls AgentSec a production AI firewall, governance platform, IAM product, or compliance validator.

## 5. Curriculum L0–L10

Names below are from `learning/academy/curriculum.json`. Home, README, Quickstart, Getting Started, the release matrix, and the instructor guide were compared with that file and with `ws_agentsec_home.xml`.

| Level | Title | Classification |
|-------|-------|----------------|
| L0 | Orientation | ALIGNED |
| L1 | Input and tool authority | ALIGNED |
| L2 | Context and evidence are data | MINOR DIFFERENCE. Home shortens the title to “Context is data”. The lab list matches. |
| L3 | Intent and identity | ALIGNED |
| L4 | Investigation craft | ALIGNED. No separate workshop. |
| L5 | Integrated purple team | ALIGNED. Named L5 Capstone / Lending Assistant Investigation. |
| L6 | Blue-team investigation and threat hunting | ALIGNED |
| L7 | Threat modeling and security architecture | MINOR DIFFERENCE. `curriculum.json` mode is REPLAY. The lab adds no attack. The matrix calls the activity static reasoning and says why. |
| L8 | Privacy, data protection and agentic data governance | ALIGNED |
| L9 | Multi-stage agentic attack, investigation and defense | ALIGNED |
| L10 | Advanced capstone and mastery | ALIGNED |
| — | Mastery Check | ALIGNED. Unscored. Not L5. Not L10. |

Overall: ALIGNED. The two minor differences are explained and do not send the learner to the wrong exercise.

## 6. Seven LIVE Labs

Authority: `known_lab_ids()` from `src/agentsec/launch_catalog.py`, measured this session. Count: 7. Each allowlist row is `live_supported` and includes ATTACK, BASELINE, and RETEST.

| Lab ID | Learner name | Level | ATTACK | RETEST | Fresh execution | Splunk |
|--------|--------------|-------|--------|--------|-----------------|--------|
| LAB-PI-001 | Direct Prompt Injection | L1 | YES | YES | YES | YES |
| LAB-MCP-001 | Tool Authorization | L1 | YES | YES | YES | YES |
| LAB-RAG-CONTEXT | RAG / Retrieved Context | L2 | YES | YES | YES | YES |
| LAB-MEMORY-001 | Persistent Memory | L2 | YES | YES | YES | YES |
| LAB-AGENT-GOAL-INTEGRITY-001 | Goal / Instruction Integrity | L3 | YES | YES | YES | YES |
| LAB-AGENT-DELEGATION-001 | Agent Identity / Delegation | L3 | YES | YES | YES | YES |
| LAB-AGENTSEC-CAPSTONE-001 | Lending Assistant Investigation | L5 | YES | YES | YES | YES |

The README and the release matrix list the same seven IDs and do not mark later workshops as launchable. Class: VERIFIED.

## 7. LIVE / REPLAY / STATIC / SIMULATED

`docs/LIVE_VS_REPLAY.md` and the matrix define LIVE as a fresh launch, REPLAY as canonical evidence, static reasoning as analysis without a fresh attack, and simulated data as fixtures. The published REPLAY list includes garak, Blue Team, privacy, L9, and L10. L7 is called out as static architecture reasoning.

External Evidence, Blue Team, L8, L9, and L10 are not Attack Service labs. L7 states that it adds no attack. Mastery Check is questions, not an execution. Class: CLEAR on the current learner path.

## 8. Capstone / L10 / Mastery

On the current path a learner can separate:

1. L5 LIVE Capstone: Lending Assistant Investigation, last launcher.
2. L10 Advanced Capstone: MASTER-2026-001, REPLAY, no starting run id.
3. Mastery Check: unscored self-check.
4. Finishing the academy: L0 through L10, with Mastery Check optional.

The instructor guide step that used to say only “Capstone” now names all three. Historical PHASE files still use the older word. Getting Started tells readers not to treat those files as the install path. Class: CLEAR for a learner who starts at the README. Historical files remain historical.

## 9. Release Identity

| Occurrence | Class |
|------------|-------|
| README, Quickstart, Getting Started, product boundary: `develop` holds L0–L10; the tag peels to `main` and does not contain L6–L10 | CORRECT CURRENT |
| `pyproject.toml` `1.0.0rc1` and Splunk `app.conf` `1.0.0-rc1` | CORRECT CURRENT metadata, explained as unbumped. Not a claim that `develop` is the tag. |
| RC1 release notes and the RC1 reproducibility doc | CORRECT HISTORICAL |
| No learner-entry page says the full L0–L10 academy is inside the RC1 tag | — |

Leaving the package and app strings at RC1 is sufficiently explained for this review. Bumping them is the job of the RC2 candidate build, which this review does not perform. Class: ALIGNED.

## 10. First-Time Learner Journey

Starting from the README only:

| Persona | Rating | Why |
|---------|--------|-----|
| A — IT practitioner | READY WITH FRICTION | The path, first lab, and LIVE versus REPLAY are written down. Splunk search language and security vocabulary still arrive quickly. |
| B — security student | READY WITH FRICTION | ATTACK, RETEST, BASELINE, and evidence limits are explicit. Early cards still show expected outcomes. |
| C — experienced practitioner | READY WITH FRICTION | AI-specific boundaries (context is not a grant, tool is not a goal) are in L1–L3 before L10. They still pass through teaching labs rather than a short expert track. |
| D — AI security expert | READY WITH FRICTION | External evidence, goal versus tool, L9, and L10 are present. Path B and early answers reduce the surprise. Package metadata still says RC1 until the candidate build. |

## 11. Time to First Insight

Warm-environment time to first insight: NOT MEASURED. This review did not time a launch-to-insight path.

Clean-room time to first insight: NOT MEASURED. No empty machine was created.

## 12. Security Semantics

MEASURED in code this session.

- `CTRL-MCP-001` is the control id in `src/agentsec/mcp/authorize.py`. `coded_policy()` in `src/agentsec/mcp/policy.py` is the server-owned tool allow-list. Request JSON does not widen it.
- RAG, memory, and identity trust modules state that they do not mint an allow ticket. Goal pipeline text states that goal observation or deny does not mint one.
- `src/agentsec/external_evidence/plugin.py` forbids adapters from calling CTRL-MCP-001.
- Splunk is described as downstream in the README, the product boundary, and the workshops.

OBSERVE is not written as authorization. Class: STRONG.

## 13. ATTACK / RETEST / BASELINE

The README table says ATTACK is not universal compromise, RETEST is not universal safety, and BASELINE is not trusted forever. The RAG workshop’s RETEST and COMPARE copy repeats that one RETEST is not universal resistance. Class: DOCUMENTED and OBSERVED in workshop source. The distinction holds.

## 14. Splunk Learning Journey

The path still runs from a pasted `run.id` and starter SPL (Quickstart and early Path A), through field reading and ATTACK/RETEST comparison, then multi-source correlation in external evidence and L9, then L6–L10 work without treating a supplied run id as the start of the case. L10’s mission does not start from a run id. Detection content is a candidate, not an installed detector.

The jump into L6 is still abrupt. Early labs do more of the thinking. Class: MIXED. Not a release blocker. Do not redesign it in the RC2 candidate build unless a separate phase says so.

## 15. Splunk Evidence Semantics

README: READY is service health, not searchable evidence. HEC acceptance is not completeness. Zero rows are not safety. Known limitations: indexing delay, and a missing event is not prevention. Workshop no-data text says a missing `mcp.started` is not DENY. `dc(_raw)` remains the completeness comparison against local events, not a raw indexed count. Class: STRONG in current learner material.

## 16. External Security Evidence

Contract constant: `EXTERNAL_CONTRACT_VERSION = "1.0.0"` in `src/agentsec/external_evidence/contract.py`.

Path in `docs/EXTERNAL_SECURITY_EVIDENCE.md`: external tool, adapter, normalized evidence, HEC, Splunk, investigation. The same doc says this is not a second PDP.

Cisco mcp-scanner is attributed to Cisco AI Defense with repository `https://github.com/cisco-ai-defense/mcp-scanner`. garak is attributed to NVIDIA with `https://github.com/NVIDIA/garak`. garak pack text says no `agentsec.run.id` was produced or inherited. Scanner HIGH is not DENY. Zero findings are not safe. Hash equality is not called causation. Class: STRONG for the control boundary. License closure is not claimed here; see section 33.

## 17. Threat Modeling

L7’s own objective list covers what is protected, how data moves, where trust changes, influence, authority, who authorizes, what can go wrong, where controls live, how you would know, what cannot be proven, and residual risk. It adds no attack, runtime control, or compliance score. Class: STRONG as a reasoning exercise. Transfer outside AcmeBank is practiced on one described system, not measured on a second organization.

## 18. Privacy

L8’s curriculum line is to trace what an agent can see, infer, remember, disclose, send, persist, retrieve, log, and expose, and to separate an authorized action from appropriate data use. The matrix repeats that this is not a privacy certification. Class: STRONG as lab teaching. It is not legal advice and not a compliance result.

## 19. L9 Integration

`learning/level_1/LAB-MULTI-STAGE-INCIDENT-001/incident.json` marks goal integrity and identity/delegation as relevant but not observed. Authentication, human approval, cryptographic delegation, and production IAM are NOT MODELED. Path B says goal and identity failure are NOT OBSERVED. Direct retrieve-to-write causality is NOT PROVEN. The exercise uses RAG, memory, MCP, external evidence as a lead, privacy, false leads, and bounded reporting. Class: STRONG. Path B still holds the reference answer.

## 20. L10 / Mastery

L10 is a REPLAY investigation that does not start from a run id, separates tool authorization from the objective, and leaves customer impact unproven. Mastery Check is a separate unscored surface. Opening the dashboard does not record a mastered skill. There is no progress store. Class: MIXED. The case is independent relative to earlier labs. The assessment is an honor system, which known limitations already state.

## 21. Evidence Vocabulary

The README now says MEASURED, OBSERVED, TESTED, DOCUMENTED, REPLAYED, and SIMULATED describe how evidence was obtained, and PROVEN, SUPPORTED, INFERRED, NOT OBSERVED, NOT MODELED, NOT PROVEN, and REFUTED describe claim strength. The two lists are not merged, and they do not need to be. A careful reader can tell them apart. A skimmer can still mix them. Class: PARTIAL.

## 22. Learner Friction

**Early answer leakage.** The RAG mission still contains “ANSWER THE LAB DEFENDS: NO”. The RETEST card states the defended DENY and points at handler count before the learner launches. Class: ACCEPTABLE RC2 DEBT. It teaches the invariant early. It is not a false security claim. Fixing it would be a UI change, which the remediation correctly left alone.

**Path B.** Answer tabs remain visible, including `PATH B · ANSWERS` on Blue Team and a PATH B tab on L10. Known limitations say Studio does not hide Path B. This is transparent pedagogical convenience, not access control, and not a release blocker. Class: ACCEPTED RC2 DEBT.

**Canonical ids on LIVE pages.** The RAG RETEST tab prints a REPLAY run id and says the table is not the learner’s LIVE id. The README says the same. A learner can still copy the specimen id. Class: MEDIUM FRICTION, not HIGH release risk, because the page labels the id as REPLAY.

## 23. UI Smoke

OBSERVED on the existing lab, not a clean volume. Chrome headless. Wait about 2.5 seconds per view. No page errors were captured.

Views: Academy Home, Direct Prompt Injection, Tool Authorization, RAG, Memory, Goal, Identity, garak, Blue Team, L7, L8, L9, L10, Mastery Check.

At 1440 and at 1024, every view URL loaded and `documentElement` horizontal overflow was false. This pass did not open every tab and did not repeat 1280 or 200% zoom. Prior L10 review recorded Splunk-chrome overflow at 200%. That limitation stands. Class: PASS for this bounded smoke.

## 24. Accessibility

Screen reader: NOT TESTED this session. Keyboard and focus were not re-measured this session. Earlier L10 review recorded keyboard movement and a visible focus outline on that workshop only. Overall: PARTIAL. Not a WCAG conformance claim. Known limitations now say screen-reader coverage is partial.

## 25. Clean-Room Status

No current learner-entry document claims a proven clean-room install. Known limitations still point at the RC1 reproducibility note. Instructor guide still says the Phase 17D environment was not a clean-room VM. Class: NOT PROVEN. Disposition: FINAL 1.0 REQUIREMENT. It does not block creating the RC2 candidate.

## 26. Future Architecture Non-Claims

The README states that production IAM, non-human identity, agent-to-agent identity, cryptographic delegation, and privacy compliance are not evidenced. Product boundary still excludes OAuth/OIDC/SPIFFE, a real A2A stack, production RAG, and production memory. L9 marks human approval and cryptographic delegation NOT MODELED. No learner-entry page claims JIT credentials, signed delegation, replay protection, human-in-the-loop enforcement, a semantic gateway, or tamper-resistant audit chaining. Class: DOCUMENTED non-claims. Not a penalty.

## 27. Original HIGH Findings

### F-01 — release identity

Original: README and package metadata called the tree RC1 while `develop` was not the tag. Remediation: README, Quickstart, Getting Started, and the product boundary separate the tag from `develop` and explain the unbumped `1.0.0rc1` strings. Current status: CLOSED for the learner. The strings themselves stay until the RC2 build. That is explained, not misleading.

### F-02 — learner map

Original: README and the matrix stopped at Capstone and Mastery Check and omitted garak and L6–L10. Remediation: both documents now list the Home path, garak, and the three endings. Current status: CLOSED.

HIGH findings closed: 2/2. None remain as RC2 blockers.

## 28. Original MEDIUM Findings

| ID | Problem | What happened | Current severity | Disposition |
|----|---------|---------------|------------------|-------------|
| F-03 | Default clone is `main`, which is RC1 | README and Quickstart say to use `develop` | LOW as a surprise, because it is now stated | CLOSED as a documentation requirement. The GitHub default branch was not changed. Changing it is a later release step, not a precondition for the candidate tag. |
| F-04 | Early mission cards state the lab answer | UI not changed. Recorded as deferred. | MEDIUM friction | ACCEPTED FOR RC2 |
| F-05 | Path B is visible | Limitation kept and repeated in the README | MEDIUM friction | ACCEPTED FOR RC2 |
| F-06 | Three meanings of Capstone | README, matrix, and instructor guide name L5, L10, and Mastery Check | Closed on the learner path | CLOSED |
| F-07 | Two evidence vocabularies | README explains which question each list answers. No separate glossary page. | LOW | ACCEPTED FOR RC2 |
| F-08 | Clean-room install not proven | Still stated. Not newly claimed. | Unchanged | ACCEPTED FOR RC2. Required before final 1.0. |
| F-10 | garak pin license versus backlog | Pin still says Apache-2.0. Backlog item 1 is still NEEDS EXTERNAL VALIDATION. Remediation did not edit the pin. | Unchanged | ACCEPTED FOR RC2. Not release-blocking. |

MEDIUM findings closed or accepted for RC2: 7/7. None are MUST FIX BEFORE RC2.

## 29. LOW Findings

| ID | This review |
|----|-------------|
| F-11 | garak Path A still names a scan id. Backlog. Not combined into a blocker. |
| F-12 | Least privilege is still not a Home heading. Backlog. |
| F-13 | `.env.example` still warns that lab defaults are for localhost. No values were copied into the remediation diff. |
| F-14 | Mastery remains self-assessed. Intentional. |
| F-15 | Screen reader still not tested. Limitation now appears in known limitations. |
| F-16 | PHASE files remain. Getting Started still diverts readers. Intentional. |
| F-17 | Placeholder saved searches were not part of this diff. Backlog. |
| F-18 | The README line that called memory “memory-derived authority” is gone from the rewritten entry. The fixture limitation remains in the memory lab. Stale as a README defect. |
| F-19 | Effort figures are still estimates. Time to insight was not measured. |
| F-20 | The 2026-09-24 review is still historical. This review, not that file, decides RC2. |

No LOW finding regressed into a HIGH. No set of LOW findings combines into a release blocker.

## 30. Test Strategy

Focused command:

```text
uv run --extra test python -m pytest tests/unit/test_phase17d_release.py tests/splunk/test_local_compose_provisioning.py tests/splunk/test_agentsec_home_dashboard.py tests/splunk/test_threat_modeling.py tests/splunk/test_privacy_data_governance.py tests/splunk/test_multi_stage_incident.py tests/splunk/test_advanced_capstone_mastery.py tests/unit/test_phase16d_academy.py -q --tb=line -m "not live_ollama and not live_splunk"
```

Result: 55 passed in 0.16s. Class: TESTED.

Full offline command:

```text
uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
```

Result: 1027 passed, 3 deselected in 10.75s. Same count as the remediation checkpoint. Class: TESTED.

Pytest does not prove security effectiveness. Live Splunk was not re-executed for this review. Prior L10 live evidence remains historical to that phase.

Allowlist check, same session: 7 labs, each with ATTACK, BASELINE, and RETEST. Class: MEASURED.

## 31. Documentation Links

Relative links in the README, Quickstart, Getting Started, and the release matrix were resolved on disk. None were broken. In-page README anchor `#academy-l0-l10` matches the heading. Historical PHASE files were not crawled. Class: PASS.

## 32. Secret Hygiene

The remediation diff was scanned for key, token, password assignment, private-key, and cloud-key patterns. Hits: 0. `.env` is not a tracked file. No secret value is written in this report. Class: PASS for the reviewed tree and that diff. Local lab defaults in `.env.example` remain a documented localhost warning (F-13), not a committed production secret.

## 33. Third-Party Attribution

Learner-facing README and matrix name Cisco mcp-scanner (Cisco AI Defense) and garak (NVIDIA) as tools AgentSec did not build. Pin files carry repository URLs. garak’s pin license string is stronger than `docs/EXTERNAL_VALIDATION_BACKLOG.md`, which still marks the upstream license, probe fidelity, and Ollama generator behavior as NEEDS EXTERNAL VALIDATION. That tension is deferred external-validation debt. It does not block RC2. Class: PASS for attribution. PARTIAL for license closure, which is not claimed.

## 34. RC2 Release Findings

| Severity | Count | Notes |
|----------|-------|-------|
| BLOCKER | 0 | — |
| HIGH | 0 | F-01 and F-02 are closed |
| MEDIUM | 0 that must be fixed before the candidate | F-04, F-05, F-07, F-08, and F-10 are accepted debt |
| LOW | backlog only | No new LOW regression |

RC2 must fix before the candidate tag: NONE, inside this review. The candidate build itself is expected to set current version fields to RC2 and to leave historical RC1 text alone. That work is the next authorized phase, not a defect in this tree.

## 35. Final 1.0 Requirements

Required before final `v1.0.0`, not before the RC2 tag:

1. A measured clean-room first boot.
2. A real screen-reader pass. Do not claim WCAG before that.
3. Pin `ollama/ollama:latest`.
4. Reconcile the garak license line with the external-validation backlog.
5. Leave third-party probe, protocol, and framework-identifier items unresolved until externally checked. Do not invent that validation.

## 36. Final Recommendation

GO — CREATE RC2 CANDIDATE

The academy on `develop` is coherent enough to freeze as a release candidate. Security semantics, the seven-lab allowlist, and the learner map agree. Remaining issues are documented debt or final-1.0 work.

Do not treat this sentence as the tag. Do not merge to `main` from this review. Do not create a GitHub Release from this review.

Post-RC2 horizon, not in this candidate: production non-human identity and JIT credentials, agent-to-agent authentication and delegation, human approval, production RAG and vector authorization, semantic input controls, tamper-resistant evidence, more external tools, and deeper detection-engineering or hunting exercises.
