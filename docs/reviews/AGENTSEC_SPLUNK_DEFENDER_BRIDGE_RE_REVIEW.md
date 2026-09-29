# Splunk Defender Bridge independent re-review

**Date:** 2026-09-29
**Reviewed remediation commit:** `978f91bc3a47fd6a94c446f784306d8740d9cf89`
**Original review commit:** `e33b0813b421affb9dd95b9005db9c2fc07bd11a`
**Original product build:** `1ecd883483fb98459a53952270d046d3c3b82175`
**Mode:** validation only. This review created this document. It did not change runtime, schema, contract, detectors, attacks, or tags.
**Decision:** recorded in section 13 after remote sync.

Evidence classes used below: MEASURED, OBSERVED, TESTED, DOCUMENTED, NOT TESTED, NOT PROVEN.

## 1. Repository state

Measured at review start, before this document existed:

| Ref | SHA | Result |
|-----|-----|--------|
| `HEAD` | `978f91bc3a47fd6a94c446f784306d8740d9cf89` | Matches the expected remediation commit |
| Branch | `develop` | Current branch |
| `origin/develop` | `1ecd883483fb98459a53952270d046d3c3b82175` | Behind local `develop` by 2 commits |
| `main` and `origin/main` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | Unchanged |
| `v1.0.0-rc1^{}` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | Not moved |
| `v1.0.0-rc2^{}` | `1be214b92f840f843aaf27fb2b9536f764dd7126` | Not moved |
| Tags | `v1.0.0-rc1`, `v1.0.0-rc2` | No RC3 |

The two local commits not on `origin/develop` at review start were `e33b081` (original independent review) and `978f91b` (remediation). Untracked `docs/plans/` was present and was not staged.

**REMOTE SYNC at review start: FAIL.** The remediation report stated this and did not conceal it. This review did not push until the validation below was finished. The post-push result is in section 12.

## 2. Original HIGH findings, reconstructed

From `docs/reviews/AGENTSEC_SPLUNK_DEFENDER_BRIDGE_INDEPENDENT_REVIEW.md`, not from the remediation report's conclusion.

**HIGH-01.** The shipped sequence and comparison searches required `agentsec.control.id=CTRL-MCP-001` on every returned event. Execution events such as `agentsec.mcp.started`, `agentsec.mcp.completed`, and `agentsec.mcp.failed` do not carry that field. The same filter hid `hop_denied` and `completed_denied`.

**HIGH-02.** A no-split count equaled `dc(_raw)` (then 141 and 141). Inflation appeared when `stats` split on multivalue `agentsec.testbed.mode` (`mvcount` 3). The workshop called that gap restaged copies. That cause was not supported.

Both were checked again against the current SPL, the workshop text, tests, and the current index.

## 3. HIGH-01 — closed

`Q-BRIDGE-SEQUENCE.spl` puts `CTRL-MCP-001` and `DENY` only inside the subsearch that selects run ids. The outer search is `index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0` plus that run-id constraint. It projects `control_id`, `decision`, `reason`, `tool`, and `outcome`, and sorts by `run_id` then `_time`. It does not require a control id on every row. Class: DOCUMENTED from the file, then MEASURED by running it.

`Q-BRIDGE-COMPARE.spl` is authorization only: control decisions for CTRL-MCP-001. `Q-BRIDGE-COMPARE-EXECUTION.spl` selects MCP start, complete, fail, hop completion, and run completion. It does not mention CTRL-MCP-001. Class: DOCUMENTED, then MEASURED.

The shipped sequence returned 26 events for three DENY runs. Rows with an empty control id included `agentsec.run.started`, `agentsec.hop.started`, `agentsec.memory.recalled`, `agentsec.pipeline.stopped`, `agentsec.hop.completed` (`hop_allowed` and `hop_denied`), and `agentsec.run.completed` (`completed_denied`). CTRL-MCP-001 DENY `tool_not_granted` for `lookup_customer_tier` was present on each of those runs. `agentsec.mcp.started` was absent on those three runs. That absence is NOT OBSERVED for those runs. It is not a control-id filter.

## 4. Discovery without a supplied run id

Initial run id supplied: NO. `Q-BRIDGE-DISCOVER.spl` and `Q-BRIDGE-NARROW.spl` contain no `agentsec.run.id=` constraint and no UUID. Class: DOCUMENTED.

Discovery returned 25 control-decision rows. The sample included CTRL-MCP-001 ALLOW `tool_granted` for `prepare_support_contact` in RETEST and ATTACK, CTRL-MCP-001 DENY `tool_not_granted` for `lookup_customer_tier` in RETEST, and a vulnerable-profile ALLOW whose reason describes fail-open. Other control ids, including CTRL-INPUT-001, were in the same sample. Class: MEASURED.

Narrow returned 48 CTRL-MCP-001 DENY rows. The first row, used as the candidate because it was first in that result and not because it was known in advance:

| Field | Value |
|-------|--------|
| `agentsec.run.id` | `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` |
| Mode | RETEST |
| Tool | `lookup_customer_tier` |
| Decision | DENY |
| Reason | `tool_not_granted` |
| Indexed rows | 1 |
| Distinct raw | 1 |

Evidence used: the narrow search output. No previously known run id was inserted. Candidate discovery: PASS.

## 5. Run-level correlation

A follow-up search used only that discovered run id. It did not filter on `agentsec.control.id`. It sorted by `_time`. Class: MEASURED.

Events that carry a control id:

| Time (GMT) | Event | Control id | Decision | Other |
|------------|-------|------------|----------|-------|
| 2026-09-14 04:19:21.752 | `agentsec.control.decision` | CTRL-MCP-001 | ALLOW | `lookup_policy`, `tool_granted` |
| 2026-09-14 04:19:21.755 | `agentsec.control.decision` | CTRL-MCP-RESULT-001 | OBSERVE | `lookup_policy`, `result_is_data` |
| 2026-09-14 04:19:21.756 | `agentsec.control.decision` | CTRL-MCP-001 | DENY | `lookup_customer_tier`, `tool_not_granted` |

Events in the same run with no control id:

| Time (GMT) | Event | Tool or outcome |
|------------|-------|-----------------|
| 2026-09-14 04:19:21.751 | `agentsec.run.started` | none |
| 2026-09-14 04:19:21.751 | `agentsec.hop.started` | none |
| 2026-09-14 04:19:21.753 | `agentsec.mcp.started` | `lookup_policy` |
| 2026-09-14 04:19:21.754 | `agentsec.mcp.completed` | `lookup_policy` |
| 2026-09-14 04:19:21.755 | `agentsec.hop.completed` | `hop_allowed` |
| 2026-09-14 04:19:21.756 | `agentsec.hop.started` | none |
| 2026-09-14 04:19:21.757 | `agentsec.pipeline.stopped` | none |
| 2026-09-14 04:19:21.758 | `agentsec.run.completed` | `completed_denied` |
| 2026-09-14 04:19:21.758 | `agentsec.hop.completed` | `hop_denied` |

`agentsec.mcp.failed` was not in this run. Class for that stage: NOT OBSERVED.

Two pairs share a timestamp (`run.started` with `hop.started`, and `run.completed` with the denied hop). Order inside that millisecond is NOT PROVEN as a causal sequence. Order across different timestamps is MEASURED.

This run is the correlation proof the original finding asked for. CTRL-MCP-001 DENY selected the run. The pivot then showed an earlier CTRL-MCP-001 ALLOW for a different tool, MCP start and completion for that allowed tool, and denied hop and run outcomes. Those MCP and outcome rows have no control id. DENY on `lookup_customer_tier` did not erase the allowed `lookup_policy` execution in the same run. ALLOW on `lookup_policy` is not a grant for `lookup_customer_tier`.

Run-level correlation: PASS. Execution events without control id: VERIFIED. Authorization versus execution: PASS.

## 6. `head 3` sample

The sequence subsearch uses `dedup run_id | head 3` and does not sort before `head`. The panel title is "Events for denied-authorization runs, in time order." Exercise 4 says the sequence table samples denied-authorization runs, and tells the learner to pivot on the run they found without adding a control id. Class: DOCUMENTED.

The three runs in the shipped table were not the narrow-first candidate. A learner who treats that panel as every DENY run would be wrong. The exercise text calls it a sample. The title does not say "three." That is a wording limit, not a filter that drops events for the runs it does select.

A probe that copied the subsearch shape with decision `DENY_NOT_PRESENT_FOR_REREVIEW` returned `indexed_rows=0`. It did not return the whole `otel:agentic:json` population. The remediation report's statement that an empty subsearch can drop the constraint and match every event was NOT OBSERVED for this search shape on this Splunk. Class: MEASURED for the zero-row probe. The broader Splunk footgun remains NOT PROVEN here.

Classification: ACCEPTABLE LIMITATION. Not expanded into a new fix.

## 7. ATTACK / RETEST / BASELINE

Authorization comparison, after one mode value and one decision value per event. Class: MEASURED on this index during this review.

| Mode | Decision | Indexed rows | Distinct raw | Distinct runs |
|------|----------|--------------|--------------|---------------|
| ATTACK | ALLOW | 60 | 60 | 58 |
| ATTACK | ERROR | 8 | 8 | 8 |
| BASELINE | ALLOW | 16 | 16 | 16 |
| BASELINE | ERROR | 1 | 1 | 1 |
| RETEST | ALLOW | 8 | 8 | 8 |
| RETEST | DENY | 48 | 48 | 48 |

`indexed_rows` equals `distinct_raw` on every authorization row. ERROR remains its own decision. These numbers match the previously reported distribution. They are this volume, not a product constant. The mission does not hardcode them. Class: DOCUMENTED for the mission text, MEASURED for the counts.

Execution comparison is a separate search and does not filter on CTRL-MCP-001. After dedup, indexed rows equal distinct raw. RETEST `mcp.started` is 8 distinct runs, the same count as RETEST ALLOW on this volume. BASELINE has 16 `mcp.started`, 11 `mcp.completed`, and 5 `mcp.failed` beside 16 ALLOW decisions. Completion is not ALLOW. The candidate run in section 5 shows a DENY and an ALLOW in one run, with execution only for the allowed tool.

Workshop text says ALLOW is not execution, DENY is not universal prevention, ERROR is not ALLOW and not DENY, BASELINE is not a proof of safety, and RETEST is a controlled label rather than a safety result. Class: DOCUMENTED, and OBSERVED in Splunk Web.

ATTACK / RETEST / BASELINE separation: PASS.

## 8. Multivalue root cause and the duplicate claim

No-split CTRL-MCP-001 decisions. Class: MEASURED.

| Indexed rows | `dc(_raw)` | Distinct runs | max `mvcount(agentsec.testbed.mode)` |
|--------------|------------|---------------|----------------------------------------|
| 141 | 141 | 137 | 3 |

`count` equals `dc(_raw)`. This volume does not establish duplicate raw copies of these decisions.

A confirmatory search that grouped by the raw `agentsec.testbed.mode` field, which the workshop does not ship, returned ATTACK 204 indexed versus 68 distinct raw, BASELINE 51 versus 17, and RETEST 168 versus 56. That is three times the distinct raw count, matching `mvcount` 3. Class: MEASURED.

The shipped mode grouping deduplicates mode before `by`. It returned ATTACK 68/68/66, BASELINE 17/17/17, RETEST 56/56/54, with indexed rows equal to distinct raw. Class: MEASURED.

Learner-facing text tells the reader to compare a no-`by` search first, that `stats by` a multivalue field can raise `count` when `dc(_raw)` does not, and that `mode_value_count` is values inside the field. Path B says that if indexed rows equal distinct raw, the search is not showing extra indexed copies, and that grouping before dedup can make `count` larger without an additional event. It says not to invent a cause. The word "restaged" is absent from the learner pages. A builder check rejects that word if it is put back into Path B or the challenge. "Deduplicate" in the hint refers to the repeated field value, not to extra executions.

Unsupported duplicate claim: REMOVED. Multivalue root cause: VERIFIED. HIGH-02: CLOSED.

## 9. Learner SPL progression

DISCOVER tells the learner to write the command, states the goal and the fields, and gives one hint: check `mvcount` on mode and deduplicate a repeated value before `stats` uses it in `by`. The finished `mvindex(mvdedup('agentsec.testbed.mode'),0)` pipeline is not on Path A. It is on Path B. Class: DOCUMENTED and OBSERVED in Splunk Web.

That is a guided write of `stats`, `count`, `dc()`, and `by`, with `sort` shown on Path B. It is not filling a `stats _____ by ...` skeleton. Copying Path B would skip the exercise. Path B remains visible. That is the accepted Path B debt from the original LOW-1.

Learner SPL modification: PASS. Learner SPL authoring: PASS.

## 10. External evidence and the conclusion

`Q-BRIDGE-EXTERNAL.spl`. Class: MEASURED.

| Sourcetype | Indexed rows | Distinct raw | Distinct runtime run ids | Other values |
|------------|--------------|--------------|---------------------------|--------------|
| `agentsec:external:evaluation` | 8 | 1 | 0 | PASS, `identity_tuple` |
| `agentsec:scanner:finding` | 27 | 6 | 0 | HIGH, `hash_join` |

The external indexed-versus-distinct-raw gap was not given a new cause. It is not the CTRL-MCP-001 mode split. Zero runtime run ids stay CORRELATION NOT ESTABLISHED. The challenge says HIGH is not a CTRL-MCP-001 DENY and a garak result is not a runtime authorization. Path B says those claims are NOT PROVEN. Class: DOCUMENTED and OBSERVED.

Exercise 10 asks for five separate lines: authorization, execution or NOT OBSERVED, outcome or NOT OBSERVED, external evidence or CORRELATION NOT ESTABLISHED, and at least one NOT PROVEN. The shape leaves the decision, the run, and the unsupported claim for the learner to fill. Failure language stays NO EVIDENCE FOUND, INSUFFICIENT EVIDENCE, and CORRELATION NOT ESTABLISHED. The challenge does not use the words SAFE, SECURE, or NO ATTACK as verdicts. Class: DOCUMENTED and OBSERVED.

External false lead: PASS. Bounded conclusion: PASS.

## 11. UI, keyboard, versions, security

Splunk Web was already up. This review did not restart the lab and did not launch an attack. Page errors on the bridge view: 0. Class: OBSERVED.

| Width | Horizontal overflow |
|-------|---------------------|
| 1920 | false |
| 1440 | false |
| 1280 | false |
| 1024 | false |

Tabs opened: MISSION, DISCOVER, INVESTIGATE, CHALLENGE, PATH B · REVIEW. Home lists Splunk Defender Bridge. Mission has the security question and Beginner. DISCOVER has the write-it-yourself exercise and does not show the finished pipeline. INVESTIGATE has the sample wording, both comparison tables, and `mode_value_count`. CHALLENGE has NOT PROVEN, NOT OBSERVED, and CORRELATION NOT ESTABLISHED, and does not say restaged. Path B has the finished pipeline and does not say restaged.

Keyboard, without the mouse after focus was placed on MISSION: ArrowRight moved focus to DISCOVER. Tab moved focus into the mission text. Shift+Tab returned focus to MISSION. Mission outline was `rgb(0, 110, 170) none 3px`. After Tab, the outline was `rgb(0, 95, 204) auto 1px`. Class: OBSERVED.

CSS `zoom: 2` on `documentElement` at viewport 1024: horizontal overflow true. That is a CSS zoom approximation, not browser zoom and not a screen reader. Classification: KNOWN ACCESSIBILITY LIMITATION. It did not pass.

Screen reader: NOT TESTED. No WCAG claim.

UI at the four widths: PASS. Accessibility: PARTIAL.

Running versions. Class: MEASURED.

| Surface | Result |
|---------|--------|
| AcmeBank `/health` and in-container package | `1.0.0rc1`, health `degraded`, `ollama_reachable=false` |
| In-container schema, contract, control | `1.9.0`, `1.0.0`, `CTRL-MCP-001` |
| Attack Service `/health` and package | `1.0.0rc1`, `schema_version=1.9.0`, healthy |
| Splunk `app.conf` | `version = 1.0.0-rc2` |
| Running saved searches | AgentSec stanza `disabled = 1`, `enableSched = 0`; other listed stanzas `disabled = 1` |

The running application containers are 1.0.0rc1. The Splunk app file says 1.0.0-rc2 because the tree was copied earlier. This review does not call the running stack RC2. Final 1.0 still needs an image rebuild and clean-room validation. Class for that future work: NOT TESTED.

The remediation diff does not touch `src/agentsec`, Attack Service routes, or `savedsearches.conf`. CTRL-MCP-001 remains the tool PDP id in the running container. RAG and memory control ids remain separate constants in source, and this review did not launch a new RAG or memory attack. Splunk, scanner, and garak are still downstream: the external search returned zero runtime run ids, and the workshop says they do not authorize. No detector was enabled. No new attack was added. Schema file constant remains 1.9.0. ExternalEvidence constant remains 1.0.0. Security semantics: PASS, on the basis of an unchanged diff plus the running ids. A fresh live proof of RAG and memory PDP behavior was NOT PERFORMED.

## 12. Tests, concurrency, secrets, sync

Focused, this review:

`uv run --extra test python -m pytest tests/splunk/test_splunk_defender_bridge.py tests/splunk/test_agentsec_ui_shell.py tests/unit/test_phase16d_academy.py -q --tb=line`

**25 passed in 0.12s.** Class: TESTED. These tests read files. They do not execute the searches. The Splunk sections above are the execution evidence.

Full offline, this review, first and only full run:

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`

**1033 passed, 3 deselected in 11.47s.** No failure in this run. Class: TESTED.

The remediation report recorded an earlier full run of 1 failed, 1032 passed, 3 deselected. The failure was `test_concurrent_rag_attack_and_retest_do_not_leak_profile`, with RETEST `lookup_customer_tier_handler_count` equal to 1 where the test expects 0. That assertion, if it failed again, would be evidence of ATTACK and RETEST state mixing. This review ran that test 15 times in isolation. **15 passed, 0 failed.** Classification: INTERMITTENT — NOT REPRODUCED. This does not prove the earlier failure cannot happen. It is not evidence of real cross-run leakage in this check, so this review did not stop for a release-significant leak.

Secret scan of `e33b081..978f91b` found no AWS-style keys, GitHub tokens, live secret prefixes, private-key blocks, certificate blocks, assigned `SPLUNK_PASSWORD`, or a workstation home path. `.env` was read locally to authenticate to Splunk and was not printed or committed. The learner pages contain no customer data. Secret hygiene: PASS.

Codeguard credential rule: applied by not writing secrets into this report or the remediation diff.
Codeguard certificate rule: applied by not introducing certificate material.
Codeguard crypto rule: applied by not adding cryptographic code.

Remote sync after this validation: see the commit that adds this file and the subsequent `origin/develop` check recorded with the final recommendation. `main` and the RC tags were not push targets.

## 13. Findings and recommendation

| Finding | Status |
|---------|--------|
| HIGH-01 sequence required control id on every event | CLOSED. Run pivot returns MCP and outcome rows with an empty control id. |
| HIGH-02 restaged-copy explanation | CLOSED. `count` equals `dc(_raw)` at 141. Grouping by the raw mode field still triples the count. The workshop teaches that and does not claim restaged copies. |
| LOW-1 Path B shows the finished stats command | Remains. Accepted teaching debt. Authoring on Path A no longer depends on a blank inside a finished command. |
| LOW-2 CSS zoom overflow | Remains. KNOWN ACCESSIBILITY LIMITATION. |
| `head 3` sequence sample | ACCEPTABLE LIMITATION. |
| Empty-subsearch full-index expansion | NOT OBSERVED on the probe. The probe returned 0. |
| Running containers at 1.0.0rc1 | INFORMATIONAL. Final 1.0 debt. |
| AcmeBank degraded, Ollama unreachable | INFORMATIONAL. This replay did not need a new launch. |
| RAG concurrency failure | INTERMITTENT — NOT REPRODUCED in 15 runs. |

Open counts: BLOCKER 0, HIGH 0, MEDIUM 0, LOW 2.

L5 → Bridge: PASS. The learner can start from the security question and obtain a run id from the index.

Bridge → L6: PASS for the transition this bridge was built to teach. The learner can separate authorization from execution, keep a missing MCP stage as NOT OBSERVED, and avoid treating a multivalue count as extra copies. L6 itself was not re-tested as a workshop.

The technical result supports GO — DEFENDER BRIDGE VALIDATED; AUTHORIZE DETECTION ENGINEERING DESIGN. That authorization stands only after the push of `develop` leaves local HEAD equal to `origin/develop`. A failed push does not reopen the two HIGH findings. It does block the next implementation phase until sync succeeds.

## 14. What this review did not do

No product file was left modified. No runtime telemetry was rewritten. No detector was enabled. No attack was launched. No schema or contract constant was edited. RC1, RC2, and `main` were not moved. Detection engineering was not started.

## 15. Post-push verification

Measured after `git push origin develop` of the review commit `4ee27442fcc0f5e06b4bb18c9c46a4c3fba01a7f`:

| Ref | SHA |
|-----|-----|
| `HEAD` | `4ee27442fcc0f5e06b4bb18c9c46a4c3fba01a7f` |
| `origin/develop` | `4ee27442fcc0f5e06b4bb18c9c46a4c3fba01a7f` |

`HEAD` equaled `origin/develop`. That push also published `978f91b` and `e33b081`. `main`, `origin/main`, `v1.0.0-rc1`, and `v1.0.0-rc2` were unchanged. No RC3 tag exists.

REMOTE SYNC: PASS.

Final recommendation: GO — DEFENDER BRIDGE VALIDATED; AUTHORIZE DETECTION ENGINEERING DESIGN. Detection engineering was not started by this review.
