# AgentSec detection engineering design — independent review

**Date:** 2026-09-29
**Product HEAD:** `8ec6f76f799b925d483f3ebe77f56a929a8dec3d` (`develop` = `origin/develop`)
**Defender Bridge remediation, ancestor of HEAD:** `978f91bc3a47fd6a94c446f784306d8740d9cf89`
**Design under review:** `docs/architecture/AGENTSEC_DETECTION_ENGINEERING_DESIGN.md` (untracked; not inside `8ec6f76`)
**Mode:** Review only. No workshop, detector, saved search, attack, schema, contract, or runtime change.

Evidence classes: MEASURED means a Splunk export in this review. DOCUMENTED means source or the design file. INFERRED means a conclusion from those two. This review did not launch an attack.

Splunk authentication was read from `.env` inside the query process and was not written here. No certificate material and no cryptographic implementation were part of this review.

## 1. Executive summary

The design picks the right lesson. DET-MCP-001 looks for a later `agentsec.mcp.started` of the same tool after a DENY. On the current index that predicate matches nothing. The principal ATTACK path is a fail-open ALLOW followed by a start. A learner can write a plausible detection, tighten it, and still miss the attack. That teaching pattern is valid.

Two factual errors in the design have to be corrected before that workshop is built from the text as written.

The shipped SPL does not require `agentsec.control.id=CTRL-MCP-001`. It treats any control-decision DENY with the same run and tool as the denial. Goal-integrity and delegation DENY events on this index do carry `gen_ai.tool.name`. None of them was followed by a same-tool start, so the omission did not produce a measured match. The design still says the file already constrains the control id.

The design's false-positive example says a run-id-only search flags `lookup_policy` after a DENY of `lookup_customer_tier`. On run `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` the start is sequence 4 and the DENY is sequence 9. A second RETEST run, `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`, has the same tool split: start of `lookup_policy` at sequence 5, DENY of `lookup_customer_tier` at sequence 9. The broad candidate matches both. The shipped same-tool predicate matches neither.

Positive evidence remains a `makeresults` row labeled `SIMULATED`. This review executed that search: 1 row, run `simulated-det-mcp-001-0001`. That supports LOGIC VALIDATED for the synthetic input. It does not support SCENARIO VALIDATED.

Recommendation: **CONDITIONAL GO**. Correct those two design statements. Then build one REPLAY workshop. Do not enable DET-MCP-001. Do not edit `savedsearches.conf`.

## 2. Repository detection reality

| Check | Result |
|-------|--------|
| HEAD and `origin/develop` | `8ec6f76f799b925d483f3ebe77f56a929a8dec3d` |
| `v1.0.0-rc1` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| `v1.0.0-rc2` | `1be214b92f840f843aaf27fb2b9536f764dd7126` |
| `v1.0.0-rc3` | no tag |
| `SCHEMA_VERSION` | `1.9.0` in `src/agentsec/experiment.py` |
| `EXTERNAL_CONTRACT_VERSION` | `1.0.0` in `src/agentsec/external_evidence/contract.py` |
| Tool PDP | `CONTROL_ID = "CTRL-MCP-001"` in `src/agentsec/mcp/authorize.py` |
| `EXECUTION_MODE` | `LIVE` in `src/agentsec/experiment.py`. That is `agentsec.execution.mode`, not `agentsec.testbed.mode`. |
| Working tree | Untracked `docs/architecture/`, `docs/plans/`. Tracked product files were not modified by this review. |
| Enabled saved searches | 0. No `disabled = 0` and no `enableSched = 1` under `splunk_app/`. |
| Disabled detector stanza | 1: `AgentSec - MCP Execution After Authorization Deny` |
| Placeholder stanzas | 2: `Q-RUN`, `Q-DENY`. Both `disabled = 1`. Descriptions say PLACEHOLDER and not Splunk-validated in Phase 2. |

Reality is **MIXED**. The predicate, the contrasting specimens, and the disabled detector exist. Nothing is an enabled operational detector. A SPL file is not one.

Architecture that this review confirmed in source, not only in the design:

- CTRL-MCP-001 is the tool allow-list decision in `authorize_tool`. Vulnerable profile and overlay hits return ALLOW with a `vulnerable_profile_fail_open:` reason. Defended ungranted tools return DENY `tool_not_granted`.
- Splunk is downstream. The saved-search description says Splunk does not enforce authorization.
- Scanner sourcetype `agentsec:scanner:finding` and garak sourcetype `agentsec:external:evaluation` are separate. This review measured 0 runtime `agentsec.run.id` values on both.

## 3. Detection artifact inventory

| Artifact | Class | Basis |
|----------|--------|--------|
| `DET-MCP-001.spl` and the matching saved search | DISABLED_DETECTOR | `disabled = 1`, `enableSched = 0`. Same SPL body. Not enabled. |
| `DET-MCP-001-POSITIVE-CONTROL.spl` | SIMULATED_POSITIVE | `makeresults`, `evidence_class=SIMULATED`. Executed in this review: 1 row. |
| `DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl`, `DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl`, `Q-MCP-AFTER-DENY-POSITIVE-CONTROL.spl`, `Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl` | SIMULATED_POSITIVE | `makeresults` files. Not executed in this review. Not indexed attacks. |
| `Q-RUN`, `Q-DENY` | PLACEHOLDER | Disabled saved searches. Not detectors. |
| `Q-MCP-AFTER-DENY.spl` | THREAT_HUNT | Run token, includes completed and failed. Not a detector. Not executed here. |
| `Q-LLM-AFTER-DENY.spl` | THREAT_HUNT | Prompt-injection hunt. Not this teaching case. Not executed here. |
| `Q-L9-DETECTION-CANDIDATE.spl` | CANDIDATE_DETECTION | Status text `DETECTION CANDIDATE — NOT INSTALLED`. Scope mismatch and `mcp.started`. Not installed. |
| `Q-L10-DETECTION-CANDIDATE.spl` | CANDIDATE_DETECTION | Status text `DETECTION CANDIDATE — NOT INSTALLED`. Goal OBSERVE and `mcp.completed` by run id only. Not installed. |
| `Q-INCIDENT-*.spl` (L6) | INVESTIGATION_QUERY | Blue-team hunt. Not a detector. |
| `Q-BRIDGE-*.spl` | TEACHING_QUERY | Defender Bridge investigation. Prior re-review: REPLAY_VALIDATED for that workshop. Not a detector. |
| Other `Q-*.spl` lab hunts | INVESTIGATION_QUERY | Not detectors because they are not packaged, enabled, or validated as detections. |
| Tests that read `DET-MCP-001.spl` | File assertions | They check the file and that the saved search stays disabled. They do not dispatch the search. |

Candidate detection queries, using the files that label themselves NOT INSTALLED: **2**. Hunt queries are not counted as detectors.

There is no VALIDATED_POSITIVE indexed specimen for same-tool DENY then start. There is no DEPRECATED detector stanza.

## 4. DET-MCP-001 semantics

The design hypothesis is: CTRL-MCP-001 DENY for a run and tool, and a later `agentsec.mcp.started` for that same run and tool, produce a candidate finding.

The SPL in `learning/level_1/LAB-MCP-001/searches/DET-MCP-001.spl` does the following:

- It keeps `event.name` of `agentsec.control.decision` or `agentsec.mcp.started`.
- It collapses multivalue fields with `mvindex(mvdedup(...),0)` before comparison. Fields include `agentsec.run.id`, `gen_ai.tool.name`, `event.name`, `agentsec.control.decision`, `agentsec.sequence`, and `agentsec.control.id`.
- `is_deny` is true only when the event is a control decision and the decision is DENY. **It does not test `agentsec.control.id`.**
- `is_started` is true for `agentsec.mcp.started`.
- `eventstats` groups by `run_id` and `tool`. It takes the minimum DENY sequence and copies control id and other fields from DENY rows onto the group.
- It keeps start rows where `has_deny=1` and `sequence>deny_sequence`.
- It then sets `decision="DENY"` on the output. That is a label copied from the group, not a field that arrived on the start event.

What that implements: same run, same tool, start sequence greater than the earliest DENY sequence for that pair, any control's DENY.

What it does not implement: a filter that the DENY was CTRL-MCP-001. The saved-search description claims CTRL-MCP-001. The SPL does not enforce the description.

`mcp.started` is not required to carry `agentsec.control.id`. The copy happens in `eventstats`. That part of the design is right.

The `.spl` file has no `earliest=`. The saved search sets `dispatch.earliest_time = -24h` and `dispatch.latest_time = now`. This review dispatched the file body with `earliest=0`. It did not dispatch the scheduled `-24h` window.

## 5. Correlation assessment

Primary key the shipped predicate actually uses: `agentsec.run.id` plus `gen_ai.tool.name`.

Same-run alone is not enough. This review built the design's broad candidate: CTRL-MCP-001 DENY and any `agentsec.mcp.started` in the same run, no tool key and no sequence test. It matched 2 RETEST runs and 2 start rows. The shipped predicate matched 0 rows.

Those two runs, MEASURED:

| Run | Mode | DENY tool | DENY sequence | Start tool | Minimum start sequence |
|-----|------|-----------|---------------|------------|------------------------|
| `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` | RETEST | `lookup_customer_tier` | 9 | `lookup_policy` | 4 |
| `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` | RETEST | `lookup_customer_tier` | 9 | `lookup_policy` | 5 |

For `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` the decision and start rows were:

| Sequence | Event | Control id | Decision | Tool |
|----------|--------|------------|----------|------|
| 3 | `agentsec.control.decision` | CTRL-MCP-001 | ALLOW | `lookup_policy` |
| 4 | `agentsec.mcp.started` | (absent in the table) | | `lookup_policy` |
| 6 | `agentsec.control.decision` | CTRL-MCP-RESULT-001 | OBSERVE | `lookup_policy` |
| 9 | `agentsec.control.decision` | CTRL-MCP-001 | DENY | `lookup_customer_tier` |

A synthetic pair, DENY `tool_a` then start `tool_b`, run through the same `eventstats by run_id, tool` predicate, returned 0 rows. The shipped predicate distinguishes DENY(A) then START(B) from DENY(A) then START(A). The broad candidate does not.

`eventstats` uses `latest()` for the copied control id and `min()` for the DENY sequence. If one run and tool had two DENY rows, those two functions could describe different DENY rows. This review did not find a same-tool DENY-then-start at all, so that divergence was not observed. It stays a code possibility, not a measured false positive.

Secondary keys: `agentsec.sequence` for order, `agentsec.testbed.mode` for the specimen label after dedup, `trace_id` only as output context.

## 6. Temporal ordering assessment

Ordering is required for a claim of execution after denial.

The predicate uses `agentsec.sequence`, which `src/agentsec/events.py` sets in `_base_event` by incrementing `RunContext.next_sequence()`. It does not use `_time`.

A synthetic same-tool pair with start sequence 3 and DENY sequence 4 returned 0 rows. START then DENY of the same tool does not match.

On the index, runs that contain a CTRL-MCP-001 DENY and any start had `runs_same_tool_after=0`, `runs_same_tool_before=0`, and `runs_same_tool_equal=0`. The only overlap was a different tool (`runs_with_different_tool=2`, mode RETEST).

Among control-decision and `mcp.started` events, sorting by run and sequence and comparing `_time` to the previous event in that run found 0 inversions (a later sequence with an earlier `_time`). Equal timestamps were not separately counted. Sequence remains the predicate. `_time` is display context.

This is not a missing field. `agentsec.sequence` exists. Calling it invented would be wrong.

## 7. Primary ATTACK assessment

CTRL-MCP-001 decisions on this index, `earliest=0`, after `mvdedup` of mode, decision, and reason class. Indexed rows equaled distinct raw in every row below.

| Mode | Decision | Reason class | Rows | Runs |
|------|----------|--------------|------|------|
| ATTACK | ALLOW | `vulnerable_profile_fail_open` | 50 | 50 |
| ATTACK | ALLOW | `tool_granted` | 10 | 10 |
| ATTACK | ERROR | other | 8 | 8 |
| BASELINE | ALLOW | `tool_granted` | 16 | 16 |
| BASELINE | ERROR | other | 1 | 1 |
| RETEST | ALLOW | `tool_granted` | 8 | 8 |
| RETEST | DENY | `tool_not_granted` | 46 | 46 |
| RETEST | DENY | `scope_not_granted` | 1 | 1 |
| RETEST | DENY | `resource_not_granted` | 1 | 1 |

There is no CTRL-MCP-001 DENY in ATTACK or BASELINE on this index.

Fail-open ALLOW on ATTACK, same run and tool, later `mcp.started`: 50 runs and 50 start rows. Tools in that result: `lookup_customer_tier` and `lookup_policy`. Every measured fail-open ALLOW row has a later start of that tool.

`authorize_tool` returns that ALLOW when the profile is vulnerable, or when an overlay hits, and the reason starts with `vulnerable_profile_fail_open:`. The handler is then allowed to run. That is the principal vulnerable path: **ALLOW → START**.

ERROR → START was not separately counted. Eight ATTACK ERROR rows exist. They are not the bulk of the ATTACK decisions.

**DET-MCP-001 detects the primary ATTACK: NO.**

The search returned 0 rows with `earliest=0`. ATTACK never records the DENY this predicate requires. Silence means the attack took the ALLOW path. It does not mean the attack was stopped.

## 8. Failed-detection teaching pattern

The lesson "a detection can be logically correct and still miss the attack you thought it covered" is supported.

- The synthetic positive returns the DENY-then-start row. The predicate can match that shape.
- The indexed ATTACK shape is fail-open ALLOW then start. The predicate is specified to ignore ALLOW. The SPL comments and `DET-MCP-001.md` already say it does not alert on vulnerable fail-open ALLOW.
- This review measured both sides. The miss is demonstrated, not hypothetical.

**FAILED-DETECTION TEACHING PATTERN = VALID.**

Do not change the attack so the detector fires. Do not add a fabricated DENY-then-start event to the index.

## 9. Positive evidence assessment

| Specimen | Class |
|----------|--------|
| Indexed same run, same tool, CTRL-MCP-001 DENY, later `agentsec.mcp.started` | NONE |
| `DET-MCP-001-POSITIVE-CONTROL.spl` | MAKERESULTS_ONLY |

This review ran the positive-control search in Splunk. Result: 1 row, `run_id=simulated-det-mcp-001-0001`, `evidence_class=SIMULATED`.

Classification: **LOGIC TESTED WITH SYNTHETIC SPL INPUT**.

Not SCENARIO VALIDATED. Not a live attack. Not an indexed replay of a handler run.

## 10. ATTACK / RETEST / BASELINE results

Shipped `DET-MCP-001.spl` with `earliest=0`:

| Specimen | Events present | Detector rows | Result |
|----------|----------------|---------------|--------|
| ATTACK | 913 indexed rows, 103 runs | 0 | NO_MATCH |
| RETEST | 633 indexed rows, 85 runs | 0 | NO_MATCH |
| BASELINE | 259 indexed rows, 28 runs | 0 | NO_MATCH |

`stats by mode` on an empty detector result returns no mode rows. The total `stats count` returned `rows=0`. The specimen counts above show the modes exist, so the zero is a non-match, not an empty index.

Broad candidate (CTRL-MCP-001 DENY and any start, same run only):

| Specimen | Result |
|----------|--------|
| ATTACK | NO_MATCH |
| RETEST | MATCH, 2 runs, both different-tool |
| BASELINE | NO_MATCH |

RETEST therefore still shows attempt evidence: 48 CTRL-MCP-001 DENY rows. It does not show same-tool execution after that DENY. A non-match is not "RETEST is safe."

BASELINE non-match is "this predicate did not flag the available baseline rows." It is not a false-positive rate.

## 11. Detection maturity

The ladder fits if the gates stay evidentiary. This review adopts it. A query is not a validated detection. A candidate is not an enabled detector. An ATTACK match would not be universal detection. A BASELINE non-match is not an acceptable false-positive rate.

DET-MCP-001 today:

| Stage | Held? |
|-------|--------|
| OBSERVATION | Yes. The index has the decision and start events. |
| HYPOTHESIS | Yes, in the saved-search description and `DET-MCP-001.md`. The description is narrower than the SPL (it names CTRL-MCP-001; the SPL does not filter it). |
| CANDIDATE_DETECTION | Yes. The SPL is written and disabled. |
| LOGIC_VALIDATED | Yes, for the synthetic positive executed in this review, and for the synthetic non-matches (different tool; start before DENY). |
| SCENARIO_VALIDATED | No. No indexed positive. The indexed result is a bounded non-match. |
| OPERATIONALLY_VALIDATED | No. Disabled, `enableSched=0`, window `-24h` not shown to cover this corpus. |
| ENABLED_DETECTOR | No. |

The design's ceiling, LOGIC VALIDATED, matches this review. Do not call the exercise SCENARIO VALIDATED, OPERATIONALLY VALIDATED, PRODUCTION READY, or CERTIFIED.

`DET-MCP-001.md` still says "one operational detection." That sentence is not true of a disabled search with a simulated positive. The design correctly refuses the operational claim. The workshop must not copy the lab page's wording.

## 12. False positive analysis

| Vector | Class | What was checked |
|--------|--------|------------------|
| DENY(tool A) and START(tool B), same run | MEASURED | 2 RETEST runs. Broad candidate matches. Shipped predicate does not. On the fully listed run, the start is before the DENY and follows an ALLOW of the other tool. |
| Same-tool START then DENY | Not on this index. Synthetic non-match MEASURED. | `runs_same_tool_before=0`. Synthetic reverse returned 0. |
| Multivalue fields | MEASURED, partial | Raw `mvcount` reached 2 for `gen_ai.tool.name` and `agentsec.sequence`, and 3 for `agentsec.testbed.mode`, on control-decision and `mcp.started` events. After `mvdedup`, the groups this review's distinct-count search returned were 1. That search did not account for every control-decision event (176 of 303 appeared in the deduped group). Do not describe the repeats as extra executions. The SPL already dedups before `eventstats`. |
| Duplicate indexed runtime events | Not shown for these rows | Specimen search: indexed rows equaled `dc(_raw)` for ATTACK 913, BASELINE 259, RETEST 633. |
| Duplicate external indexing | MEASURED, not this predicate | Garak 8 indexed / 1 distinct raw / 0 run ids. Scanner 27 / 6 / 0. Do not join them into DET-MCP-001. |
| Other controls' DENY plus same-tool start | SUPPORTED by code and by DENY rows; not a measured match | DENY rows with a tool: CTRL-MCP-001 RETEST 48; CTRL-GOAL-INTEGRITY-001 RETEST 5 and BASELINE 1; CTRL-DELEGATION-001 RETEST 1. CTRL-INPUT-001 DENY rows have no tool (ATTACK 2, RETEST 3). A search for non-CTRL-MCP-001 DENY then later same-tool `mcp.started` returned 0 rows. |
| `makeresults` mistaken for a live hit | OBSERVED | The positive control is labeled `SIMULATED`. It is not an indexed run. |
| Replayed lab history | OBSERVED | These rows are existing lab specimens. This review did not generate them. |
| Missing completion | Not a false positive for this predicate | The predicate does not require `mcp.completed`. A completion is not the finding. |

Administrative workflows, production policy transitions, and clock skew beyond the ordering check above were not evidenced. They are not taught as measured platform behavior.

## 13. False negative analysis

| Miss | Class |
|------|--------|
| Fail-open ALLOW then same-tool start | DEMONSTRATED MISS. 50 ATTACK runs. The predicate requires DENY. |
| Requiring `agentsec.control.id` on `mcp.started` | DEMONSTRATED by the emitter. `mcp_started()` does not set that field. The known run's start row had no control id in the table. A filter on every event drops the start. This is the Defender Bridge lesson, still true. |
| Different tool in the same run | DEMONSTRATED non-match of the tuned predicate. In scope for a run-id-only hunt. Out of scope once the hypothesis is same-tool. |
| `-24h` saved-search window | CONFIGURED gap. This review did not dispatch that window, and did not measure `_time` bounds. Do not claim the window is empty without that dispatch. The file used here had `earliest=0` added for the export. |
| ERROR then start | SUPPORTED POSSIBILITY. 8 ATTACK and 1 BASELINE ERROR decisions exist. Pairing them with a later start was not counted. The predicate ignores ERROR. |
| Goal or delegation DENY then same-tool start | Not observed (0 rows). The SPL would count it, because it does not filter control id. |
| Ingest drops `mcp.started` while a handler runs | SUPPORTED POSSIBILITY already written on `DET-MCP-001.md`. Not re-demonstrated by comparing a local event file to Splunk in this review. |
| Renamed tool, empty tool, or execution with no `mcp.started` | HYPOTHETICAL until a row shows it. `mcp_started()` always sets `gen_ai.tool.name` and `agentsec.run.id` when it runs. |

## 14. Telemetry sufficiency

Names are the emitted names. `agentsec.event.name` and `agentsec.tool.name` are not emitted.

| Field | Class | Emitter fact |
|-------|--------|----------------|
| `agentsec.run.id` | REQUIRED, CORRELATION | `_base_event` |
| `gen_ai.tool.name` | REQUIRED, CORRELATION | Set on `mcp_started`. Set on a control decision only when `tool_name` is passed. |
| `event.name` | REQUIRED | `agentsec.control.decision` or `agentsec.mcp.started` |
| `agentsec.event.name` | NOT_AVAILABLE | |
| `agentsec.sequence` | REQUIRED, CORRELATION | `_base_event`, monotonic in one run context |
| `agentsec.control.id` | REQUIRED on the decision for the intended hypothesis. NOT_AVAILABLE on `mcp.started`. The shipped SPL copies it and does not filter it. | `control_decision` sets it. `mcp_started` does not. |
| `agentsec.control.decision` | REQUIRED on the decision. NOT_AVAILABLE on `mcp.started`. | |
| `agentsec.control.reason` | CONTEXT | Fail-open versus `tool_not_granted`, `scope_not_granted`, `resource_not_granted` |
| `agentsec.testbed.mode` | CONTEXT | ATTACK, RETEST, BASELINE. Repeated values; dedup before grouping. |
| `_time` | CONTEXT | Not the predicate. 0 sequence-versus-time inversions on the compared pairs. |
| `agentsec.operation.executed` | CONTEXT | Control decisions set it false. `mcp.started` sets it true. Not used by DET-MCP-001. |
| `operation.executed` | NOT_AVAILABLE | The field is prefixed. |
| `agentsec.operation.outcome` | CONTEXT on DENY and ERROR decisions only | Set to `prevented` when the decision is DENY or ERROR. Not set by `mcp_started`. |
| `operation.outcome` | NOT_AVAILABLE | |

**Telemetry sufficiency: PARTIAL.**

The correlation can be taught without a schema change. The decision event and the start event do not carry the same fields. `agentsec.operation.outcome=prevented` is not proof that a later start is absent. That is enough to teach, and not enough to pretend the two planes are one record.

## 15. Authorization versus execution

`control_decision` sets `agentsec.operation.executed` to false on every decision, and sets `agentsec.operation.outcome` to `prevented` only when the decision is DENY or ERROR. That describes the decision event.

On `0ab10594-a7fc-48b6-81bf-4cbca54a64c6`, a CTRL-MCP-001 DENY at sequence 9 coexists with an earlier `mcp.started` for a different tool. The DENY event's `executed=false` does not describe that start.

ALLOW does not prove execution. Execution evidence for this predicate is `event.name=agentsec.mcp.started`. The fail-open rows are the example of ALLOW that is then followed by a start. An ALLOW with no start would be NOT OBSERVED for execution, not proof the handler was incapable of running.

`mcp_started` sets `agentsec.operation.executed` true and does not set `agentsec.control.id`, `agentsec.control.decision`, or `agentsec.operation.outcome`.

The design preserves this split. That part is accepted.

## 16. Detection versus incident

The design states, and the workshop must keep:

- A hunt is not a detection.
- A query is not a detector.
- A match is not an incident.
- A finding is not an incident.
- DENY is not safe.
- No match is not safe.
- ALLOW is not execution.
- A RETEST non-match is not universal safety.
- A BASELINE non-match is not a false-positive rate.
- An ATTACK match would not be universal detection. This index does not provide that match.

The coverage statement in the design asks for justified and unjustified conclusions, including NOT OBSERVED, NOT PROVEN, and CORRELATION NOT ESTABLISHED. That is the right learner artifact.

No incident severity engine is proposed. The package label HIGH on DET-MCP-001 must stay a package label.

## 17. External evidence boundary

MEASURED this review:

| Sourcetype | Indexed rows | Distinct raw | Distinct `agentsec.run.id` |
|------------|--------------|--------------|----------------------------|
| `agentsec:external:evaluation` | 8 | 1 | 0 |
| `agentsec:scanner:finding` | 27 | 6 | 0 |

Scanner HIGH is not DENY. Zero scanner rows would not be trust. Garak PASS is not safe. Garak FAIL is not DENY. A shared hash or identity string is not a runtime run id. Neither plane may change a CTRL-MCP-001 decision. The design holds this boundary. This review accepts it.

## 18. Workshop pedagogy

The proposed path is real detection engineering if the two factual corrections are in the text the learner sees:

behavior, broad search with no supplied run id, discovery of the two RETEST runs, proof that they are a different tool and that the start is not after that DENY, same-tool and sequence tuning, an explicit control-id constraint the shipped file does not have, ATTACK then RETEST then BASELINE, the fail-open explanation, false-positive and false-negative notes, one tuning gain and one tuning loss, coverage statement.

That is not SPL copying, provided Path B does not open with the finished conclusion or with a claim that zero rows means the system is secure.

The design's tuning warning is right: do not add filters until BASELINE is empty. BASELINE is already empty for this predicate. The interesting comparison is the broad RETEST match versus the tuned non-match, and the ATTACK non-match versus the visible fail-open ALLOW.

## 19. Learner modes

One workshop can carry three modes. Three workshops are not required.

Beginner: the hypothesis in words, the field list, a partial search that stops before `eventstats`, and an empty evidence matrix. Hint: same run is not the same tool, and sequence 4 is not after sequence 9.

Practitioner: write the broad search, tune it, compare the three modes, explain the two RETEST runs and the fail-open miss, write the coverage statement.

Expert: derive the fields from the behavior, reject `operation.outcome=prevented` as proof, separate the simulated row from the index, and list what would still be required before `disabled=0`.

Do not give any mode a filled coverage statement with this index's counts on the first screen.

## 20. Splunk progression

This follows the Defender Bridge. The learner does not start with a run id.

Order: security behavior, broad search, the runs that appear, correlation, edit the SPL, compare ATTACK / RETEST / BASELINE, explain the miss, bounded coverage statement.

Avoid a second product search language. Reuse `earliest=0` on this lab index, `mvindex(mvdedup(...),0)`, and the rule that control id is not required on `mcp.started`. Add the control-id test only on the decision side, and say the shipped file does not do that yet.

Placement stays a REPLAY checkpoint after L6. Level ids stay L0–L10. Not a LIVE lab.

## 21. Detection coverage statement

The design's statement should become a standard learner artifact for this workshop. Add two lines the current list implies but should say outright:

- The positive row, if any, is SIMULATED or indexed. Say which.
- Operational validation is still required before enablement.

Required answers otherwise match the design: hypothesis, behavior detected, behavior not detected, telemetry, correlation, scenarios, what matched, what did not, false positives, false negatives, gaps, claim strength, what is proven, what is not proven.

A justified statement on today's index: the tuned predicate did not match ATTACK, RETEST, or BASELINE; the synthetic control matched one simulated row; ATTACK fail-open ALLOW then start is outside the predicate. An unjustified statement: the system is secure, the attack was detected, RETEST proved safety, or BASELINE proved a low false-positive rate.

## 22. DET-MCP-001 disposition

**KEEP DISABLED — GOOD TEACHING CANDIDATE.**

It is the right specimen because the same-tool and sequence logic is real, the synthetic positive works, and the indexed ATTACK miss is the lesson. It is the wrong object to enable. It is not unsuitable, and it should not be deprecated in this phase.

Do not "fix" the missing control-id filter in this phase. Teach it as a gap between the description and the SPL. A future logic change would be its own gate.

A detector aimed at fail-open ALLOW then start is a **FUTURE CANDIDATE** only. It is not designed here and not implemented here. ALLOW then start is also the normal BASELINE path (`tool_granted`, 16 runs), so that future candidate would need a reason or profile constraint and would still not be an authorization control.

## 23. Operationalization gap

Still required before any enablement, none of it done here:

- An indexed positive scenario, or an explicit decision that enablement is impossible without one.
- Repeatability on unchanged data.
- A false-positive note tied to a real row (the two RETEST runs are the start of that note for the broad query, not for the tuned one).
- A false-negative note that includes the 50 fail-open runs.
- A chosen schedule, lookback, and correlation window. `-24h` is configured and was not shown to be the teaching window.
- Dedup that survives repeated field values, and a rule for one finding per run and tool.
- Throttling, finding fields that cannot be read as ALLOW or DENY, an owner, a severity rationale that is not an incident engine, a runbook, rollback to `disabled=1`, and a way to notice a failed search.
- Tests that dispatch the predicate, not only tests that read the file.

Until that gate: do not enable.

## 24. Framework semantics

`docs/AGENTSEC_DETECTION_ENGINEERING_CURRICULUM.md` exists. This review did not re-validate any technique identifier against an external catalog. The design's rule stands: OWASP, MITRE ATLAS, MAESTRO, and NIST language, if used, is EDUCATIONAL MAPPING. Unverified identifiers stay NEEDS_EXTERNAL_VALIDATION. No certification and no compliance claim.

`agentsec.technique.id` is optional on events when a context sets it. This predicate does not depend on it.

## 25. Scope guardrails

This review does not authorize:

an enabled detector, a `savedsearches.conf` edit, a new saved search, SOAR, automated containment, scanner-to-deny, garak-to-deny, a new attack, a new LIVE lab, a new scanner, a new evaluation harness, AI-BOM, production IAM, OAuth, PKI, A2A authentication, HITL, a schema bump, an ExternalEvidence bump, or RC3.

CTRL-MCP-001, runtime telemetry, schema 1.9.0, and ExternalEvidence 1.0.0 were read and not modified. RC1 and RC2 tags were not moved.

## 26. Findings

BLOCKER 0. HIGH 0. MEDIUM 2. LOW 2.

The ATTACK miss is not a defect. It is the teaching point, and the design already points at it.

### MEDIUM-01 — The design says the shipped SPL constrains CTRL-MCP-001. It does not.

DOCUMENTED. `DET-MCP-001.spl` sets `is_deny` from `event.name=agentsec.control.decision` and `decision=DENY` only. `savedsearches.conf` uses that same search. The design's tuning section says the control-id constraint "is the existing DET-MCP-001 shape."

MEASURED context: goal-integrity and delegation DENY events include a tool name. A later same-tool start after those DENY rows was 0, so this index did not show the false positive. The workshop must not tell learners the file already filters the control id. The learner's tuned predicate should add that test on the decision side. Do not patch the SPL in the workshop phase unless a later gate says so.

### MEDIUM-02 — The cited false positive is not "start after deny."

MEASURED. The design tells the learner that run-id-only correlation flags `lookup_policy` after a DENY of `lookup_customer_tier` on `0ab10594-a7fc-48b6-81bf-4cbca54a64c6`. On that run the ALLOW and the start of `lookup_policy` are sequences 3 and 4. The DENY of `lookup_customer_tier` is sequence 9. A second RETEST run has the same tool split, with start sequence 5 and DENY sequence 9. The design names only the first run.

The workshop has to say both runs, and that the start is earlier than the DENY. The broad candidate still matches because it ignores tool and sequence. That is a stronger lesson, and it is not the sentence currently in the design.

### LOW-01 — The design file is not in commit `8ec6f76`.

MEASURED. `git status` shows `docs/architecture/` untracked. The product commit under review does not contain the design. This review compared the working-tree file to that commit. Committing it was not requested.

### LOW-02 — `DET-MCP-001.md` calls the disabled search an operational detection.

DOCUMENTED. The page says it is one operational detection of an invariant violation. The saved search is disabled. The positive control is simulated. The design's maturity section does not repeat the operational claim. The workshop must not.

## 27. Recommended implementation

After the two design corrections, and only then: **one REPLAY detection-engineering workshop** after L6.

The learner starts from the behavior, with no run id. They write a broad search, find the two RETEST runs, see the tool split and the sequence order, tune to same run, same tool, later sequence, and CTRL-MCP-001 on the decision only, compare ATTACK, RETEST, and BASELINE, and explain why the fail-open ATTACK still does not match. They mark the positive control as simulated. They write a coverage statement whose last principle is: detection coverage is a claim that must be proven. They do not conclude that the system is secure.

Reuse the existing index, `DET-MCP-001.spl` as the reference that omits the control-id filter, and the positive-control file as a labeled simulation. Create no saved search. Enable no detector. Change no runtime, schema, contract, attack, or LIVE lab.

## 28. Final recommendation

**CONDITIONAL GO — DESIGN REMEDIATION REQUIRED**

The remediation is a correction of the design text: the shipped SPL does not filter CTRL-MCP-001, and the measured broad-candidate runs start `lookup_policy` before they deny `lookup_customer_tier`. There are two such runs. The workshop concept, the maturity ceiling, and the decision to keep DET-MCP-001 disabled stay as recommended.

Do not implement the workshop until that text is corrected and explicitly authorized.
