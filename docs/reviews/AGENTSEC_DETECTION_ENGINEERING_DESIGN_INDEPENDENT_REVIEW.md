# AgentSec detection engineering design — independent review

**Date:** 2026-09-29
**Requested design baseline:** `8ec6f76f799b925d483f3ebe77f56a929a8dec3d`
**Local HEAD:** `e124ce92b8f4579e0ddb160ebc2ad917f91ba630`
**origin/develop:** `8ec6f76f799b925d483f3ebe77f56a929a8dec3d`
**Mode:** Review only. This pass did not edit the workshop, DET-MCP-001, `savedsearches.conf`, runtime, schema, or ExternalEvidence.

The design file is not in `8ec6f76`. It was added, with the corrections below, in local commit `e124ce9`, which is not on `origin/develop`. This review read that file and re-checked the index. It did not treat the design's prose as measurement.

Splunk authentication was read from `.env` inside the query process and was not written here. No certificate and no cryptographic code were part of this review.

## 1. Executive summary

The corrected design matches the shipped SPL and the indexed order. `DET-MCP-001.spl` keys on the same run and the same tool, and it keeps a start only when `agentsec.sequence` is greater than the earliest DENY sequence. It does not require `agentsec.control.id=CTRL-MCP-001`. The design now says that. The control id is copied by `eventstats`.

On this index the shipped search returns 0 rows. The principal ATTACK path is fail-open ALLOW then `agentsec.mcp.started`: 50 ATTACK runs, 50 later starts. A run-id-only candidate matches two RETEST runs that deny `lookup_customer_tier` at sequence 9 and start `lookup_policy` earlier. The same-tool predicate matches neither. The only positive row executed here is `makeresults` labeled `SIMULATED`.

That is a valid failed-detection lesson. DET-MCP-001 stays disabled. Maturity is LOGIC VALIDATED, not scenario validated and not operational.

Local `develop` already contains one REPLAY workshop for this lesson (`e124ce9`). This review does not authorize a second workshop, an enablement, or a push.

**GO — the corrected design supports that one workshop. Do not build it again.**

## 2. Repository detection reality

| Check | Result |
|-------|--------|
| Local HEAD | `e124ce9` `feat(academy): add a replay detection engineering workshop after L6` |
| `origin/develop` | `8ec6f76` |
| `8ec6f76` ancestor of HEAD | yes |
| Defender Bridge remediation `978f91b` ancestor | yes |
| `v1.0.0-rc1` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| `v1.0.0-rc2` | `1be214b92f840f843aaf27fb2b9536f764dd7126` |
| `v1.0.0-rc3` | no tag |
| Schema | `SCHEMA_VERSION = "1.9.0"` |
| ExternalEvidence | `EXTERNAL_CONTRACT_VERSION = "1.0.0"` |
| Tool PDP | `CONTROL_ID = "CTRL-MCP-001"` |
| Enabled saved searches | 0. No `disabled = 0`. No `enableSched = 1`. |
| Disabled detector | 1. `AgentSec - MCP Execution After Authorization Deny`, `disabled = 1`, `enableSched = 0` |
| Placeholders | `Q-RUN` and `Q-DENY`, both `disabled = 1` |
| Working tree | Untracked `docs/plans/` only, before this review file was rewritten |

Reality is **MIXED**. The predicate and the contrasting specimens exist. Nothing is an enabled detector.

CTRL-MCP-001 remains the tool allow-list in `authorize_tool`. Splunk remains downstream. The saved-search description says Splunk does not enforce authorization. Scanner and garak stay on their own sourcetypes.

## 3. Detection artifact inventory

| Artifact | Class |
|----------|--------|
| `DET-MCP-001.spl` and its saved-search stanza | DISABLED_DETECTOR |
| `DET-MCP-001-POSITIVE-CONTROL.spl` | SIMULATED_POSITIVE. Executed this review: 1 row, `evidence_class=SIMULATED`. |
| Scope, resource, and hunt `makeresults` controls | SIMULATED_POSITIVE. Not executed this review. |
| `Q-RUN`, `Q-DENY` | PLACEHOLDER. Not detectors. |
| `Q-MCP-AFTER-DENY.spl`, `Q-LLM-AFTER-DENY.spl` | THREAT_HUNT |
| `Q-L9-DETECTION-CANDIDATE.spl`, `Q-L10-DETECTION-CANDIDATE.spl` | CANDIDATE_DETECTION. Text says NOT INSTALLED. |
| L6 `Q-INCIDENT-*.spl` | INVESTIGATION_QUERY |
| Defender Bridge `Q-BRIDGE-*.spl` | TEACHING_QUERY. Prior bridge re-review validated that workshop as investigation. Not a detector. |
| `Q-DET-EVENTS.spl`, `Q-DET-BROAD.spl`, `Q-DET-TUNED.spl` | TEACHING_QUERY in the local workshop commit. Not saved searches. Not enabled detectors. |
| Other lab `Q-*.spl` | INVESTIGATION_QUERY |
| Tests that read `DET-MCP-001.spl` | File assertions. They do not dispatch the search. |

No VALIDATED_POSITIVE indexed specimen. No DEPRECATED detector stanza. Candidate queries that label themselves NOT INSTALLED: **2**.

## 4. DET-MCP-001 semantics

`is_deny` is:

`event_name="agentsec.control.decision" AND decision="DENY"`

There is no `control_id="CTRL-MCP-001"` term. `eventstats` groups by `run_id` and `tool`, takes `min()` of the DENY sequence, and copies `control_id` with `latest()`. The keep clause is `has_deny=1 AND is_started=1 AND sequence>deny_sequence`. Output then sets `decision="DENY"` as a label.

What the SPL expresses: same run, same tool, start sequence after the earliest DENY sequence, any control's DENY.

What the description expresses: CTRL-MCP-001 denied that tool. The description is narrower than the SPL. The design's correction section now says this. That claim is accurate.

The `.spl` file has no `earliest=`. The saved search window is `-24h` to `now`. This review dispatched the file body with `earliest=0`. It did not dispatch the `-24h` window.

Multivalue fields are collapsed with `mvindex(mvdedup(...),0)` before the predicate. This review did not re-count `mvcount`. The SPL's dedup is present in the file.

## 5. Correlation assessment

Shipped primary key: `agentsec.run.id` plus `gen_ai.tool.name`.

A broad candidate that requires a CTRL-MCP-001 DENY and any `agentsec.mcp.started` in the same run, with no tool key and no sequence test, returned two RETEST runs:

| Run | DENY tool | DENY sequence | Start tool | Minimum start sequence |
|-----|-----------|---------------|------------|------------------------|
| `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` | `lookup_customer_tier` | 9 | `lookup_policy` | 4 |
| `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` | `lookup_customer_tier` | 9 | `lookup_policy` | 5 |

The shipped search returned 0 rows, so it does not match DENY(tool A) plus START(tool B). The broad candidate does. The design now says the start is not after the customer-tier DENY. That matches these sequences.

`min()` and `latest()` can describe different DENY rows if one run and tool has two DENYs. No same-tool DENY-then-start row exists here, so that split was not observed.

## 6. Temporal ordering assessment

Order is required for "after denial." The predicate uses `agentsec.sequence`, which `_base_event` sets by incrementing `RunContext.next_sequence()`. It does not use `_time`. The field is emitted. It is not invented.

On both measured mixed-tool runs the `lookup_policy` start sequence is lower than the `lookup_customer_tier` DENY sequence. A later start of the denied tool was not present. This review did not re-count `_time` inversions. Sequence remains the ordering field the SPL actually uses.

## 7. Primary ATTACK assessment

CTRL-MCP-001 decisions, `earliest=0`, after dedup of mode. This review's export:

| Mode | Decision | Reason class | Rows | Runs |
|------|----------|--------------|------|------|
| ATTACK | ALLOW | fail-open prefix | 50 | 50 |
| ATTACK | ALLOW | `tool_granted` | 10 | 10 |
| ATTACK | ERROR | `malformed_arguments` | 1 | 1 |
| ATTACK | ERROR | `missing_requested_scope` | 2 | 2 |
| ATTACK | ERROR | `unknown_resource` | 1 | 1 |
| ATTACK | ERROR | `unknown_scope` | 3 | 3 |
| ATTACK | ERROR | `unknown_tool` | 1 | 1 |
| BASELINE | ALLOW | `tool_granted` | 16 | 16 |
| BASELINE | ERROR | `malformed_arguments` | 1 | 1 |
| RETEST | ALLOW | `tool_granted` | 8 | 8 |
| RETEST | DENY | `tool_not_granted` | 46 | 46 |
| RETEST | DENY | `scope_not_granted` | 1 | 1 |
| RETEST | DENY | `resource_not_granted` | 1 | 1 |

No CTRL-MCP-001 DENY in ATTACK or BASELINE. Fail-open ALLOW on ATTACK followed by a later same-tool `mcp.started`: 50 runs and 50 start rows.

**DET-MCP-001 detects the primary ATTACK: NO.**

The shipped search returned 0 rows. ATTACK does not record the DENY the predicate requires. Silence means the attack took ALLOW then start. It does not mean the attack was stopped.

## 8. Failed-detection teaching pattern

The synthetic positive returns one SIMULATED DENY-then-start row. The indexed ATTACK path is ALLOW then start. The predicate ignores ALLOW. Both sides were measured in this review.

**FAILED-DETECTION TEACHING PATTERN = VALID.**

Do not change the attack so the detector fires.

## 9. Positive evidence assessment

Indexed same-run, same-tool, CTRL-MCP-001 DENY, later `agentsec.mcp.started`: **NONE**.

`DET-MCP-001-POSITIVE-CONTROL.spl`: **MAKERESULTS_ONLY**. This review executed it. 1 row, `evidence_class=SIMULATED`.

**LOGIC TESTED WITH SYNTHETIC SPL INPUT.** Not SCENARIO VALIDATED.

## 10. ATTACK / RETEST / BASELINE results

Shipped `DET-MCP-001.spl` with `earliest=0` returned 0 rows and 0 runs. The mode table above shows ATTACK, RETEST, and BASELINE events exist, including 48 RETEST DENY rows. The zero is a non-match, not an empty index.

| Specimen | Shipped DET-MCP-001 | Broad run-id candidate |
|----------|---------------------|------------------------|
| ATTACK | NO_MATCH | NO_MATCH. No CTRL-MCP-001 DENY. |
| RETEST | NO_MATCH | MATCH. Two different-tool runs. |
| BASELINE | NO_MATCH | NO_MATCH. No CTRL-MCP-001 DENY. |

RETEST still has attempt evidence. A non-match is not universal safety. BASELINE non-match is not a false-positive rate.

## 11. Detection maturity

The ladder fits. A query is not a validated detection. A candidate is not an enabled detector. An ATTACK match would not be universal detection. A BASELINE non-match is not an acceptable false-positive rate.

| Stage | DET-MCP-001 |
|-------|-------------|
| OBSERVATION | Yes. Decision and start events are indexed. |
| HYPOTHESIS | Yes, in the description. Narrower than the SPL. |
| CANDIDATE_DETECTION | Yes. Written and disabled. |
| LOGIC_VALIDATED | Yes, for the synthetic positive executed here, and for the measured different-tool non-match. |
| SCENARIO_VALIDATED | No. No indexed positive. |
| OPERATIONALLY_VALIDATED | No. Disabled. `-24h` window not dispatched. |
| ENABLED_DETECTOR | No. |

Do not call it PRODUCTION READY, OPERATIONALLY VALIDATED, or CERTIFIED.

`DET-MCP-001.md` still says "one operational detection." That sentence is not true of a disabled search. The design's maturity section does not adopt it.

## 12. False positive analysis

| Vector | Class |
|--------|--------|
| DENY(tool A) and START(tool B), same run | MEASURED. Two RETEST runs. Broad candidate matches. Shipped predicate does not. The policy start is earlier than the customer-tier DENY. |
| Same-tool START then DENY | Not in the shipped result (0 rows). Not separately synthesized in this pass. |
| Multivalue repeats | SPL dedups before use. This pass did not re-count `mvcount`. Do not call repeats extra executions without `dc(_raw)`. |
| Duplicate runtime rows for this predicate | Not shown. The detector output is empty. |
| Duplicate external indexing | MEASURED, other sourcetypes. Garak 8 indexed / 1 distinct raw / 0 run ids. Scanner 27 / 6 / 0. Not this predicate. |
| Another control's DENY plus a later same-tool start | SUPPORTED by the SPL, because `is_deny` ignores control id. Not a measured match: the shipped search returned 0 rows. |
| `makeresults` read as a live hit | OBSERVED. The control is labeled SIMULATED. |
| Replayed lab history | OBSERVED. This review did not launch a run. |
| Missing completion | NOT a false positive. The predicate does not require `mcp.completed`. |

## 13. False negative analysis

| Miss | Class |
|------|--------|
| Fail-open ALLOW then same-tool start | DEMONSTRATED MISS. 50 ATTACK runs. |
| Requiring `agentsec.control.id` on `mcp.started` | DEMONSTRATED by `mcp_started()`. That function does not set the field. |
| Different tool in the same run | DEMONSTRATED non-match of the shipped predicate. Out of scope once the hypothesis is same-tool. |
| `-24h` saved-search window | CONFIGURED. Not dispatched this review. Do not claim the window is empty without that dispatch. |
| ERROR then start | SUPPORTED POSSIBILITY. Eight ATTACK ERROR rows exist. Pairing them with a later start was not counted. The predicate requires DENY. |
| Ingest drops `mcp.started` | SUPPORTED POSSIBILITY already written on `DET-MCP-001.md`. Not re-compared to a local event file here. |
| Renamed tool or execution with no `mcp.started` | HYPOTHETICAL until a row shows it. |

## 14. Telemetry sufficiency

| Field | Class |
|-------|--------|
| `agentsec.run.id` | REQUIRED, CORRELATION. On the base event. |
| `gen_ai.tool.name` | REQUIRED, CORRELATION. On `mcp.started`. On a decision only when a tool name is passed. |
| `event.name` | REQUIRED. |
| `agentsec.event.name` | NOT_AVAILABLE. |
| `agentsec.sequence` | REQUIRED, CORRELATION. |
| `agentsec.control.id` | REQUIRED on the decision for the intended CTRL-MCP-001 hypothesis. NOT_AVAILABLE on `mcp.started`. Not filtered by the shipped SPL. |
| `agentsec.control.decision` | REQUIRED on the decision. NOT_AVAILABLE on `mcp.started`. |
| `agentsec.control.reason` | CONTEXT. |
| `_time` | CONTEXT. Not the predicate. |
| `agentsec.operation.executed` | CONTEXT. False on every decision. True on `mcp.started`. Not used by DET-MCP-001. |
| `operation.executed` | NOT_AVAILABLE under that bare name. |
| `agentsec.operation.outcome` | CONTEXT on DENY and ERROR decisions (`prevented`). Not set by `mcp_started`. |
| `operation.outcome` | NOT_AVAILABLE under that bare name. |

**Telemetry sufficiency: PARTIAL.** The predicate can be taught without a schema change. The decision event and the start event do not carry the same fields.

## 15. Authorization versus execution

`control_decision` sets `agentsec.operation.executed` false on every decision, and sets `agentsec.operation.outcome` to `prevented` only for DENY or ERROR. That describes the decision event. It does not prove a later start is absent. The two RETEST runs contain a DENY and an earlier start of a different tool.

ALLOW does not prove execution. Execution evidence for this predicate is `event.name=agentsec.mcp.started`. The 50 fail-open rows are ALLOW followed by that start.

The design keeps detection downstream of CTRL-MCP-001. This review accepts that split.

## 16. Detection versus incident

The design and the local workshop text keep these distinctions: a query is not a detector, a match is not an incident, a finding is not an incident, DENY is not a safety verdict, no match is not a safety verdict, ALLOW is not execution, RETEST is not universal safety, and BASELINE is not a false-positive rate. The coverage page tells the learner not to conclude that the system is secure.

No incident severity engine was added. The package label HIGH remains a package label.

## 17. External evidence boundary

| Sourcetype | Indexed rows | Distinct raw | Distinct `agentsec.run.id` |
|------------|--------------|--------------|----------------------------|
| `agentsec:external:evaluation` | 8 | 1 | 0 |
| `agentsec:scanner:finding` | 27 | 6 | 0 |

Scanner HIGH is not DENY. Zero scanner rows would not be trust. Garak PASS is not safe. Garak FAIL is not DENY. A hash or identity string is not a runtime run id. Neither plane may change CTRL-MCP-001. The design holds this boundary.

## 18. Workshop pedagogy

The corrected design teaches detection engineering: hypothesis, broad search, same-run weakness, same-tool and sequence, ATTACK / RETEST / BASELINE, the fail-open miss, false positives, false negatives, tuning gain and loss, coverage statement. That is not SPL copying if Path A does not open with the finished correlation. The local workshop commit follows that shape. This review did not rebuild it.

The interesting comparison is the broad RETEST match versus the tuned non-match, and the ATTACK non-match versus the visible fail-open ALLOW. Tuning is not "add filters until BASELINE is empty."

## 19. Learner modes

One workshop is enough. Beginners get the hypothesis, field names, a partial search, and hints. Practitioners write and compare. Experts derive the fields, reject `operation.outcome=prevented` as proof, and list what enablement would still require. Three workshops are not needed.

## 20. Splunk progression

The path builds on the Defender Bridge: no supplied run id, broad search, discovered runs, correlation, comparison, bounded conclusion. Control id stays off `mcp.started`. Level ids stay L0–L10. The local checkpoint is placed after L6. It is not a LIVE lab.

## 21. Detection coverage statement

The design's statement should stay the learner artifact. It asks what was detected, what was not, what matched, what did not, what is justified, and what is not. It should keep an explicit line that a positive row is either SIMULATED or indexed, and that operational validation is still required. A match is not an incident.

## 22. DET-MCP-001 disposition

**KEEP DISABLED — GOOD TEACHING CANDIDATE.**

Same-tool order is real. The synthetic positive works. The indexed ATTACK miss is the lesson. Do not enable it. Do not patch the missing control-id filter in this review. A fail-open ALLOW-then-start detector is a **FUTURE CANDIDATE** only. ALLOW then start is also the BASELINE `tool_granted` path (16 runs), so that future candidate would need a reason or profile constraint. It is not implemented here.

## 23. Operationalization gap

Still required before enablement, and not done here: an indexed positive or an explicit decision that enablement waits for one; a repeat run; false-positive and false-negative notes tied to these rows; a chosen schedule and lookback; dedup; throttling; finding fields that are not ALLOW or DENY; an owner; a severity rationale that is not an incident engine; a runbook; rollback to `disabled = 1`; monitoring; tests that dispatch the predicate. The current `-24h` window was not shown to be the teaching window.

## 24. Framework semantics

No new technique identifier was introduced. Mapping to OWASP, MITRE ATLAS, MAESTRO, or NIST, if used in teaching, stays EDUCATIONAL MAPPING. Unverified identifiers stay NEEDS_EXTERNAL_VALIDATION. This is not certification or compliance. The predicate does not depend on `agentsec.technique.id`.

## 25. Scope guardrails

This review does not authorize an enabled detector, a `savedsearches.conf` edit, a new saved search, SOAR, containment, scanner-to-deny, garak-to-deny, a new attack, a new LIVE lab, a new scanner, a new evaluation harness, AI-BOM, production IAM, OAuth, PKI, A2A authentication, HITL, a schema bump, an ExternalEvidence bump, or RC3.

It also does not authorize a second copy of the workshop. Local commit `e124ce9` already adds one REPLAY workshop. That commit is not on `origin/develop`. This review did not push it.

## 26. Findings

BLOCKER 0. HIGH 0. MEDIUM 0. LOW 2.

The ATTACK miss is not a defect. The earlier control-id and event-order errors in the design are corrected in the file this review read.

### LOW-01 — Local develop is ahead of origin/develop

MEASURED. `origin/develop` is `8ec6f76`. Local HEAD is `e124ce9`, which adds the design, this review's previous text, and the workshop. The requested baseline commit does not contain the design file. Do not treat `8ec6f76` as the tree that holds the corrected design. Do not implement the workshop again.

### LOW-02 — `DET-MCP-001.md` still calls the disabled search operational

DOCUMENTED. The saved search is disabled. The positive control is simulated. The design does not repeat that operational claim. Teaching must not copy the lab page's sentence.

The `min()` versus `latest()` split and the `-24h` window remain documented limitations. Neither was a new observed mismatch in this dispatch.

## 27. Recommended implementation

No further build. The bounded workshop already exists locally as one REPLAY checkpoint after L6. It must stay a lesson that a plausible detection can miss fail-open ALLOW then start, and that coverage is a claim that must be proven. It must not conclude that the system is secure.

Do not enable DET-MCP-001. Do not edit `savedsearches.conf`. Do not add an attack or a LIVE lab.

## 28. Final recommendation

**GO — AUTHORIZE BOUNDED DETECTION ENGINEERING WORKSHOP**

The authorization is for the workshop that the corrected design describes. That workshop is already present in local commit `e124ce9`. This review does not start another implementation.

Do not enable a detector. Do not push from this review.
