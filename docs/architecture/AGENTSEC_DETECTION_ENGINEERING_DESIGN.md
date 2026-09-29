# AgentSec detection engineering design

**Date:** 2026-09-29
**Status:** DESIGN ONLY. Nothing in this document was implemented.
**Reviewed HEAD:** `8ec6f76f799b925d483f3ebe77f56a929a8dec3d` (`develop` = `origin/develop`)
**Defender Bridge remediation, contained in HEAD:** `978f91bc3a47fd6a94c446f784306d8740d9cf89`
**Application code, runtime, schema, ExternalEvidence, saved searches, detectors, tags:** unchanged by the design gate

## Design corrections after independent review

These corrections describe the repository. They do not change `DET-MCP-001.spl` or `savedsearches.conf`.

**Control id.** The shipped predicate does not require `agentsec.control.id="CTRL-MCP-001"`. `is_deny` is true when `event.name` is `agentsec.control.decision` and `agentsec.control.decision` is `DENY`. `eventstats` copies `control_id` from the DENY rows onto the group. The saved-search description names CTRL-MCP-001. The SPL does not enforce that description. The workshop's tuned predicate adds the control-id test on the decision side. That addition is teaching. It is not a silent edit of DET-MCP-001.

**Mixed-tool order.** Two indexed RETEST runs contain a CTRL-MCP-001 DENY of `lookup_customer_tier` at sequence 9 and an earlier `agentsec.mcp.started` of `lookup_policy`:

- `0ab10594-a7fc-48b6-81bf-4cbca54a64c6`: ALLOW of `lookup_policy` at sequence 3, start at sequence 4, DENY of `lookup_customer_tier` at sequence 9.
- `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`: start of `lookup_policy` at sequence 5, DENY of `lookup_customer_tier` at sequence 9.

Do not describe the `lookup_policy` start as occurring after the `lookup_customer_tier` DENY. A run-id-only candidate matches both runs. The same-tool predicate matches neither.

**min(sequence) and latest().** DET-MCP-001 takes the earliest DENY sequence with `min()` and copies decision metadata with `latest()`. If one run and tool had more than one DENY, those functions could describe different DENY rows. That divergence was not observed on the indexed same-tool case, because that case had no match. It remains a limitation of the shipped SPL.

**Dispatch window.** The saved search uses `dispatch.earliest_time=-24h`. The `.spl` file has no `earliest=`. Workshop searches over the historical lab index use `earliest=0`. Those are not the same search. Enabling the saved search would not, by itself, search the teaching corpus.

Evidence classes: MEASURED means a prior recorded Splunk or test result. DOCUMENTED means the repository text or source. INFERRED means a conclusion from those two, not a new search. This gate did not launch an attack and did not execute DET-MCP-001 against the index.

## 1. Executive summary

AgentSec can teach detection engineering from evidence it already has. It cannot honestly call that teaching an operational detector.

The one packaged detector, DET-MCP-001, is disabled. Its hypothesis is narrow: CTRL-MCP-001 denied a tool, and a later `agentsec.mcp.started` exists for the same run and the same tool. The live teaching volume measured during the Defender Bridge re-review is mostly the opposite shape. ATTACK often ALLOWs and then starts. RETEST often DENYs `lookup_customer_tier` and does not start that tool. One measured run DENYed `lookup_customer_tier` and started a different tool, `lookup_policy`. A detector keyed only on `agentsec.run.id` would treat that run as execution after denial. The existing SPL does not, because it also keys on `gen_ai.tool.name`.

That contrast is the teaching case. The learner writes a broad candidate, tunes it to the same run and tool, and compares ATTACK, RETEST, and BASELINE. Silence on the known ALLOW-then-start attack is a bounded result, not safety. A match is not an incident and not an authorization decision. The positive example already in the repo is SIMULATED (`makeresults`), not a live attack.

Recommended build, after review: one REPLAY workshop after L6. No new saved search. DET-MCP-001 stays disabled. No runtime, schema, contract, attack, or LIVE lab change. The maturity a learner may claim is **LOGIC VALIDATED** for this predicate. **SCENARIO VALIDATED** is not available for a live positive, because the indexed ATTACK population does not demonstrate same-tool start after DENY.

## 2. Current detection reality

SPL in the repo is not an operational detection capability.

| Item | Where | Classification |
|------|--------|----------------|
| DET-MCP-001 logic | `learning/level_1/LAB-MCP-001/searches/DET-MCP-001.spl` | IMPLEMENTED as SPL. DISABLED as a saved search. EDUCATIONAL. Live negatives were MEASURED in Phase 3E on older specimens. Positive control is SIMULATED. Not LIVE_VALIDATED as an enabled detector. |
| Saved search `AgentSec - MCP Execution After Authorization Deny` | `splunk_app/agentsec/default/savedsearches.conf` | DISABLED (`disabled = 1`, `enableSched = 0`). Same SPL as the file. Window `-24h` to `now`. |
| DET-MCP-001 positive controls | `DET-MCP-001-POSITIVE-CONTROL.spl` and scope/resource variants | SIMULATED `makeresults`. EDUCATIONAL. Not indexed evidence. |
| Q-MCP-AFTER-DENY | `Q-MCP-AFTER-DENY.spl` | EDUCATIONAL hunt. Uses a run token. Not a detector. |
| Q-RUN | saved search stanza | DISABLED PLACEHOLDER. Description says not Splunk-validated in Phase 2. |
| Q-DENY | saved search stanza | DISABLED PLACEHOLDER. NOT_VALIDATED. Not a detector. |
| L6 Blue Team | `LAB-BLUE-TEAM-INCIDENT-001` searches `Q-INCIDENT-*` | EDUCATIONAL REPLAY hunt and investigation. Not a detector. |
| Defender Bridge | checkpoint after L5, searches `Q-BRIDGE-*` | EDUCATIONAL. REPLAY_VALIDATED for investigation correlation on the current index (re-review). Not a detection. |
| L9 `Q-L9-DETECTION-CANDIDATE.spl` | scope mismatch and `mcp.started` | CANDIDATE. Status text says NOT INSTALLED. NOT_VALIDATED as a detector. |
| L10 `Q-L10-DETECTION-CANDIDATE.spl` | goal OBSERVE plus `mcp.completed` | CANDIDATE. Status text says NOT INSTALLED. NOT_VALIDATED as a detector. |
| Other lab `Q-*` hunts | MCP, RAG, memory, goal, delegation, privacy, capstone | EDUCATIONAL investigation queries. Not detectors. |
| ATTACK / RETEST / BASELINE | `agentsec.testbed.mode` on indexed runtime events | REPLAY_VALIDATED as specimen labels on the current index. Not production traffic. |
| ExternalEvidence 1.0.0 | scanner and garak sourcetypes | IMPLEMENTED adjacent evidence. REPLAY_VALIDATED as non-authoritative. Not a detector input that authorizes. |
| Runtime schema 1.9.0 | `SCHEMA_VERSION` | IMPLEMENTED. Not a detection feature. |

Enabled saved searches in `savedsearches.conf`: none. The file has three stanzas. All have `disabled = 1`. Only the AgentSec stanza is a detector definition. Q-RUN and Q-DENY are placeholders.

Phase 3E records live negative results for DET-MCP-001 on Phase 3C specimens and a simulated positive. That document's schema note is 1.1.0. It is historical evidence for that package, not a fresh result on today's index, and not proof the detector is operationally validated. This design gate did not re-run that search.

Academy levels stay L0–L10. Detection engineering is not a level today. L4 teaches "hunt versus detection" and "0 rows is not SAFE" as practice, not as a detector workshop. The post-RC2 curriculum review said not to enable DET-MCP-001 in the bridge phase, and that a later phase could let learners author one candidate and show that zero rows are not safe. The bridge re-review authorized a detection-engineering design. It did not authorize implementation.

## 3. Detection terminology

The proposed ladder fits this architecture if the evidence bar is strict.

| Stage | Meaning in AgentSec | Evidence required to enter | What it is not |
|-------|---------------------|----------------------------|----------------|
| OBSERVATION | Indexed events exist for a behavior. | Rows with named fields. A count without `dc(_raw)` is not enough. | A finding. |
| HYPOTHESIS | A security claim about those events. | A written behavior, the trust boundary, and what would disprove it. | A search. |
| CANDIDATE DETECTION | SPL that would surface that behavior for an analyst. | The query, the correlation keys, and the fields it refuses to require. | An enabled detector. A passing pytest of the file. |
| LOGIC VALIDATED | The query keeps and drops the rows its predicate names, on known specimens or an explicitly simulated control. | Side-by-side results for the positive shape and for at least one non-match, with evidence class labeled. | A live attacker. A false-positive rate. |
| SCENARIO VALIDATED | The real scenario, not a `makeresults` row, produces the match the hypothesis predicts, and the contrasting specimens behave as stated. | Indexed ATTACK, RETEST, and BASELINE results for this predicate, each classified. | Universal detection. |
| OPERATIONALLY VALIDATED | A scheduled search, window, owner, dedup, and rollback were tested on purpose. | A repeatable enabled-search exercise recorded as its own gate. | Production certification. |
| ENABLED DETECTOR | `disabled = 0` and a schedule that is intended to run. | The operational gate above, still inside the lab. | Authorization. Containment. An incident. |

A SPL file alone is not a validated detection. DET-MCP-001 is IMPLEMENTED and DISABLED. It is not ENABLED. A match on ATTACK would not establish universal detection. A non-match on BASELINE would not establish an acceptable false-positive rate. Zero rows are not SAFE, not DENY, and not prevention.

This ladder is adopted for teaching. It is not a product certification scheme.

## 4. Detection maturity model

Current packaged DET-MCP-001 sits at the boundary of CANDIDATE DETECTION and historical LOGIC VALIDATED negatives. Phase 3E measured live negatives and a simulated positive. The simulated row is labeled `evidence_class=SIMULATED`. That does not reach SCENARIO VALIDATED. The saved search is not OPERATIONALLY VALIDATED: it is disabled, its window is `-24h`, and the Defender Bridge evidence dates (2026-09-14 and 2026-09-25) sit outside a 24-hour window ending on 2026-09-29. That window fact is DOCUMENTED from the conf file plus previously measured `_time` values. This gate did not dispatch the saved search.

L9 and L10 candidate queries are CANDIDATE DETECTION text. Their own status field says NOT INSTALLED. They are not validated detections.

The workshop recommended below may lead a learner to claim LOGIC VALIDATED for the same-tool DENY-then-start predicate, including an explicit simulated positive and indexed non-matches. It must not claim SCENARIO VALIDATED, OPERATIONALLY VALIDATED, PRODUCTION READY, or CERTIFIED.

## 5. Learner progression

Placement: L5 LIVE capstone, then the Splunk Defender Bridge, then L6 hunt, then this detection workshop. Do not insert a new level id. L0–L10 stay as they are. The workshop is a REPLAY checkpoint after L6, the same kind of placement the bridge used after L5, unless a later implementation review chooses a page inside an existing lab. It is not an eighth LIVE lab and not a new attack.

The learner moves in this order:

security question, behavior hypothesis, observable behavior, required telemetry, SPL exploration, candidate detection, ATTACK comparison, RETEST comparison, BASELINE comparison, false-positive analysis, false-negative analysis, one tuning step, coverage statement, limitations, operationalization decision.

The decision at the end is "remains a candidate" or "not ready to enable." Enabling is out of scope.

Sentences the workshop has to make the learner say in their own words:

- A hunt reconstructs a case. A detection is a reusable predicate. They are not the same activity.
- A query is not a detector.
- A finding is not an incident.
- ALLOW is not execution. Execution is an `agentsec.mcp.started` or later execution event.
- DENY is not safe. A DENY with no later start is NOT OBSERVED for execution of that tool, not proof of safety.
- No result is not safe.
- A match on one ATTACK specimen is not universal detection.
- A non-match on BASELINE is not a proven low false-positive rate.

## 6. Selected teaching case

**Same-tool MCP start after CTRL-MCP-001 DENY.**

This is the behavior DET-MCP-001 already names. It is the teaching case because the predicate is bounded and the contrasting evidence is already indexed.

Why this case, and not a louder one:

- Fail-open ALLOW followed by `mcp.started` is common on ATTACK. The bridge re-review measured ATTACK ALLOW 60 and ATTACK `mcp.started` 60, and a discover row whose reason begins with `vulnerable_profile_fail_open`. Detecting that reason detects a string the vulnerable profile writes on purpose. BASELINE also has ALLOW and `mcp.started` (16 and 16 in that same measurement). ALLOW-then-start does not separate an attack from ordinary tool use without the lab-specific reason. That is a weak detection hypothesis.
- "Any start in a run that also has a DENY" is teachable as the broad candidate the learner must outgrow. Two measured RETEST runs, `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` and `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`, deny `lookup_customer_tier` at sequence 9 and start `lookup_policy` at an earlier sequence. On the first run the policy tool is allowed at sequence 3 and started at sequence 4. Run-id-only correlation flags that granted tool. The start is not after the customer-tier DENY. That false positive is MEASURED.
- Same-tool and later sequence is the invariant already written down: if this tool was denied, a later start of this tool is the violation. The SPL already collapses multivalue fields and does not require `agentsec.control.id` on `mcp.started`. That preserves the Defender Bridge lesson.
- The live positive violation was not in the re-review's sampled DENY runs. The repo's positive control is SIMULATED. The workshop can still use ATTACK, RETEST, and BASELINE as non-match and contrast specimens. It must say the positive is simulated.

The case is selected for a clear hypothesis and bounded semantics, not for dramatic impact.

## 7. Detection hypothesis

If CTRL-MCP-001 records DENY for a run and a tool, and a later `agentsec.mcp.started` exists for that same run and that same tool, emit a candidate finding for an analyst. Do not emit a block, a DENY, or an incident.

The finding says: indexed evidence shows a start after a denial of that tool. It does not say the start was authorized, that Splunk denied anything, or that every attack looks like this.

Out of scope for the predicate: scanner HIGH, garak PASS or FAIL, RAG text, memory text, and an ALLOW on a different tool in the same run.

## 8. Telemetry requirements

Names below are the indexed names in `src/agentsec/events.py` and in DET-MCP-001. Do not rename them to `agentsec.event.name` or `agentsec.tool.name`. Those names are not the emitted fields.

| Field | Role | Where it is emitted | Notes |
|-------|------|---------------------|-------|
| `agentsec.run.id` | REQUIRED, primary correlation | Base event, including control decisions and `mcp.started` | Present on both sides. |
| `gen_ai.tool.name` | REQUIRED, primary correlation | Control decision when a tool is set; `mcp.started` always sets it | Same-tool key. Not `agentsec.tool.name`. |
| `event.name` | REQUIRED | Both event types | Values `agentsec.control.decision` and `agentsec.mcp.started`. Not `agentsec.event.name`. |
| `agentsec.control.decision` | REQUIRED on the decision only | Control decision | Do not require it on `mcp.started`. The start event does not set it. |
| `agentsec.control.id` | REQUIRED on the decision in the workshop's tuned predicate. The shipped DET-MCP-001 SPL does not filter on it. | Control decision | NOT AVAILABLE on `mcp.started`. `eventstats` copies it from the DENY row. That copy is not a filter and is not a claim the start event carried it. |
| `agentsec.sequence` | REQUIRED for order | Base event | Integer order inside the run. Prefer this over `_time` when timestamps collide. |
| `agentsec.testbed.mode` | CONTEXT | Base event | ATTACK, RETEST, BASELINE. Multivalue on the measured decision events (`mvcount` 3). Deduplicate before `stats by`. |
| `agentsec.control.reason` | CONTEXT | Control decision | Explains the DENY or the fail-open ALLOW. Not required for the match. |
| `agentsec.security.profile` | CONTEXT | Base event | defended versus vulnerable. Not a detection by itself. |
| `gen_ai.agent.id` | CONTEXT | Hop identity helper | Useful in the output. Not a correlation key for this predicate. |
| `agentsec.principal.id` | CONTEXT | Base event | Output context. |
| `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope` | OPTIONAL context | Set on the control decision when the caller passes them | Not required for this predicate. L9 uses them for a different candidate. |
| `trace_id` | CORRELATION, secondary | Base event | Ties spans. Not sufficient alone. |
| `agentsec.outcome` | NOT REQUIRED here | Set on hop and run completion, not on `mcp.started` in `mcp_started()` | Outcome is a separate question. `hop_denied` and `completed_denied` are not this detector. |
| `agentsec.operation.executed` | NOT a substitute | Control decision sets it false. `mcp.started` sets it true | False on a DENY event does not mean the run never started a tool. |
| `agentsec.operation.outcome` | Do not use as execution proof | On DENY or ERROR the control event sets `prevented` | That is the control's own claim. It is not the absence of `mcp.started`. |
| `source_run_id` | NOT AVAILABLE under that name | Memory uses `agentsec.memory.source_run_id` when set | Not part of this predicate. |
| `_time` / `timestamp` | CONTEXT | Every event | Ordering aid. Same-millisecond ties were MEASURED. Not the primary order key. |

Telemetry gaps, with no schema change:

- `agentsec.control.id` and `agentsec.control.decision` are absent on `mcp.started`. The correlation must tolerate that.
- A grant list such as `allowed_tools` is not an indexed field on these events. "Tool was not in the grant" is represented by `agentsec.control.reason` when the control emits it, not by a snapshot of the policy object.
- External scanner and garak events do not carry `agentsec.run.id` in the measured volume (distinct runtime run ids 0). They cannot join this predicate.
- The saved-search window does not cover the historical lab volume. That is a search-window gap, not a missing field.

Telemetry for this predicate is PARTIAL: the required fields exist, and two important fields exist only on the decision.

## 9. Correlation model

Primary key: `agentsec.run.id` together with `gen_ai.tool.name`.

Secondary keys: `agentsec.sequence` for order, `trace_id` for the trace, `agentsec.testbed.mode` for the specimen label after `mvdedup`.

Time window: for the workshop, `earliest=0` on the lab index, and the learner states that window. The packaged saved search's `-24h` to `now` is an operational choice, not the teaching window. Do not treat those as the same search.

Order: a start counts only when its `agentsec.sequence` is greater than the DENY sequence for that same run and tool. `_time` is a display order. It is not the predicate, because two events in one run have shared a timestamp.

Event population:

- Authorization evidence for the workshop predicate is `event.name=agentsec.control.decision` with `agentsec.control.id=CTRL-MCP-001` and `agentsec.control.decision=DENY`. The shipped DET-MCP-001 file checks the event name and DENY only.
- Execution evidence is `event.name=agentsec.mcp.started` for the same run and tool. It has no control id.
- Outcome evidence (`agentsec.hop.completed`, `agentsec.run.completed`, `agentsec.mcp.completed`, `agentsec.mcp.failed`) is not required for this match. Absence of those events is NOT OBSERVED for outcome, not a second finding.

Missing-event behavior:

- DENY and no later start for that tool: no match. Execution of that tool is NOT OBSERVED. That is not SAFE.
- Start and no DENY for that tool: no match. If the decision was ALLOW, the start can still be real. ALLOW is not this finding.
- DENY for tool A and start for tool B: no match. The bridge run is the example.
- Start with no `gen_ai.tool.name`: the key is incomplete. CORRELATION NOT ESTABLISHED. Do not invent the tool.
- Empty result for the whole search: NO EVIDENCE FOUND for this predicate in this window. Not prevention.

Do not stamp `agentsec.control.id` onto the start event in telemetry. The existing `eventstats` copy is an output column taken from the DENY row. Teaching text must say that.

## 10. ATTACK validation model

ATTACK validation answers one question: on the indexed ATTACK rows, did this predicate match, and what did those rows actually contain?

A match would mean: at least one ATTACK run started the same tool after CTRL-MCP-001 denied it. That would support the hypothesis for that specimen. It would not prove universal detection, production effectiveness, technique coverage, a false-negative rate, or attribution.

The measured ATTACK population from the bridge re-review is mostly ALLOW and `mcp.started`, plus 8 ERROR decisions. The discover sample included a fail-open ALLOW whose reason says the handler executes. For this predicate, a non-match on that population is the expected teaching result if no same-tool DENY-then-start exists. The non-match means the known ATTACK succeeded through ALLOW, which this detector does not look for. It does not mean the attack was stopped.

This gate did not re-execute DET-MCP-001, so a fresh match count is NOT MEASURED here. The workshop implementation must run the comparison and record the observed number. Until that run, ATTACK support for a positive match is NOT AVAILABLE, and ATTACK support for the contrasting ALLOW-then-start behavior is AVAILABLE from the re-review.

Correct claim: "On this index, the ATTACK rows that were examined did not establish same-tool execution after DENY" or, if a later search finds a row, "this search matched these ATTACK run ids." Both stay below universal detection.

## 11. RETEST validation model

RETEST is not "zero detections or the control failed."

Separate the questions:

| Question | What a row means | What zero rows mean |
|----------|------------------|---------------------|
| Attack attempt | A DENY, or another decision that the tool was requested | NOT OBSERVED for that request. Not "no attack." |
| Authorization failure | CTRL-MCP-001 decision DENY, with reason | The control did not record DENY in this window. Not SAFE. |
| Successful execution of the denied tool | `mcp.started` for that same tool after the DENY | Execution of that tool is NOT OBSERVED. Not proof the handler was incapable of running. |
| Impact | A later outcome or data effect tied to that start | NOT OBSERVED or NOT MODELED. `completed_denied` is an outcome label, not customer harm. |

The re-review measured RETEST DENY 48 and RETEST `mcp.started` 8, with the 8 lining up with RETEST ALLOW 8 on that volume. One RETEST run denied `lookup_customer_tier` (`tool_not_granted`) and started `lookup_policy` under a different ALLOW. Expected result for the tuned predicate: no match on that denied tool. Expected result for a run-id-only candidate: a match, which is the false positive the tuning step removes.

A RETEST match on the tuned predicate would be evidence that a defended specimen still started the denied tool. That would be a candidate finding, not proof the product is unsafe everywhere, and not something this design claims to have measured.

## 12. BASELINE validation model

BASELINE is a controlled comparison label. The re-review measured BASELINE ALLOW 16, ERROR 1, `mcp.started` 16, `mcp.completed` 11, and `mcp.failed` 5. That is enough to ask whether the candidate fires on those rows. It is not a sample of production benign traffic.

A non-match supports only: this predicate did not trivially flag the available BASELINE specimens in this window. It does not support a production false-positive rate, environment-wide specificity, or "universal benign behavior."

If BASELINE produced a match, the learner would have a false-positive candidate or a real same-tool DENY-then-start inside the baseline specimen. Either result is a finding to explain. Neither result is a rate.

## 13. False positive analysis

The learner exercise: what legitimate or merely different behavior could satisfy the SPL?

Use only dimensions this repo can illustrate.

| Dimension | Relevance here | What the learner should do |
|-----------|----------------|----------------------------|
| Same run, different authorized tool | MEASURED on `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` and `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` | Show that run-id-only correlation flags an earlier `lookup_policy` start in a run that later denies `lookup_customer_tier`. The policy start is not after that DENY. |
| Multivalue fields | MEASURED. `mvcount(agentsec.testbed.mode)=3`. No-split count 141 equals `dc(_raw)` 141. Grouping by the raw mode field tripled the count. | Deduplicate before `by`. Do not call the gap duplicate executions. |
| Control event says executed false, or outcome prevented | DOCUMENTED in `control_decision()` | Those fields describe the decision event. They do not prove a later start is absent. |
| Partial telemetry | `mcp.started` has no control id | Requiring control id on every event drops the start, or, if the learner copies the id blindly, invents a field the event did not have. |
| Same timestamp | MEASURED on the bridge run | Do not use `_time` alone as "after." |
| Unusual but authorized workflow | ALLOW then start is the normal success path on BASELINE and on RETEST ALLOW | Those rows are not this finding. |
| External duplicate indexing | Garak was 8 indexed rows and 1 distinct raw, with 0 runtime run ids | Do not import that plane into this correlation. |

Do not build exercises around administrative approval workflows, production policy transitions, or clock skew beyond the ties already measured. Those are not evidenced here.

## 14. False negative analysis

The learner must separate demonstrated gaps from hypothetical ones.

Demonstrated:

- Fail-open ALLOW then start. The vulnerable profile records ALLOW and the reason says the handler executes. DET-MCP-001's own note says it does not alert on that. The bridge discover sample showed the reason. A detector of DENY-then-start misses the ATTACK that never receives a DENY.
- Different tool in the same run. The measured RETEST run starts `lookup_policy` and denies `lookup_customer_tier`. The tuned predicate correctly misses the start. A learner who wanted "any execution while a denial exists" would call that a miss. The coverage statement has to pick one behavior and admit the other is out of scope.
- Missing control id on the start. Requiring it is a self-inflicted false negative. The bridge sequence showed start and outcome rows with an empty control id.
- `mcp.completed` and `mcp.failed` are outside this predicate. A completion without a start, if one existed, would not match. This gate did not establish that shape as a measured gap for this volume. Treat it as a scope limit, not as a discovered miss.
- Search window. The disabled saved search looks back 24 hours. The teaching events are older. A scheduled run can miss them even when `earliest=0` in Search still shows them. That is a demonstrated configuration gap, not a new measurement of a scheduled dispatch.

Hypothetical, and labeled as such until a search shows them:

- `agentsec.sequence` missing or not monotonic, so a real later start fails `sequence>deny_sequence`.
- An ERROR decision followed by a start. ERROR is not DENY. ATTACK has 8 ERROR decisions in the re-review. Pairing those with a later start of the same tool was not measured in this gate.
- A renamed tool or a start whose tool field is empty.
- Ingest that drops `mcp.started` while the handler still ran. The runtime count would be the authority. Splunk would be silent. That limitation is already written on DET-MCP-001. It was not re-demonstrated here.

## 15. Tuning method

The learner changes the SPL on purpose. Three versions, not a pile of filters.

1. Broad candidate. Same `agentsec.run.id` has both a CTRL-MCP-001 DENY and any `agentsec.mcp.started`. No tool key. No sequence test.
2. Tuned candidate. Same run and same `gen_ai.tool.name`, DENY sequence strictly less than start sequence, and `agentsec.control.id=CTRL-MCP-001` on the decision event only. Same-tool order is the shipped DET-MCP-001 shape. The control-id test is not in that file. The learner adds it. Path B may show the finished SPL after that attempt, including the note that the shipped file omits the control-id test.
3. Comparisons. Run both versions against ATTACK, RETEST, and BASELINE. Record match counts, distinct raw, and distinct runs. Deduplicate mode before grouping.
4. What tuning gains. It drops the measured case where a denied tool and a different allowed tool share a run. It stops treating every start in a denied run as a violation.
5. What tuning loses. It will not flag a start that lacks a tool name, a start of a different tool the analyst still considers suspicious, or execution that appears only as `mcp.completed` or `mcp.failed`. It will stay silent on fail-open ALLOW. Those silences are scope, not proof of health.

Do not teach tuning as "add filters until BASELINE is empty." BASELINE emptiness is not the goal. The goal is a predicate the learner can say out loud, including what it ignores.

## 16. Detection evidence matrix

The workshop copies this table and fills Observed from the searches the learner runs. The Expected column is the hypothesis. It is not a pre-filled answer key. This design does not invent today's match counts.

| Test | Expected for the tuned predicate | Observed | Evidence | Interpretation |
|------|----------------------------------|----------|----------|----------------|
| ATTACK | No same-tool DENY-then-start, if this volume's ATTACK path is ALLOW-then-start. Fail-open rows remain visible in the authorization search. | Filled by the learner. Not pre-measured as a DET-MCP-001 dispatch in this gate. | Index rows, `dc(_raw)`, run ids, mode. | A non-match does not mean the attack failed. A match names those run ids only. |
| RETEST | DENY of a tool without a later start of that tool is a non-match. A start of a different tool is a non-match after tuning and a match before tuning. | Filled by the learner. The mixed run is prior MEASURED evidence for the broad-versus-tuned contrast. | Same, plus tool and sequence. | Attempt evidence can exist when execution-after-deny does not. |
| BASELINE | Non-match if these specimens have no same-tool DENY-then-start. | Filled by the learner. | Same. | Non-match is not a false-positive rate. |
| Simulated positive | One match on `simulated-det-mcp-001-0001`, labeled SIMULATED. | The SPL file is built to return that row. This gate did not execute it. | `makeresults`, `evidence_class=SIMULATED`. | Logic check only. Not an attack. |
| False positive considerations | Run-id-only correlation; multivalue `stats`; `operation.outcome=prevented` read as proof. | Learner notes. | Sections 13. | |
| False negative considerations | Fail-open ALLOW; other tool; start event omitted; 24h window. | Learner notes. | Sections 14. | |
| Telemetry dependencies | Run id, tool, event name, decision, control id on the decision, sequence. | Present or NOT OBSERVED per row. | Section 8. | |
| Known gaps | No live positive in the cited bridge sample. External evidence has no run id. | State as gaps. | Re-review. | |
| Claim strength | LOGIC VALIDATED at most, if the learner's own results agree. | The learner's sentence. | Section 17. | Not operational. Not certified. |

## 17. Coverage statement

Every learner writes a DETECTION COVERAGE STATEMENT. Path B does not contain a filled example with this volume's numbers. The required answers:

- What behavior does this detection look for?
- What evidence does it depend on?
- Which scenarios were tested?
- What matched?
- What did not match?
- What remains untested?
- What could cause false positives?
- What could cause false negatives?
- What security conclusion is justified?
- What security conclusion is not justified?

A justified conclusion looks like: "Indexed evidence supports a candidate finding that this tool started after CTRL-MCP-001 denied that same tool in this run" or "this window does not contain that sequence." An unjustified conclusion looks like: safe, secure, attack prevented, universally detected, low false-positive rate, scanner proved the attack, or Splunk denied the call.

At least one of NOT OBSERVED, NOT PROVEN, or CORRELATION NOT ESTABLISHED stays in the statement when the evidence supports the gap. On this teaching case the fail-open ATTACK path and the external plane supply those gaps.

## 18. DET-MCP-001 assessment

| Question | Assessment |
|----------|------------|
| Behavior it claims | A tool execution begins after CTRL-MCP-001 denied that same run and tool. |
| SPL | `DET-MCP-001.spl`. Decision or `mcp.started`, `mvdedup` before use, `eventstats` by `run_id` and tool, keep a start whose sequence is greater than the DENY sequence. |
| Telemetry | Fields in section 8. Control id is taken from the DENY side. |
| ATTACK | Historical Phase 3E negatives say the overlay ALLOW attack does not match. Consistent with the later bridge measurement of ALLOW-then-start. Not re-dispatched in this gate. |
| RETEST | The predicate should ignore DENY without a same-tool start, and ignore a start of another tool. The mixed run supports that reading. Not re-dispatched as the full saved search. |
| BASELINE | Historical expectation is no match. Not re-dispatched here. A non-match would still not be a false-positive rate. |
| Name | Accurate for this predicate. The saved-search description already says it is not a general MCP bypass detector. |
| Semantics | Bounded. Severity HIGH in the description is the package label for an invariant break. It is not a severity engine and not an ES notable. The description says Splunk does not enforce authorization. |
| Teaching candidate | Yes. It is the right specimen to study and to re-derive. It is the wrong object to enable in the workshop. |
| Stay disabled | Yes. |

Design facts to leave in the SPL until a later gate:

- The description names CTRL-MCP-001. `is_deny` does not test `agentsec.control.id`. `eventstats` copies `control_id` onto the output row. A reader can think `mcp.started` contained CTRL-MCP-001, or that the file already filtered for that control.
- `min()` chooses the DENY sequence and `latest()` copies the other DENY fields. More than one DENY for the same run and tool could make those functions describe different rows. That split was not observed on an indexed same-tool match.
- The description's HIGH severity can be read as an incident severity. Teaching must say it is a package label.
- The file has no `earliest=`. The saved search has `-24h`. Learners who enable it would not be searching the same window as the workshop.
- The positive control is simulated and easy to mistake for a live attack if the evidence class is stripped.
- It is silent on the fail-open path, which is the common ATTACK. That is correct for the name and fatal if someone describes it as "the MCP attack detector."

Do not fix these in this gate. Do not enable the search.

## 19. Q-RUN / Q-DENY assessment

Q-RUN is a disabled saved search. Its search is the index macro plus `agentsec.run.id=*`. The description says PLACEHOLDER, not validated in Phase 2, and tells the user to fill a run id. It answers "did any run id produce events?" only in the weakest sense. It is not a detector under section 3. Classification: DISABLED PLACEHOLDER. NOT_VALIDATED.

Q-DENY is a disabled saved search. It looks for `agentsec.control.decision=DENY`, `agentsec.operation.executed=false`, and `agentsec.testbed.mode=LIVE`. The control-decision builder sets `agentsec.operation.executed` false on the decision event itself, including when a later event in the run starts a tool. The mode filter is LIVE, not ATTACK, RETEST, or BASELINE. The description says PLACEHOLDER and not validated in Phase 2. Classification: DISABLED PLACEHOLDER. NOT_VALIDATED. Not a detector. Using it as one would confuse a property of the decision event with proof that execution did not occur.

## 20. External evidence boundary

Cisco mcp-scanner remains static catalog evidence (`agentsec:scanner:finding`). A HIGH finding is not a DENY and not a detection match.

garak remains model-evaluation evidence (`agentsec:external:evaluation`). PASS is not safe. FAIL is not a runtime block.

Splunk remains the investigation and detection workbench. A Splunk row does not call CTRL-MCP-001.

CTRL-MCP-001 remains the tool PDP. ExternalEvidence does not authorize. A missing `agentsec.run.id` on scanner or garak events stays CORRELATION NOT ESTABLISHED. Do not join them into this predicate with `hash_join` or `identity_tuple` and call the result causality.

## 21. Splunk detection architecture

```
Agent workflow
  → AgentSec runtime (CTRL-MCP-001 decides)
  → telemetry (control decision, mcp.started, outcomes)
  → Splunk index agentsec_telemetry
  → candidate SPL written by the learner
  → candidate finding rows
  → analyst investigation
  → bounded coverage statement
```

Detection sits downstream of authorization. The workshop does not add a response action, a notable, a webhook, or a control that reads Splunk before allowing a tool.

Sourcetype for this predicate: `otel:agentic:json`. The macro `` `agentsec_index` `` is defined as that index and sourcetype. Scanner and garak sourcetypes stay on their own searches.

## 22. Finding versus incident

A detection match is evidence that the predicate held for those keys. It is not an incident.

States the learner may use:

| State | When |
|-------|------|
| MATCH OBSERVED | The tuned SPL returned these run and tool keys. |
| SUPPORTED SECURITY FINDING | The match's decision, tool, sequence, and start event are present and the order holds. Still not an incident declaration. |
| INSUFFICIENT EVIDENCE | A partial key, or a count that was not checked with `dc(_raw)`. |
| CORRELATION NOT ESTABLISHED | No shared run id, or an external object with no runtime run id. |
| NOT PROVEN | A claim the rows do not carry: impact, intent, production rate, universal coverage. |
| NOT OBSERVED | A stage the search did not return, including `mcp.started` for the denied tool. |

Do not add an incident severity engine. Do not map MATCH OBSERVED to HIGH, critical, or a ticket.

## 23. Framework mapping

The exercise can use vocabulary the academy already treats as educational: an authorization boundary, a tool invocation, and a gap between a decision and a later action. OWASP agentic guidance, MITRE ATLAS, CSA MAESTRO, and NIST AI RMF are lenses for that conversation, in the same sense L7 already states.

This workshop must not add technique identifiers. Any identifier not already validated against the current official source stays NEEDS_EXTERNAL_VALIDATION. The mapping is EDUCATIONAL MAPPING. It is not certification, compliance, or coverage of a framework.

`agentsec.technique.id` is an optional runtime field when a context sets it. Presence of that field on some event would still not validate an external framework entry. This design does not rely on it.

## 24. Beginner, practitioner, and expert

Beginner. Receives the security hypothesis in words, the field list in section 8 marked required versus context, a partial SPL that selects the two event names and stops before `eventstats`, and the evidence-matrix checklist with an empty Observed column. Hints stop at "same run is not the same tool."

Practitioner. Writes the broad candidate and the tuned candidate, runs ATTACK, RETEST, and BASELINE, explains one false positive and one false negative using a row they found, and writes the coverage statement.

Expert. Starts from the behavior, names the telemetry, rejects `agentsec.operation.outcome=prevented` as proof, separates the simulated positive from the index, and writes what would still be required before anyone set `disabled = 0`. No Path B until that note exists.

All three modes share the same index. The workshop does not reveal a different answer key per persona.

## 25. Path B design

Path B stays visible, as in the rest of the academy. It is a review key, not policy.

It may contain, after the exercises:

- The tuned SPL, equivalent to the existing DET-MCP-001 logic, with a comment that control id is constrained on the decision search and not required on `mcp.started`.
- A reminder that the simulated positive is `makeresults` and is not an indexed attack.
- The sentence that zero rows are not SAFE.

It must not contain:

- A filled coverage statement using this volume's counts.
- A verdict that ATTACK was detected or that RETEST is safe.
- An instruction to set `disabled = 0` or to change `savedsearches.conf`.
- The claim that a larger `count` than `dc(_raw)` means restaged copies.

Progressive hints on Path A: hypothesis, then fields, then "do not correlate on run id alone," then the checklist. One hint per stuck point. Not the finished `eventstats` on the first screen.

## 26. Operationalization requirements

A future gate, not this one, would have to show all of the following before anyone enabled a detector:

- Logic validation recorded on the current index, with the simulated positive still labeled SIMULATED.
- ATTACK, RETEST, and BASELINE results from that same dispatch, including distinct raw and distinct runs.
- A repeat run that returns the same predicate result on unchanged data.
- A written false-positive note tied to a real row, not a slogan.
- A written false-negative note that includes the fail-open path.
- An explicit schedule, search window, and lookback. The current `-24h` does not cover the teaching corpus. Changing it is a product change and needs its own test.
- Deduplication that survives multivalue fields.
- A statement of what would throttle or suppress repeat rows for one run and tool. Not implemented now.
- A finding schema that cannot be mistaken for a control decision. No field that says Splunk allowed or denied.
- An owner, a severity rationale that is not an incident severity engine, a short runbook, a rollback to `disabled = 1`, and a way to notice the search failing.

Until that gate, the only honest operationalization decision is: do not enable.

## 27. Explicit deferrals

Do not build, in the implementation that follows this design or inside this gate:

- An enabled detector, including DET-MCP-001.
- A new saved search, a cron change, or an edit to `savedsearches.conf`.
- SOAR, automated containment, or any action that turns a Splunk row into a control decision.
- HIGH means DENY. Scanner means deny. Garak means deny.
- Production IAM, OAuth, PKI, HITL, A2A authentication.
- A new scanner, evaluation harness, attack, or LIVE lab.
- AI-BOM, a new enterprise scenario, a schema bump, an ExternalEvidence bump, RC3.

L9 and L10 candidate queries stay as they are. This workshop does not promote them to detectors and does not merge them into DET-MCP-001.

## 28. Final 1.0 debt separation

These remain release debt. They are not detection-engineering tasks:

- Clean-room install and image rebuild. Running AcmeBank and Attack Service were `1.0.0rc1` at the bridge re-review. Splunk `app.conf` was `1.0.0-rc2`.
- Screen-reader validation. The bridge re-review left it NOT TESTED. CSS zoom overflow at a 1024 viewport remains a known limitation.
- Ollama image pinning. AcmeBank was degraded when Ollama was unreachable. This design does not need a new model launch.
- Garak license text still marked for external validation in that lab.
- Third-party fidelity validation for scanner and garak behavior.
- Default GitHub branch, if it is still not `develop`. Not checked as a change in this gate.

## 29. Risks

- A learner, or a later implementer, enables the saved search because the SPL already exists. The workshop has to say disabled is the intended state.
- Zero rows on ATTACK get written up as "the detector works" or as "the attack was blocked." Both are false for this predicate.
- Run-id-only correlation becomes the candidate people remember, because it "finds more." It finds the wrong tool.
- The simulated positive is screenshotted without `evidence_class` and treated as a live compromise.
- `eventstats` output is described as if `mcp.started` contained CTRL-MCP-001.
- `agentsec.operation.outcome=prevented` is taught as proof of non-execution.
- Multivalue `stats` recreates the restaged-copy mistake.
- The `-24h` window is used in a demo and the room concludes the lab has no evidence.
- Framework names get pasted as if the exercise certified a technique.
- Scope creeps into L9 scope-mismatch or L10 goal overlay. Those are different hypotheses with weaker validation. Leave them.

## 30. Recommended implementation scope

Build one REPLAY workshop, name it in the implementation prompt, placed after L6 without a new level id and without a LIVE launcher.

What is built: teaching pages and searches the learner runs in Splunk Search, plus tests that the pages do not enable a detector, do not add a saved search, do not change schema or ExternalEvidence, and do not put the finished coverage statement on Path A. Reuse `DET-MCP-001.spl` as the tuned reference and `DET-MCP-001-POSITIVE-CONTROL.spl` as the labeled simulation. Reuse the existing index. Reuse ATTACK, RETEST, and BASELINE as specimen labels. Reuse the Defender Bridge rules for multivalue fields and for not requiring control id on execution events.

What is not built: a saved search, an enablement, a schedule change, a runtime change, a schema change, an ExternalEvidence change, a new attack, a new LIVE lab, a response action.

The first implementation should stop when a learner can produce the coverage statement from rows they queried. It should not stop when a detector is green.

| Question | Answer |
|----------|--------|
| Saved search created | No |
| Detector enabled | No |
| Runtime changes | No |
| Schema changes | No |
| ExternalEvidence changes | No |
| New attacks | No |
| New LIVE lab | No |
