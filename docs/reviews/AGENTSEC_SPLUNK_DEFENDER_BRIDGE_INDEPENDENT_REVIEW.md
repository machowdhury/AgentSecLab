# Splunk Defender Bridge independent review

**Date:** 2026-09-28
**Reviewed commit:** `1ecd883483fb98459a53952270d046d3c3b82175`
**Mode:** validation only. No product, runtime, schema, contract, detector, or tag change.
**Decision:** CONDITIONAL GO — REMEDIATION REQUIRED

This review did not start from a known `agentsec.run.id`. Searches below were the workshop files, then follow-up searches that used only identifiers returned by those searches.

## 1. Baseline

| Ref | SHA | Result |
|-----|-----|--------|
| `HEAD` at review start | `1ecd883483fb98459a53952270d046d3c3b82175` | Matches the expected build commit |
| `origin/develop` | same SHA | In sync at review start |
| `main` and `origin/main` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | Unchanged |
| `v1.0.0-rc2^{}` | `1be214b92f840f843aaf27fb2b9536f764dd7126` | Not moved |
| `v1.0.0-rc1^{}` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | Not moved |
| Tags | `v1.0.0-rc1`, `v1.0.0-rc2` | No RC3 |

Working tree at start: `develop` clean except untracked `docs/plans/`. That path was not staged.

Curriculum placement is L5 → Splunk Defender Bridge → L6. The checkpoint is not a new level id and not in `known_lab_ids()`. Offline tests measured that. Class: MEASURED.

## 2. Lab startup

Documented path: `./scripts/lab-preflight.sh` then `./scripts/lab-up.sh --refresh-app`.

`--refresh-app` is the documented flag that restages `splunk_app/agentsec` into the named volume. It was required so the new view existed in Splunk. Preflight result: WARN (port 8000 container already present). `lab-up` then printed READY.

| Check | Result | Class |
|-------|--------|-------|
| Splunk Web login page | HTTP 200 | MEASURED |
| Index `agentsec_telemetry` | exists | MEASURED |
| HEC health | HTTP 200 | MEASURED |
| AcmeBank `/health` | HTTP 200, `status=degraded`, `ollama_reachable=false`, `version=1.0.0rc1` | MEASURED |
| Attack Service `/health` | HTTP 200, `status=healthy`, `schema_version=1.9.0`, `version=1.0.0rc1` | MEASURED |
| Bridge view file inside Splunk | present after refresh | MEASURED |
| Splunk `app.conf` `version` | `1.0.0-rc2` | MEASURED |
| Running AcmeBank package | `1.0.0rc1`, schema `1.9.0`, ExternalEvidence `1.0.0`, `CONTROL_ID=CTRL-MCP-001` | MEASURED |

The running application containers are **1.0.0rc1**. The restaged Splunk app file says 1.0.0-rc2 because `--refresh-app` copied the current tree. This review does not call the running stack RC2.

`lab-ready.sh` does not check `ws_lab_splunk_defender_bridge`. READY does not prove that view loaded. The file was present when checked directly.

## 3. Central claim

A learner can start from a security question and find AgentSec activity without being given `agentsec.run.id`.

**Initial run.id supplied: NO.**

**Candidate run.id discovered from Splunk: YES.**

Discovery method: `Q-BRIDGE-DISCOVER.spl` (control decisions, no run identifier in the SPL), then `Q-BRIDGE-NARROW.spl` (`CTRL-MCP-001` and `DENY`, grouped by `agentsec.run.id` and `agentsec.testbed.mode`).

Candidate used for correlation, taken from the first narrow row, not from a fixture list:

`06c41bc2-4971-4b5c-bf42-5774ab2b439d`

Supporting evidence on that narrow row: mode RETEST, tool `lookup_customer_tier`, reason `tool_not_granted`, `distinct_raw=1`. The same row's `indexed_rows=9` is not an event count. A direct count of that run's control-decision event is 1 indexed row and 1 distinct raw. See finding HIGH-2.

## 4. What the searches returned

Class for all figures in this section: MEASURED on this Splunk volume during this review. They describe this index, not every future launch.

### Discovery

`Q-BRIDGE-DISCOVER.spl` returned control-decision rows with `CTRL-MCP-001`, decisions ALLOW and DENY, reasons such as `tool_granted` and `tool_not_granted`, tools, and modes ATTACK and RETEST. No run identifier was in the search text. The sample is useful. Field values inside a cell are repeated three times because `mvcount('agentsec.testbed.mode')` is 3 on these events.

`Q-BRIDGE-FIELDS.spl` returned real fields: `agentsec.control.decision` (ALLOW, OBSERVE, DENY, ERROR), `agentsec.control.id` (including CTRL-MCP-001), reasons, `agentsec.run.id`, profile, sequence, mode (ATTACK, RETEST, BASELINE), `event.name=agentsec.control.decision`, and tool names. Sample run identifiers appear in the field-summary values. They were not typed into the search.

### Narrow

Denied CTRL-MCP-001 rows in the returned page were RETEST, mostly `lookup_customer_tier` / `tool_not_granted`, plus one `lookup_policy` / `resource_not_granted`. That is enough to pick a candidate. It is not the full population of tool activity. ATTACK denials were not in that filter because this index's ATTACK CTRL-MCP-001 decisions are ALLOW and ERROR.

### Population without a multivalue split

For `event.name=agentsec.control.decision` and `agentsec.control.id=CTRL-MCP-001`, with no `by` clause:

- indexed rows = 141
- `dc(_raw)` = 141
- distinct `agentsec.run.id` = 137

Every one of those 141 events has `mvcount('agentsec.testbed.mode')=3`.

After `mvdedup` on mode and decision, the same events are:

| Mode | Decision | Events | Distinct raw | Distinct runs |
|------|----------|--------|--------------|---------------|
| ATTACK | ALLOW | 60 | 60 | 58 |
| ATTACK | ERROR | 8 | 8 | 8 |
| BASELINE | ALLOW | 16 | 16 | 16 |
| BASELINE | ERROR | 1 | 1 | 1 |
| RETEST | ALLOW | 8 | 8 | 8 |
| RETEST | DENY | 48 | 48 | 48 |

The workshop's own duplicate and stats searches report about three times these event counts. `Q-BRIDGE-DUPLICATES.spl` returned ATTACK 204 / 68 / 66, BASELINE 51 / 17 / 17, RETEST 168 / 56 / 54. 68×3=204, 17×3=51, 56×3=168. The gap is the multivalue `by` field, not extra indexed copies. On this volume, `count` equals `dc(_raw)` when the multivalue field is not a split-by.

### Comparison as indexed

`Q-BRIDGE-COMPARE.spl` returned only `agentsec.control.decision` rows:

- ATTACK: decisions ALLOW and ERROR, distinct runs 66
- BASELINE: decisions ALLOW and ERROR, distinct runs 17
- RETEST: decisions ALLOW and DENY, distinct runs 54

No `agentsec.mcp.started`, `agentsec.mcp.completed`, or `agentsec.mcp.failed` row appeared. A separate population search showed those execution events exist in the index (mcp.started 252 indexed / 84 distinct raw / 82 runs before any multivalue correction) and that `dc(agentsec.control.id)` on them is 0. The workshop filter `agentsec.control.id=CTRL-MCP-001` removes them.

Supported comparison, and only this:

- In this index, CTRL-MCP-001 DENY is observed on RETEST runs, with reasons such as `tool_not_granted`.
- ATTACK and BASELINE CTRL-MCP-001 decisions observed here are ALLOW or ERROR, not DENY.
- ALLOW includes `vulnerable_profile_fail_open` reasons on some ATTACK runs. ALLOW is not a finding that the request was malicious, and it is not execution by itself.
- BASELINE ALLOW `tool_granted` on `lookup_policy` is a controlled comparison, not a standing trust decision.
- RETEST DENY is not proof that every attack is denied, and not proof the lab is protected.

### Correlation of the discovered candidate

Run `06c41bc2-4971-4b5c-bf42-5774ab2b439d`, searched by that discovered id with no control-id filter:

| Event | Direct or grouped evidence | Claim |
|-------|----------------------------|-------|
| `agentsec.control.decision` | 1 indexed event, 1 distinct raw, CTRL-MCP-001, DENY, `tool_not_granted`, `lookup_customer_tier` | Decision OBSERVED |
| `agentsec.hop.started` | present on the run | Stage present |
| `agentsec.hop.completed` | outcome `hop_denied` | Outcome OBSERVED |
| `agentsec.pipeline.stopped` | present | Stage present |
| `agentsec.run.started` | present | Stage present |
| `agentsec.run.completed` | outcome `completed_denied` | Outcome OBSERVED |
| `agentsec.mcp.started` | not in the event list | Invocation NOT OBSERVED |
| `agentsec.mcp.completed` | not in the event list | Completion NOT OBSERVED |
| A separate request event before the decision | not in the event list | Request as its own event NOT OBSERVED |

The workshop sequence search would not show the hop or run outcome rows, because those events do not carry `agentsec.control.id=CTRL-MCP-001`.

A second run, discovered from ATTACK + ALLOW rather than from memory, `00cd3a63-1dee-4f87-8e77-921ab9610679`, has one indexed `agentsec.mcp.started` (`count=1`, `dc(_raw)=1`, `event.name` mvcount 3, tool `lookup_customer_tier`). Reason on the decision sample: `vulnerable_profile_fail_open:caller_identity_derived_authority`. Grouped results also listed `agentsec.mcp.completed` with `distinct_raw=1` and outcomes `hop_allowed` and `completed_allowed`. Invocation is OBSERVED for that run. The workshop sequence search would still hide it.

CTRL-MCP-001 remains the decision on the decision event. Splunk did not create that decision.

### External false lead

`Q-BRIDGE-EXTERNAL.spl`:

| Sourcetype | Indexed rows | Distinct raw | Distinct runtime run ids | Other values |
|------------|--------------|--------------|---------------------------|--------------|
| `agentsec:external:evaluation` | 8 | 1 | 0 | native result PASS, correlation method `identity_tuple` |
| `agentsec:scanner:finding` | 27 | 6 | 0 | severity HIGH, correlation method `hash_join` |

Scanner HIGH is present and is not a CTRL-MCP-001 DENY. Garak PASS is present and is not a runtime authorization. Neither sourcetype contributed a runtime run id. The learner-facing line for that gap is CORRELATION NOT ESTABLISHED. The challenge text says that. It does not say the lab is protected.

### Zero rows

A review probe for `agentsec.testbed.mode=MODE_NOT_PRESENT_FOR_REVIEW` returned `count=0`. Class: MEASURED. The dashboard's empty-state sentences (NO EVIDENCE FOUND, INSUFFICIENT EVIDENCE, CORRELATION NOT ESTABLISHED) were not forced on screen by shutting Splunk down. Those strings are in the view. Class for the rendered empty panel: NOT TESTED.

## 5. Learner SPL

DISCOVER shows a stats command with `stats _____` and does not show the finished aggregation. That was observed in Splunk Web. PATH B · REVIEW shows the finished command, including `dc(agentsec.run.id) as distinct_runs`. That tab is visible. This matches accepted Path B practice. It is not hidden.

The finished command runs and returns rows. Those rows use `stats count by agentsec.testbed.mode`, so `indexed_rows` is the inflated figure (ATTACK ALLOW 540 in the workshop stats output versus 60 events after `mvdedup`).

Skill shown: MODIFY. The learner completes a supplied skeleton. That is beyond COPY. It is not a from-scratch WRITE. Authoring: PARTIAL.

## 6. UI and accessibility

Splunk Web, Chrome, view `ws_lab_splunk_defender_bridge`. Page errors: 0.

| Width | Horizontal overflow |
|-------|---------------------|
| 1920 | false |
| 1440 | false |
| 1280 | false |
| 1024 | false |

Tabs opened: MISSION, DISCOVER, INVESTIGATE, CHALLENGE, PATH B · REVIEW. Mission contains the security question and Beginner. It does not contain "was denied". Home contains "Splunk Defender Bridge".

Keyboard: focus started on MISSION. ArrowRight moved focus to DISCOVER. Mission tab computed outline was `rgb(0, 110, 170) none 3px`.

CSS `zoom: 2` on `documentElement` at a 1024 viewport: horizontal overflow true. That is a CSS zoom approximation, not a 200% browser zoom and not a screen-reader test.

Screen reader: NOT TESTED. No WCAG claim.

UI at the four widths: PASS. Accessibility: PARTIAL.

## 7. Security semantics

Running container: `CONTROL_ID` is `CTRL-MCP-001`, schema `1.9.0`, ExternalEvidence `1.0.0`, package `1.0.0rc1`.

Workshop text keeps Splunk downstream and says scanner and garak do not authorize. No authorization call was added. Running `savedsearches.conf` has `disabled = 1` and `enableSched = 0` on the AgentSec stanza. Enabled detector added: NO.

RAG and memory controls remain separate ids in the field summary (`CTRL-RAG-CONTEXT-001`, `CTRL-MEMORY-CONTEXT-001`). This review did not re-prove their PDP behavior with a new launch. The bridge searches do not route them into CTRL-MCP-001. Class for "no semantic change in this commit": the diff is curriculum and Studio, and the running PDP id is unchanged. Class: MEASURED for the running id; the absence of a code change is the reviewed commit's file list.

## 8. Tests

Focused, no rerun:

`uv run --extra test python -m pytest tests/splunk/test_splunk_defender_bridge.py tests/splunk/test_agentsec_ui_shell.py tests/unit/test_phase16d_academy.py -q --tb=line`

**25 passed in 0.12s.**

Full offline, no rerun:

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`

**1033 passed, 3 deselected in 9.98s.**

No failure was hidden. Offline tests do not execute these searches, so they did not catch HIGH-1 or HIGH-2.

## 9. Secret hygiene

The bridge workshop files have no AWS-style keys, GitHub tokens, private-key blocks, `SPLUNK_PASSWORD`, or workstation home paths. `.env` was read locally to authenticate and was not printed or committed. PASS.

## 10. Learner-journey ratings

| Step | Rating | Why |
|------|--------|-----|
| Question | PASS | Mission starts from a security question and a hypothesis. |
| Discovery | PASS | First search has no run id and returned decisions, tools, reasons, and modes. |
| Candidate identification | PASS | Narrowing to CTRL-MCP-001 DENY returned run identifiers. |
| Correlation | PARTIAL | A follow-up by the discovered id shows decision and outcome. The shipped sequence search drops those outcome events and all MCP execution events. |
| SPL modification | PASS | The stats blank is real and the finished line is not on DISCOVER. |
| Small SPL authoring | PARTIAL | The index, constraints, and `by` clause are supplied. Path B contains the finished command. |
| Comparison | PARTIAL | Mode and decision differences are real. The shipped comparison does not show execution, and its counts are inflated. |
| Evidence challenge | PASS | External rows have HIGH or PASS and zero runtime run ids. The page says CORRELATION NOT ESTABLISHED. |
| Bounded conclusion | PARTIAL | Mission does not declare a verdict. Path B tells the learner that `indexed_rows` greater than `distinct_raw` means restaged copies. On this volume that is not what the gap is. |

L5 → bridge: PASS for the skill that was missing, which is finding a candidate without a handed-out run id.

Bridge → L6: PARTIAL. L6 is a reasonable next page only after the sequence search and the duplicate explanation are corrected. As shipped, a careful beginner can leave believing denials were indexed nine times and that outcome events do not exist.

## 11. Findings

### HIGH-1 — Sequence and comparison searches hide events that share the run

`Q-BRIDGE-SEQUENCE.spl` and `Q-BRIDGE-COMPARE.spl` require `agentsec.control.id=CTRL-MCP-001` on every event, including `agentsec.mcp.started`, `agentsec.mcp.completed`, and `agentsec.mcp.failed`.

Measured: those three execution event names have `dc(agentsec.control.id)=0`. The sequence search therefore cannot show invocation or completion. The same filter also drops `agentsec.hop.completed` and `agentsec.run.completed`. For candidate `06c41bc2-4971-4b5c-bf42-5774ab2b439d` those outcome events exist (`hop_denied`, `completed_denied`) and MCP execution events do not. A learner who trusts the sequence table will mark a present outcome as absent.

Remediation: correlate execution and outcome by the discovered `agentsec.run.id` without requiring `agentsec.control.id` on non-decision events. Keep missing MCP events missing.

### HIGH-2 — `count` by a multivalue mode field is not duplicate indexing

Every measured CTRL-MCP-001 decision has `mvcount('agentsec.testbed.mode')=3`, and a no-split stats shows `count=dc(_raw)=141`.

`stats count by agentsec.testbed.mode` multiplies the count by about three. The narrow row for the candidate says `indexed_rows=9` where a direct count is 1. Path B says a larger `indexed_rows` than `distinct_raw` means replayed or restaged copies.

That conclusion is not supported on this volume. `distinct_raw` is the event count. The larger number is the multivalue split. The safe half of the lesson still holds: do not treat `count` as an execution count. The causal half does not.

Remediation: `mvdedup` or `mvindex` before `stats by`, and describe the 3× field repetition as a parsing or field-cardinality issue unless a no-split `count` versus `dc(_raw)` actually differs.

### LOW-1 — Path B shows the finished stats command

Observed in the browser. The mission and DISCOVER do not. This is the existing Path B pattern. It keeps authoring at MODIFY rather than WRITE. Not a reason to hide the tab during this gate.

### LOW-2 — CSS zoom overflow

At CSS zoom 2 on a 1024 viewport, horizontal overflow was true. Ordinary widths 1920, 1440, 1280, and 1024 did not overflow. Not a WCAG result.

### INFORMATIONAL

- Running AcmeBank and Attack Service are `1.0.0rc1`. Splunk app.conf after refresh is `1.0.0-rc2`.
- AcmeBank health was `degraded` because Ollama was not reachable. This replay did not need a new launch.
- `lab-ready.sh` does not mention the bridge view.
- Field summary lists example run identifiers. They come from indexed events, not from the mission text.

## 12. Counts

BLOCKER: 0

HIGH: 2

MEDIUM: 0

LOW: 2

INFORMATIONAL: 4

## 13. Decision

CONDITIONAL GO — REMEDIATION REQUIRED

Discovery without a supplied run id is measured and works. That was the gap between L5 and L6. GO is not met because the shipped sequence search hides same-run outcome and execution evidence, and the shipped duplicate stats teach a restage explanation that this index does not support. Offline tests alone would have missed both.

Application code modified by this review: NO

Runtime semantics modified: NO

Schema modified: NO

ExternalEvidence modified: NO

RC2 tag modified: NO

RC3 created: NO
