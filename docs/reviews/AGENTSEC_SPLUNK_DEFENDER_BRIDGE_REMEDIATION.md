# Splunk Defender Bridge remediation

**Date:** 2026-09-28
**Parent commit:** `e33b0813b421affb9dd95b9005db9c2fc07bd11a` (independent review, local at remediation start)
**Reviewed product build:** `1ecd883483fb98459a53952270d046d3c3b82175`
**Mode:** bounded remediation of the independently demonstrated Defender Bridge defects. No new attack, detector, live lab, schema change, contract change, tag move, or RC3.

Class for the Splunk figures below: MEASURED on the existing `index=agentsec_telemetry` volume during this remediation. No new attack was launched. These numbers describe this index. They are not universal product semantics and they are not written into the learner mission as expected answers.

## 1. Original findings

Independent review `e33b081` decision: CONDITIONAL GO — REMEDIATION REQUIRED.

### HIGH-01 — control id required on every correlated event

`Q-BRIDGE-SEQUENCE.spl` and `Q-BRIDGE-COMPARE.spl` required `agentsec.control.id=CTRL-MCP-001` on every returned event. Measured execution events `agentsec.mcp.started`, `agentsec.mcp.completed`, and `agentsec.mcp.failed` have no control id. The same filter dropped `agentsec.hop.completed` and `agentsec.run.completed`, including `hop_denied` and `completed_denied`.

### HIGH-02 — multivalue mode treated as restaged copies

No-split CTRL-MCP-001 decisions were `count=dc(_raw)=141`, with `mvcount(agentsec.testbed.mode)=3`. Grouping by the raw mode field multiplied the apparent count. Path B described that gap as restaged copies. That cause is not supported by this volume.

The review also rated learner SPL authoring PARTIAL, because Path A supplied a nearly complete `stats` skeleton, and the bounded conclusion PARTIAL, because the restaged-copy sentence taught an unsupported claim.

LOW-1 (Path B shows the finished stats command) and LOW-2 (CSS zoom overflow) were left in place. This remediation does not hide Path B and does not redesign the shell.

## 2. Root cause

HIGH-01 was an investigation-model error, not missing runtime telemetry. CTRL-MCP-001 is carried on authorization decision events. Execution and outcome events for the same `agentsec.run.id` often have an empty control id. Requiring the control id on the pivot hid those events. Runtime telemetry was not changed to add a control id.

HIGH-02 was a Splunk grouping effect. Each relevant decision holds the same mode value three times. `stats` by that multivalue field counts the event more than once. A no-split `count` equals `dc(_raw)`, so this volume does not show extra raw copies of those decisions.

## 3. Changes

Workshop and searches only. `src/agentsec` authorization code, schema, ExternalEvidence, saved searches, Attack Service routes, and L6/L9/L10 were not modified.

- Discovery still has no run id. Display fields are reduced with `mvindex(mvdedup(...),0)` so a repeated mode does not look like three different values.
- Narrow still discovers DENY candidates for CTRL-MCP-001, then groups by the discovered run id. Mode is deduplicated before `stats`.
- Sequence keeps CTRL-MCP-001 and DENY only inside the subsearch that selects up to three candidate run ids. The outer search returns every indexed event for those runs, in time order, and projects control id, decision, reason, tool, and outcome. Empty cells stay empty.
- Authorization comparison stays on `agentsec.control.decision` and CTRL-MCP-001.
- A separate execution/outcome comparison covers `agentsec.mcp.started`, `agentsec.mcp.completed`, `agentsec.mcp.failed`, `agentsec.hop.completed`, and `agentsec.run.completed`. It does not filter on CTRL-MCP-001.
- The no-split duplicate search reports indexed rows, `dc(_raw)`, distinct run ids, and `max(mvcount(agentsec.testbed.mode))`. It has no `by` clause.
- Mode grouping uses one mode value per event before `stats by mode`.
- Path A asks the learner to write the stats transformation. It gives a goal, the fields, and one hint: check `mvcount` on mode and deduplicate a repeated value before `by`. The finished pipeline stays on Path B.
- The conclusion exercise asks for authorization, execution, outcome, external evidence, and at least one NOT PROVEN. The word "restaged" was removed.
- Learning note `docs/learning-notes/splunk-defender-bridge.md` now states the same correlation and count distinctions.

## 4. Corrected SPL semantics

Authorization evidence is a CTRL-MCP-001 control decision: decision, reason, and requested tool. Execution and outcome evidence is whatever else shares the discovered `agentsec.run.id`: event name, tool, hop outcome, completion or failure. A missing stage stays NOT OBSERVED. ALLOW is not execution. DENY is not universal prevention. ERROR stays ERROR. RETEST is not a safety claim. BASELINE is not a trust claim.

`count` is indexed rows in that aggregation. `dc(_raw)` is distinct raw events. `dc(agentsec.run.id)` is distinct run identifiers. `mvcount` is how many values one field holds. An execution count requires an execution event. `stats` by a multivalue field can raise `count` when `dc(_raw)` does not. Compare a search with no `by` clause before naming a cause.

The sequence subsearch uses `head 3`. The table is a sample of denied-authorization runs, not the population. If that subsearch ever returned no rows, Splunk can drop it and the outer search would match every `otel:agentic:json` event. This volume returned DENY candidates, so that footgun did not fire.

## 5. Live evidence

Lab startup for the restaged view: `./scripts/lab-up.sh --refresh-app`. It printed Lab is READY. Class: OBSERVED.

Running versions, measured after refresh:

| Surface | Result |
|---------|--------|
| AcmeBank `/health` | `version=1.0.0rc1`, `status=degraded`, `ollama_reachable=false` |
| AcmeBank package inside the container | `1.0.0rc1`, schema `1.9.0`, ExternalEvidence `1.0.0`, `CONTROL_ID=CTRL-MCP-001` |
| Attack Service `/health` | `version=1.0.0rc1`, `schema_version=1.9.0`, `status=healthy` |
| Attack Service package inside the container | `1.0.0rc1` |
| Splunk `app.conf` after refresh | `version = 1.0.0-rc2` |
| Running `savedsearches.conf` | AgentSec stanza `disabled = 1`, `enableSched = 0` |

The running application containers remain **1.0.0rc1**. The Splunk app file says 1.0.0-rc2 because refresh copied the current tree. This remediation does not call the running stack RC2. Images were not rebuilt.

### Discovery without a run id

`Q-BRIDGE-DISCOVER.spl` does not contain `agentsec.run.id`. It returned 25 control-decision rows. The sample included CTRL-MCP-001 ALLOW `tool_granted` for `prepare_support_contact` in RETEST and ATTACK, CTRL-MCP-001 DENY `tool_not_granted` for `lookup_customer_tier` in RETEST, and a vulnerable-profile ALLOW whose reason says fail-open. Other control ids in the same sample included CTRL-INPUT-001. Mode, decision, and tool cells were single values after `mvdedup`.

### Candidate run ids

`Q-BRIDGE-NARROW.spl` returned 48 CTRL-MCP-001 DENY rows. The first three were RETEST, `lookup_customer_tier`, `tool_not_granted`, each with `indexed_rows=1` and `distinct_raw=1`. The earlier 9× narrow count is gone. Run identifiers came from the index. None were typed into the search as a filter.

### Sequence

The sequence search selected three DENY runs and returned 26 events in `run_id` then `_time` order. Events with an empty `control_id` included `agentsec.run.started`, `agentsec.hop.started`, `agentsec.memory.recalled`, `agentsec.pipeline.stopped`, `agentsec.hop.completed` (`hop_allowed` and `hop_denied`), and `agentsec.run.completed` (`completed_denied`). CTRL-MCP-001 DENY `tool_not_granted` was present on each sampled run. CTRL-MEMORY-CONTEXT-001 OBSERVE appeared where memory was recalled. `agentsec.mcp.started` was not in these three DENY samples. That absence is NOT OBSERVED for those runs. It is not a control-id filter: the outer search does not require CTRL-MCP-001.

A confirmatory probe of MCP event names, not a workshop search, returned `dc(agentsec.control.id)=0` for `agentsec.mcp.started`, `agentsec.mcp.completed`, and `agentsec.mcp.failed`. That probe grouped by the raw `event.name` field and its `count` was about three times `dc(_raw)` (started 252/84, completed 237/79, failed 15/5). That inflation is the same multivalue grouping effect. The workshop execution search deduplicates before `by`, and there `indexed_rows` equals `distinct_raw`.

### Authorization comparison

`Q-BRIDGE-COMPARE.spl`, after one mode value and one decision value per event:

| Mode | Decision | Indexed rows | Distinct raw | Distinct runs |
|------|----------|--------------|--------------|---------------|
| ATTACK | ALLOW | 60 | 60 | 58 |
| ATTACK | ERROR | 8 | 8 | 8 |
| BASELINE | ALLOW | 16 | 16 | 16 |
| BASELINE | ERROR | 1 | 1 | 1 |
| RETEST | ALLOW | 8 | 8 | 8 |
| RETEST | DENY | 48 | 48 | 48 |

`indexed_rows` equals `distinct_raw` on every row. ERROR remains ERROR. These figures are this volume only.

### Execution and outcome comparison

`Q-BRIDGE-COMPARE-EXECUTION.spl` does not mention CTRL-MCP-001. After dedup, `indexed_rows` equals `distinct_raw` on every row.

| Mode | Event | Indexed rows | Distinct runs | Outcomes present |
|------|-------|--------------|---------------|------------------|
| ATTACK | hop.completed | 167 | 102 | hop_allowed, hop_denied, hop_error |
| ATTACK | mcp.completed | 60 | 58 | none on the outcome field |
| ATTACK | mcp.started | 60 | 58 | none on the outcome field |
| ATTACK | run.completed | 94 | 94 | completed_allowed, completed_denied |
| BASELINE | hop.completed | 43 | 27 | hop_allowed, hop_error |
| BASELINE | mcp.completed | 11 | 11 | none on the outcome field |
| BASELINE | mcp.failed | 5 | 5 | none on the outcome field |
| BASELINE | mcp.started | 16 | 16 | none on the outcome field |
| BASELINE | run.completed | 21 | 21 | completed_allowed, completed_denied |
| RETEST | hop.completed | 125 | 85 | hop_allowed, hop_denied |
| RETEST | mcp.completed | 8 | 8 | none on the outcome field |
| RETEST | mcp.started | 8 | 8 | none on the outcome field |
| RETEST | run.completed | 85 | 85 | completed_allowed, completed_denied |

RETEST `mcp.started` distinct runs (8) line up with RETEST ALLOW (8) on this volume. That is consistent with the sampled DENY runs not showing `mcp.started`. It does not prove that every future DENY skips execution. BASELINE has 16 ALLOW decisions, 16 `mcp.started`, 11 `mcp.completed`, and 5 `mcp.failed`. Completion is not the same number as ALLOW.

`Q-BRIDGE-STATS.spl` on Path B matches the authorization comparison counts above.

### Counts and multivalue mode

`Q-BRIDGE-DUPLICATES.spl`: indexed rows 141, distinct raw 141, distinct runs 137, `mode_value_count` 3.

`Q-BRIDGE-DUPLICATES-BY-MODE.spl`, after `mvindex(mvdedup(mode),0)`: ATTACK 68/68/66, BASELINE 17/17/17, RETEST 56/56/54. 68 is 60 ALLOW plus 8 ERROR. There is no 3× inflation. The unsupported restaged-copy sentence is absent from the workshop sources and from the restaged view file.

### External evidence

`Q-BRIDGE-EXTERNAL.spl`:

| Sourcetype | Indexed rows | Distinct raw | Distinct runtime run ids | Other values |
|------------|--------------|--------------|---------------------------|--------------|
| `agentsec:external:evaluation` | 8 | 1 | 0 | PASS, `identity_tuple` |
| `agentsec:scanner:finding` | 27 | 6 | 0 | HIGH, `hash_join` |

HIGH is not DENY. PASS is not a runtime allow. `hash_join` and `identity_tuple` are not runtime causality. Zero runtime run ids remain CORRELATION NOT ESTABLISHED. This remediation did not assign a cause to the external indexed-row versus distinct-raw gap. The external architecture was not modified.

## 6. Tests

Focused:

`uv run --extra test python -m pytest tests/splunk/test_splunk_defender_bridge.py tests/splunk/test_agentsec_ui_shell.py tests/unit/test_phase16d_academy.py -q --tb=line`

**25 passed in 0.28s.**

Those tests cover discovery without a supplied run id, CTRL-MCP-001 candidate narrowing, sequence text that does not require the control id on the outer search, a separate execution comparison, no "restaged" claim, multivalue handling before `by`, external non-authority, no enabled detector, schema 1.9.0, and ExternalEvidence 1.0.0. They do not execute the searches. The live section above is the execution evidence.

Full offline, first run:

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`

**1 failed, 1032 passed, 3 deselected in 9.36s.**

Failure: `tests/unit/test_phase15b_rag_learning_loop.py::test_concurrent_rag_attack_and_retest_do_not_leak_profile`. The assertion `retest["runtime"]["lookup_customer_tier_handler_count"] == 0` saw 1. This remediation does not change RAG launch code. An isolated rerun of that test passed in 0.35s. A second full run passed: **1033 passed, 3 deselected in 9.58s.** The first failure is recorded. It was not reproduced.

## 7. UI

Splunk Web, Chrome, view `ws_lab_splunk_defender_bridge`, after `--refresh-app`. Page errors: 0.

| Width | Horizontal overflow |
|-------|---------------------|
| 1920 | false |
| 1440 | false |
| 1280 | false |
| 1024 | false |

Tabs opened: MISSION, DISCOVER, INVESTIGATE, CHALLENGE, PATH B · REVIEW. Home lists Splunk Defender Bridge. Mission contains the security question and Beginner, and does not contain "was denied". DISCOVER says to write the command and does not contain the finished `mvindex(mvdedup('agentsec.testbed.mode'),0)` pipeline. INVESTIGATE shows the authorization comparison and the execution/outcome comparison, including `mode_value_count`. CHALLENGE contains indexed rows, NOT PROVEN, and CORRELATION NOT ESTABLISHED, and does not contain "restaged". Path B contains the finished pipeline and the false-lead language, and does not contain "restaged".

Keyboard: focus started on MISSION. ArrowRight moved focus to DISCOVER. Mission tab computed outline was `rgb(0, 110, 170) none 3px`.

CSS `zoom: 2` on `documentElement` at a 1024 viewport: horizontal overflow true. That is a CSS zoom approximation, not a 200% browser zoom and not a screen-reader test.

Screen reader: NOT TESTED. No WCAG claim.

UI at the four widths: PASS. Accessibility: PARTIAL.

## 8. Security regression

CTRL-MCP-001 remains the tool PDP. The bridge text still says Splunk, scanner, and garak do not authorize. RAG and memory controls are separate ids and were not routed into CTRL-MCP-001. No authorization function was edited. No detector was enabled. No Attack Service route was added. Schema remains 1.9.0. ExternalEvidence remains 1.0.0.

## 9. Secret hygiene

Changed workshop files, the builder, the learning note, and this report were scanned for AWS-style keys, GitHub tokens, live secret-key prefixes, private-key blocks, certificate blocks, `SPLUNK_PASSWORD`, and a workstation home path. None were present. `.env` was read locally to authenticate to Splunk Web and to the Splunk REST export. The password was not printed and was not committed. No certificate was added. No cryptographic algorithm was added.

Codeguard credential rule: applied by keeping secrets out of source. The local Splunk password stays in `.env`.
Codeguard certificate rule: applied by not introducing certificate material.
Codeguard crypto rule: applied by not adding hash, cipher, or key-exchange code.

## 10. Remaining limitations

1. AcmeBank and Attack Service containers are still 1.0.0rc1. Final 1.0 still requires an image rebuild and clean-room validation. This remediation did not do either.
2. The sequence table is a `head 3` sample of DENY runs. `agentsec.mcp.started` was NOT OBSERVED on that sample. The empty-subsearch footgun remains if a future volume has no DENY rows.
3. Path B still shows the finished stats command. CSS zoom overflow at the approximation above remains. Screen reader was not tested. `lab-ready.sh` still does not check the bridge view. AcmeBank was degraded because Ollama was unreachable. External indexed-row versus distinct-raw gaps were not given a new cause. The intermittent RAG concurrency failure above was not fixed here.

## 11. Git boundary

`main`, `origin/main`, `v1.0.0-rc1`, and `v1.0.0-rc2` were not moved. No RC3 tag and no GitHub Release. Untracked `docs/plans/` was not staged.
