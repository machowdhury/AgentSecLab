# Detection Engineering workshop — independent review

**Historical Review Record.** This document records an intermediate AgentSec development/review state prior to the final v1.0.0 release. It is retained for engineering traceability and should not be interpreted as the current product state.

Read-only review of `b566ecd53b2cbfd997b8f441bc960388eddbe854` on `develop`. The product, tests, SPL, dashboards, saved searches, runtime, schema, and ExternalEvidence contract were not modified. This file is the review artifact.

Evidence classes: OBSERVED, MEASURED, DOCUMENTED. No new attack was launched and no telemetry was added.

## Baseline

| Ref | Commit |
|---|---|
| HEAD | `b566ecd53b2cbfd997b8f441bc960388eddbe854` |
| origin/develop | same |
| Starting commit of the implementation | `aeee71a9a9b4238f3245430d286bd8d5377ec2cd` (ancestor) |
| main | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| v1.0.0-rc1 | `1aafacb02f4429f168fbdce61437dc37d4cfc74b` |
| v1.0.0-rc2 | `bd8c2c02729497018b4e28b582fe6c9a9e052638` |
| v1.0.0-rc3 | not present |

Working tree at review start: `develop` matches `origin/develop`, plus pre-existing untracked `docs/plans/`. The implementation diff `aeee71a..b566ecd` is eight files. It does not touch `savedsearches.conf`, `DET-MCP-001.spl`, `src/agentsec/experiment.py`, `src/agentsec/external_evidence/contract.py`, or `src/agentsec/mcp/authorize.py`.

## Workshop uniqueness

DOCUMENTED and OBSERVED in the tree: one checkpoint `DETECTION-ENGINEERING`, one lab `LAB-DETECTION-ENGINEERING`, one view `ws_lab_detection_engineering`. Placement string is `L6 → Detection Engineering Workshop → L7`. Mode `REPLAY`. `live_launcher` is false. Level ids remain L0–L10. L6 learn text points at the workshop. L7 prerequisites name it. Nav places the view after Blue Team and before Threat Modeling. The lab id is not in `known_lab_ids()`. Other files whose names contain "detection engineering" are design notes and older models, not a second workshop.

## DET-MCP-001

`savedsearches.conf` has three stanzas, each `disabled = 1`. The MCP stanza also has `enableSched = 0` and `dispatch.earliest_time = -24h`. No `disabled = 0`. The stanza was not changed in this implementation range.

`DET-MCP-001.spl` still matches any control-decision `DENY`. It does not filter `agentsec.control.id`. It uses `min()` for the DENY sequence and `latest()` for copied fields. `DET-MCP-001.md` now calls the file a disabled teaching candidate at maturity **LOGIC_VALIDATED**, and says it is not production, not operationally validated, and not proof of prevention, compromise, or an incident. That maturity claim matches the evidence class below: synthetic positive plus indexed non-matches. It is not SCENARIO_VALIDATED.

## Hypothesis, correlation, and order

The mission question is whether a tool execution after a CTRL-MCP-001 DENY of that same tool can be detected. Path A requires `agentsec.run.id` and then `gen_ai.tool.name`, then `agentsec.sequence` greater than the DENY sequence. The broad search groups by run only and has no sequence test. The tuned search groups by `run_id tool`, requires `control_id="CTRL-MCP-001"` on the DENY test, and keeps rows only when `sequence>deny_sequence`. The tuned search does not reduce to "DENY exists AND start exists."

The tuned search uses `min()` of the DENY sequence and does not copy metadata with `latest()`. Path B states that the shipped file can mix two DENY rows and that the workshop query does not, and that this is not a universal claim. MEASURED tuned result was 0 rows, so that `min()` versus `latest()` split was not observed on an indexed same-tool match. The limitation is bounded in the lesson. It is not a false description of the shipped file.

## Live Splunk

MEASURED against the existing index. No new events were written.

| Search | Result |
|---|---|
| `Q-DET-BROAD.spl` | 2 RETEST rows. Both deny `lookup_customer_tier` and start `lookup_policy`. |
| `Q-DET-TUNED.spl` | 0 rows. |
| `DET-MCP-001.spl` with `earliest=0` | 0 rows. |
| Positive control | 1 row, `evidence_class=SIMULATED`, run `simulated-det-mcp-001-0001`. The file is `makeresults`. |
| CTRL-MCP-001 decisions | ATTACK ALLOW 60, ERROR 8. BASELINE ALLOW 16, ERROR 1. RETEST ALLOW 8, DENY 48. No ATTACK or BASELINE DENY. |
| Fail-open ALLOW then later same-tool `mcp.started` | ATTACK only: 50 runs, 50 start rows. |

ATTACK, RETEST, and BASELINE are **NO_MATCH** for the DENY-then-start candidate. That is the lesson. The measured ATTACK behavior that this predicate misses is fail-open ALLOW followed by a later start of the same tool.

The two broad runs, listed only for the decision and start events in this pass:

- `0ab10594-a7fc-48b6-81bf-4cbca54a64c6`: sequence 3 CTRL-MCP-001 ALLOW `lookup_policy`, sequence 4 `mcp.started` `lookup_policy`, sequence 9 CTRL-MCP-001 DENY `lookup_customer_tier`.
- `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`: sequence 4 CTRL-MCP-001 ALLOW `lookup_policy`, sequence 5 `mcp.started` `lookup_policy`, sequence 9 CTRL-MCP-001 DENY `lookup_customer_tier`.

Same-run correlation flags both. Same-tool correlation does not. The start is before the DENY in both runs. Run id alone is insufficient. Path B states that for both runs and gives the first run's ALLOW. It gives the second run's start and DENY and does not mention the measured sequence-4 ALLOW. That omission is incomplete. It does not reverse the order.

## Learner path

Path A starts from the security question, withholds run ids, withholds `eventstats`, and numbers ten steps through discovery, the broad candidate, the different-tool false correlation, tool identity, sequence order, mode comparison, and a coverage statement. Finished broad and tuned searches run only on Path B, labeled as an answer key, not policy.

False-positive work asks for a row the learner found and says not to invent an approval workflow. Compare text separates a different tool in the same run from gaps the learner may only be reasoning about, and it requires OBSERVED versus POSSIBLE. The same-run, different-tool RETEST case is the observed false correlation.

False-negative work states the primary gap as ALLOW then `agentsec.mcp.started`, because the candidate looks for DENY then a later start. A second hypothesis for that gap stays NOT IMPLEMENTED. The page does not print "ATTACK = NO_MATCH" as the mission answer. It does tell the learner, before they finish, that fail-open ALLOW then start is outside the predicate. That is scaffolding, and the measured corpus supports it.

The coverage tab requires the learner to say what the detection looks for, what it does not, what matched, and whether that row was indexed or simulated. It states that a detection name is not detection coverage, coverage is not attack coverage, a match is not an incident, and Splunk does not send a finding back to CTRL-MCP-001. Required gap labels include NO EVIDENCE FOUND, CORRELATION NOT ESTABLISHED, INSUFFICIENT EVIDENCE, NO MATCH, NOT OBSERVED, and NOT PROVEN. The page forbids SAFE, SECURE, PROTECTED, and NO ATTACK as conclusions.

Scanner HIGH is not execution and not DENY. Garak PASS is not runtime safety. An external finding is not a DET-MCP-001 match and not a CTRL-MCP-001 decision. No new external tool was added.

The positive control is labeled SIMULATED on the coverage tab and on Path B. It is not described as indexed runtime behavior or as live detection effectiveness.

## UI and accessibility

OBSERVED in headless Chrome on the restaged view. Screen reader: NOT TESTED. WCAG compliance is not claimed.

Tabs MISSION, HYPOTHESIS, CORRELATE, COMPARE, COVERAGE, and PATH B · REVIEW were present. The mission view did not contain the reviewed run id. Path B text contained SIMULATED and that run id.

Viewports 1920, 1440, 1280, and 1024: `scrollWidth` equaled `clientWidth`. No horizontal overflow.

`documentElement.style.zoom = 2` at a 1024 viewport: overflow, `clientWidth` 1024, `scrollWidth` 1920. That is geometric zoom, not reflow.

A 512 CSS-pixel viewport overflowed (`scrollWidth` 960, `clientWidth` 512). The widest elements were the document body, Splunk's layout header, and the app navigation bar. This is Splunk chrome at that width, not a workshop table by itself.

Keyboard: focusing the MISSION tab and pressing Tab moved focus to PATH B · REVIEW. Arrow-key movement inside the tab list was not tested. Computed `outline-style` on the focused tab was `none`. A separate indicator was present: inset `box-shadow` of 1px white and 3px `rgb(0, 110, 170)`. A keyboard user can see which tab is focused. The earlier implementation note that reported only `outline-style: none` missed that ring.

## Tests and hygiene

Focused set, including `tests/splunk/test_detection_engineering_workshop.py`: 23 passed in 0.12s. The workshop file itself contains four tests; that command exited 0.

Full offline command `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`: 1037 passed, 3 deselected, in 8.94s. These tests do not execute SPL.

The implementation diff contains no credentials, tokens, private keys, certificates, `.env`, or cryptographic code. The word `SPLUNK_PASSWORD` appears only in the implementation report's statement that the password was not printed. Schema remains `1.9.0`. ExternalEvidence contract remains `1.0.0`.

## Curriculum ratings

Detection engineering coverage of this lesson is strong: one hypothesis, a measured miss, and an explicit coverage statement. It is not a full detection-engineering program.

Blue-team progression is strong in placement. The written statement is required on the page and is not collected or graded.

Splunk progression is strong on Path A because the finished correlation is withheld. Path B remains one tab away, which is the existing answer-key pattern.

Coverage reasoning is strong. The page separates the detection name, what the predicate can match, and the fail-open ATTACK it does not match.

## Findings

No BLOCKER, HIGH, or MEDIUM findings.

LOW-01. `learning/level_1/LAB-MCP-001/dashboard.md`, the MCP-001 dashboard builder, the generated MCP-001 dashboard, and `docs/MCP_SEARCH_CONTRACT.md` still say "operational detection." The DETECT panel also says the saved search "continuously checks" the invariant, then says it is packaged disabled, that the dashboard does not enable it, and that it did not fire. A disabled search with `enableSched = 0` is not continuously checking. The same paragraph limits the claim. The workshop page and `DET-MCP-001.md` do not repeat "operational detection." `DET-MCP-001.md` still says "Operationalization of `Q-MCP-AFTER-DENY.spl`," which describes where the SPL came from, next to a status table that says disabled and LOGIC_VALIDATED.

LOW-02. Path B omits the measured sequence-4 CTRL-MCP-001 ALLOW of `lookup_policy` on `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`. The order it does state is correct: the policy start is not after the customer-tier DENY.

LOW-03. CSS zoom 2 and the 512px reflow overflow. The focus ring exists as an inset box-shadow even though `outline-style` is none. Screen reader was not tested. One Tab moved from MISSION to PATH B; arrow keys were not tested. Not a release blocker for this REPLAY page.

## Verdict

The workshop reuses the existing REPLAY checkpoint, teaches same-run then same-tool then sequence order, and the indexed candidate does not match ATTACK, RETEST, or BASELINE. The miss is taught as a coverage gap. The detector stays disabled.

GO — DETECTION ENGINEERING COMPLETE; AUTHORIZE IDENTITY & NON-HUMAN IAM DESIGN

Design only. This review does not start that design.
