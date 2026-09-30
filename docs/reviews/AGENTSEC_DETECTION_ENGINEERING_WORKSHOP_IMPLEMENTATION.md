# Detection Engineering workshop — implementation report

Evidence classes used below: OBSERVED, MEASURED, DOCUMENTED, SIMULATED. This report does not claim production detection readiness, operational validation, or WCAG conformance.

## Learner objective

Reuse the existing REPLAY workshop `LAB-DETECTION-ENGINEERING`. The learner starts from a detection hypothesis, builds SPL in steps, and writes a coverage statement. No run id is supplied on Path A.

## Detection hypothesis

A `gen_ai.tool.name` starts (`event.name=agentsec.mcp.started`) after CTRL-MCP-001 has denied that same tool in the same `agentsec.run.id`, with `agentsec.sequence` of the start greater than the DENY sequence.

## Telemetry used

Indexed fields the workshop names: `event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.testbed.mode`. Index `agentsec_telemetry`, sourcetype `otel:agentic:json`. Workshop searches set `earliest=0`. The disabled saved search window remains `-24h`. Those windows are not the same thing. `savedsearches.conf` was not edited.

## SPL progression

Path A numbers ten steps: find DENY decisions, keep their run ids, look for starts, notice a different tool in the same run, add the tool, add sequence order, compare ATTACK / RETEST / BASELINE, state what the query detects, state what it does not, write the coverage statement. Finished `eventstats` stays on Path B.

## Correlation and time

Primary key taught: `agentsec.run.id` plus `gen_ai.tool.name`. Order is `sequence > deny_sequence` for that pair. DENY-exists AND start-exists is the broad candidate only.

The workshop tuned search uses `min()` of the DENY sequence and does not copy metadata with `latest()`. That avoids the shipped `DET-MCP-001.spl` split, where `min(sequence)` and `latest()` can describe different DENY rows. The workshop does not claim that every future multi-DENY group is unambiguous. The shipped file was not changed.

## ATTACK / RETEST / BASELINE

MEASURED 2026-09-29 against the existing index after the app restage. No new attack was launched.

| Predicate | Result |
|---|---|
| `Q-DET-EVENTS.spl` | Inventory present for ATTACK, RETEST, and BASELINE (control decisions and MCP starts). |
| `Q-DET-BROAD.spl` | 2 RETEST rows. Both deny `lookup_customer_tier` and start `lookup_policy`. |
| `Q-DET-TUNED.spl` | 0 rows. |
| `DET-MCP-001.spl` with `earliest=0` | 0 rows. |
| CTRL-MCP-001 decisions | ATTACK ALLOW 60, ERROR 8. BASELINE ALLOW 16, ERROR 1. RETEST ALLOW 8, DENY 48. |

ATTACK result for the candidate: **NO_MATCH**. The measured CTRL-MCP-001 ATTACK decisions are ALLOW and ERROR, so the DENY-then-start predicate has nothing to match. The primary ATTACK shape taught here remains ALLOW then start.

RETEST result: **NO_MATCH** for the tuned predicate. DENY rows exist. The two broad rows are an earlier start of a different tool. Same-run correlation is a false correlation. Same-tool correlation rejects it.

BASELINE result: **NO_MATCH**. No CTRL-MCP-001 DENY was in the measured baseline decision counts.

The learner page does not print those verdicts as the mission answer.

## Simulated positive

`DET-MCP-001-POSITIVE-CONTROL.spl` returned 1 row, `evidence_class=SIMULATED`, run `simulated-det-mcp-001-0001`, tool `lookup_customer_tier`, deny sequence 3, start sequence 4. **SIMULATED / MAKERESULTS_ONLY.** It checks query logic. It is not indexed runtime evidence and not live detection effectiveness.

## False-positive and false-negative reasoning

OBSERVED false correlation: same run, different tools, start sequence before the DENY, on the two RETEST rows above.

POSSIBLE, not claimed as observed in this pass: malformed or duplicated telemetry, ambiguous `_time` order, replayed evidence treated as new, and poor correlation-field quality.

Demonstrated coverage gap: the candidate looks for DENY then a later same-tool start. It does not look for ALLOW then start. A second hypothesis for that gap stays NOT IMPLEMENTED. DET-MCP-001 was not widened.

## Coverage statement

The COVERAGE tab requires the learner to write what the candidate detects, what it misses, and which conclusions are not justified. The intended conclusion is that DET-MCP-001 identifies a later same-tool MCP start after a CTRL-MCP-001 DENY in the same run, and that it does not cover fail-open ALLOW followed by execution. A detection name is not detection coverage. Detection coverage is not attack coverage. A match is not an incident and not an authorization decision.

## Security semantics

CTRL-MCP-001 remains the tool decision. Splunk stays downstream. Scanner HIGH is not execution and not DENY. Garak PASS is not runtime safety. An external finding is not a DET-MCP-001 match. No new external tool was added. The saved search stays `disabled = 1`. Schema remains 1.9.0. ExternalEvidence contract remains 1.0.0. No runtime, control, or cryptographic change.

Failure labels on the page include NO EVIDENCE FOUND, CORRELATION NOT ESTABLISHED, INSUFFICIENT EVIDENCE, NO MATCH, NOT OBSERVED, and NOT PROVEN. The page forbids SAFE, SECURE, PROTECTED, and NO ATTACK as conclusions.

## Documentation correction

`learning/level_1/LAB-MCP-001/searches/DET-MCP-001.md` no longer calls the disabled search an operational detection. It states the search is disabled and at maturity LOGIC_VALIDATED. The searches README uses the same wording. `savedsearches.conf` and `DET-MCP-001.spl` were not edited to match the prose.

LAB-MCP-001's own dashboard source and `docs/MCP_SEARCH_CONTRACT.md` still contain the older phrase. Those pages were left in place. They are not this workshop.

## Tests

Focused: `tests/splunk/test_detection_engineering_workshop.py` — 4 passed.

Full offline: `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"` — 1037 passed, 3 deselected, in 9.06s. The offline tests do not execute SPL.

## Live validation

MEASURED. Splunk export of the workshop searches and the shipped candidate, as tabulated above. The only positive DENY-then-start row in this pass was the simulated makeresults control.

Before the UI check, `./scripts/lab-up.sh --refresh-app` restaged `splunk_app/agentsec` into the named volume and restarted Splunk. The view was absent from the running app until that documented restage (OBSERVED 404). After restage the same two broad rows and zero tuned rows were still present, so the restart did not replace the teaching corpus in this measurement.

## UI and accessibility

OBSERVED in headless Chrome against `ws_lab_detection_engineering` after the restage.

- Tabs MISSION, HYPOTHESIS, CORRELATE, COMPARE, COVERAGE, and PATH B · REVIEW were present.
- Initial mission text did not contain the reviewed run id. Path B text contained SIMULATED and that run id.
- Viewports 1920, 1440, 1280, and 1024: no horizontal overflow (`scrollWidth` within `clientWidth`).
- `documentElement.style.zoom = 2` at a 1024 viewport: horizontal overflow, `clientWidth` 1024, `scrollWidth` 1920.
- A 512 CSS-pixel viewport, used as a 200% reflow stand-in for 1024 physical pixels, also overflowed.
- One Tab from the MISSION tab moved focus to PATH B · REVIEW. Computed `outline-style` on the focused tab was `none` (width reported 3px). That is not a focus-visible audit.
- Screen reader: NOT TESTED. WCAG compliance is not claimed.

## Secret hygiene

Changed files were reviewed for credentials, tokens, private keys, certificates, and new cryptography. None were added. `.env` was not committed. Temporary measurement scripts read `SPLUNK_PASSWORD` from `.env` inside the process and were deleted. The password was not printed. No local absolute home path was added to learner docs. `docs/plans/` was not modified.

## Git

Completed work is the documentation correction, the existing workshop text, regenerated Studio view, the learning note, this report, and the focused test assertions. No detector was enabled.
