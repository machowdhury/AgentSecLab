# AgentSec Phase 1 — Investigation Notebook Remediation

| | |
|---|---|
| Date | 2026-10-05 |
| Branch | `develop` |
| Commit | `7ca0dcd` |
| AgentSec version | 1.1.0 |
| Runtime schema | 1.9.0 (unchanged) |
| ExternalEvidence contract | 1.0.0 (unchanged) |
| Splunk app build | 4 (unchanged) |
| Lab | LAB-MCP-001 — MCP Tool Authorization |
| Verdict | **CONDITIONAL — NOTEBOOK REMEDIATION INCOMPLETE** |

---

## 1. What the gap actually was

The runtime was not broken. CTRL-MCP-001 decided correctly, the telemetry was
emitted correctly, and both outcomes were independently reproduced and
corroborated in Splunk before this work started.

The gap was that a learner who finished an ATTACK was handed **native Splunk
Search**. Native Search answers whatever you already know to ask. A learner who
has just met MCP tool authorization does not yet know to ask whether a control
decision and a downstream execution are two separate facts — that is the thing
the lab exists to teach. The surface assumed the knowledge it was supposed to
create.

So this was a pedagogical and interaction-model gap, not an evidence gap, and
the remediation changes no runtime semantics.

## 2. What was built

INVESTIGATE is now the **AgentSec Investigation Notebook**: a header, a run-state
panel, and five cells. Every cell has the same six-part shape.

```
QUESTION
  -> WHY THIS QUESTION MATTERS
    -> VISIBLE SPL
      -> REAL RESULT
        -> YOUR OBSERVATION
          -> WHAT THIS DOES NOT PROVE
            -> NEXT QUESTION
```

| # | Question | Data source | Lesson |
|---|---|---|---|
| 1 | What did the control decide? | `ds_nb_decision` | `ALLOW != EXECUTION` |
| 2 | Did downstream execution occur? | `ds_nb_execution` | `CONTROL DECISION != EXECUTION` |
| 3 | Requested vs granted scope? | `ds_nb_scope` | `KNOWN TOOL != GRANTED TOOL` |
| 4 | What was actually indexed? | `ds_nb_timeline` | the record, not the narrative |
| 5 | What can you legitimately conclude? | — | claim strength discipline |

Three decisions are worth recording because they are where this could have gone
wrong quietly:

**Cell 2 cannot see `agentsec.control.decision`.** Answering an execution
question from a decision field is exactly the collapse the lab exists to
prevent. Enforcing that in the query rather than requesting it in the prose
means the separation survives a future edit by someone who has not read the
prose. A test asserts the field is absent from that search.

**Cell 4 sorts whatever was indexed.** The validated ATTACK and RETEST sequences
are regression context, not answer keys. Hard-coding them as the expected
sequence would turn an observation into a reading-comprehension exercise, so the
cell narrates no event names and the test asserts it does not.

**Cell 5 names the two overclaims it refuses.** `ATTACK != UNIVERSAL COMPROMISE`
and `RETEST != UNIVERSAL SECURITY`. A conclusion cell that does not name the
tempting wrong answer is not teaching against it.

## 3. Surrounding remediation

**MISSION answer leakage (§19, was LOW).** MISSION stated the expected ALLOW,
the expected DENY, the `tool_not_granted` reason and both handler counts, then
asked the learner to predict them. Prediction against a stated answer is
copying. MISSION now states three *determinations* and says the outcomes are
deliberately withheld.

**PATH B (§18).** PATH B is the answer key and now opens by saying so, telling
the learner to predict first. The surface also admits it **cannot lock itself** —
Studio has no gating primitive, so the honest move is to say the gate is social,
not to imply an enforcement that does not exist.

**EVIDENCE vs INVESTIGATE (§17).** EVIDENCE was carrying near-duplicates of the
guided tables, which teaches a learner that the two tabs are interchangeable. It
is now explicitly the raw explorer, says "this tab is not the guided
investigation", and shares **zero** data sources with INVESTIGATE. A test
enforces the empty intersection.

**Comparison reset (§20, was MEDIUM).** After navigation the rich ATTACK vs
RETEST table read "Not run" while session history simultaneously listed two
completed runs. Two surfaces disagreeing about the same facts is worse than one
surface being empty. Session history stores only summary fields, so rather than
widening it into a second copy of the launch payload — a second state system —
the table now rehydrates from `GET /api/launches/<run_id>`, the launcher records
those runs already produced. If a record is gone the row says so rather than
reading as "not run".

**Handoff drift found during the work.** `search_handoff` had its own hand-copied
lab-to-view table, and it had already drifted: `LAB-MEMORY-001` mapped to
`ws_lab_memory_001`, a view that does not exist. That lab's learners would have
been sent to a 404. The duplicate is deleted; the module now reads
`workshop_flows.LAB_TO_VIEW`, which is owned by the code that writes the views,
and two tests assert the duplicate is not reintroduced and that every mapped
view file ships.

## 4. What was deliberately not built

**No Jupyter, no notebook server, no second query engine, no second auth
system.** "Notebook" here is an interaction model, not a kernel. The five cells
are Dashboard Studio markdown panels backed by five real `ds.search` sources. A
test asserts every visualization is markdown/table/image and every data source
is `ds.search`.

**No URL token handoff.** §14 asked whether the run.id could be carried into
Studio. It cannot. The repo already encodes `studio_token_binding: "NOT
SUPPORTED / DO NOT BUILD"`, and Splunk documents Studio token passing only via
in-Splunk `drilldown.linkToDashboard`. Appending `?live_run_id=...` would be
silently ignored and would teach the learner to trust a field that never
filled — worse than no handoff. So the button copies the run.id to the clipboard
and the page states the limitation in plain words. Unsupported DOM scripting was
not used.

**No invented telemetry.** `llm_call_count` and `tool_call_count` are Figma
demonstration values. This scenario emits no `agentsec.llm.*` events at all, and
manufacturing some to fill a panel would be fabricating evidence. Tests assert
neither name appears anywhere in the workshop definition.

**No new input.** The five searches offer both `live_run_id` and `run_id` to the
index and take the newer, so the "exactly one `input.text`, titled LIVE run.id"
invariant is unchanged.

## 5. Architectural invariants — confirmed unchanged

| Invariant | State | How verified |
|---|---|---|
| Runtime schema | 1.9.0 | asserted in test |
| ExternalEvidence contract | 1.0.0 | asserted in test |
| CTRL-MCP-001 semantics | unchanged | `ALLOWED_TOOLS == {lookup_policy}` asserted |
| DET-MCP-001 | disabled | `disabled = 1` asserted in `savedsearches.conf` |
| MCP ATTACK / RETEST behaviour | unchanged | no runtime file touched |
| Execution attribution | unchanged | no runtime file touched |
| AcmeBank listener boundary | unchanged | still `127.0.0.1:5000` |
| Splunk app build | 4 | `appserver/static/` untouched |
| Phase 2 labs/controls | absent | all six ids asserted absent |

`agentsec-ui.js` is served by Flask, not from `appserver/static/`, so the Splunk
static cache guard does not cover it and no build bump was required.

## 6. Tests

**Focused suite:** `tests/splunk/test_investigation_notebook.py` — **57 new
assertions, 57 passed.**

Coverage includes: notebook structure and cell ordering; all five questions
present; each result table immediately follows its question; SPL visible in each
cell; every search uses real `agentsec.*` fields; no invented counters; decision
and execution queries provably disjoint; requested-vs-granted labelled DOCUMENTED
vs OBSERVED; timeline data-driven with no narrated sequence; conclusion uses the
claim vocabulary and refuses whole-system verdicts; no cell states an outcome;
MISSION leakage absent; PATH B gated; primary navigation is the notebook and not
Search; Search still reachable; shipped XML matches the generated definition;
contract versions, control identity, detection state and Phase 2 absence.

**Full offline suite:**

```
uv run --extra test python -m pytest tests -q --tb=line \
  -m "not live_ollama and not live_splunk"

1244 passed, 3 deselected in 11.30s        exit code 0
```

Two pre-existing tests were updated as **specification changes**, not
weakenings, and both are stated here for review:

1. `test_phase15b_rag_learning_loop.py` asserted `instructions[3]` contained
   `document.id`. The handoff gained instructions ahead of that line. The index
   was incidental to the intent, so the assertion now checks that *some*
   instruction carries `document.id`. Same guarantee, no positional coupling.
2. Tests pinning `viz_workbench_investigate` and `viz_nb_q*` were updated to the
   new ids. These pinned the old structure that this work replaced.

One assertion **failed and was fixed in the code, not the test**: cell 5
initially had no explicit evidence boundary. The boundary was added to the cell.

## 7. Deployment

| Check | Result | Class |
|---|---|---|
| Pushed to `origin/develop` | `7ca0dcd` | OBSERVED |
| `origin/main` untouched | `0178c70` | OBSERVED |
| Deployed SHA on EC2 | `7ca0dcd` matches | OBSERVED |
| Splunk view deployed | 12 `viz_nb*`, 5 `ds_nb_*` present in container | OBSERVED |
| Deployed view byte-identical to repo | sha256 `6716c79324ac846e…` both sides | MEASURED |
| Splunk app build / cache identity | 4, unchanged | OBSERVED |
| Attack Service template | **see §8** | — |
| Real ATTACK run | **NOT MEASURED** | — |
| Real RETEST run | **NOT MEASURED** | — |
| Indexed evidence for those runs | **NOT MEASURED** | — |
| Browser verification | **NOT TESTED** | — |

## 8. Why the verdict is CONDITIONAL

Three things are outstanding and none of them should be reported as done.

**8.1 The Attack Service was serving a stale template.** The first deployment
used `--refresh-app` without `--build`. The Splunk side refreshed correctly, but
the Flask image did not, so the deployed workbench still contained
`open-search-primary` and no advanced-search disclosure. An image rebuild was
started; **its result is not yet confirmed in this report.** Until a rebuilt
container is observed serving `open-notebook-primary`, the §15 handoff is
NOT VERIFIED in the deployed environment.

**8.2 No real ATTACK or RETEST run was captured for this commit.** The
verification attempts failed on operational errors (wrong container name, wrong
route path, root-owned temp files) and then on the stale image. Previous runs
corroborate the runtime, but those are REPLAYED relative to this commit, not
MEASURED on it. The notebook SPL has therefore **not been executed against live
indexed data** — it is validated by syntax and field-name review only.

**8.3 Nothing was verified in a browser.** No claim of browser PASS is made.
Specifically unverified: that Studio renders all twelve panels; that the five
searches return rows; that the canvas height shows no dead space; that the
clipboard copy fires on the notebook link; that the comparison rehydrate works
after a real reload; and the **real physical keyboard run-id entry** check
required by §14.

## 9. Re-validation checklist

1. Confirm the rebuilt Attack Service serves `open-notebook-primary` and the
   advanced-search disclosure, and no longer serves `open-search-primary`.
2. Run a real ATTACK and a real RETEST on this commit; record both run.ids.
3. Confirm both run.ids are searchable in `agentsec_telemetry`.
4. Open INVESTIGATE; type one run.id into **LIVE run.id using a real physical
   keyboard**, not a dispatched browser event.
5. Confirm all five result panels return rows for that run.
6. Confirm cell 2 reports execution independently of cell 1's decision.
7. Confirm MISSION reveals no outcome before prediction.
8. Confirm PATH B shows the answer-key warning first.
9. Reload the workbench and confirm the comparison rehydrates and does not
   contradict session history.
10. Confirm the notebook link copies the run.id.

## 10. Phase boundary

No Phase 2 work was started. `LAB-GOV-004`, `CTRL-RUNTIME-004`, `LAB-DATA-003`,
`CTRL-DATA-003`, `LAB-A2A-005` and `CTRL-A2A-005` are absent and asserted absent.
`main` was not merged, nothing was tagged, no release was published.

---

**VERDICT: CONDITIONAL — NOTEBOOK REMEDIATION INCOMPLETE**

The notebook is built, tested and deployed to Splunk. It is not proven in the
deployed Attack Service, not exercised against a live run on this commit, and
not browser-verified.
