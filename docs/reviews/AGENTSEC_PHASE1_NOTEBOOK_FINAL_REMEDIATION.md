# AgentSec Phase 1 — Notebook Final Remediation

Bounded remediation of the CONDITIONAL verdict in
`AGENTSEC_PHASE1_NOTEBOOK_BROWSER_REVALIDATION.md`. No Phase 2, no redesign, no
new curriculum, no schema or control change, no tag or release.

Evidence labels: MEASURED / OBSERVED / DOCUMENTED / REPLAYED / SIMULATED / PARTIAL / NOT TESTED.
Claim strength: PROVEN / SUPPORTED / OBSERVED / INFERRED / NOT OBSERVED / NOT MODELED / NOT PROVEN / REFUTED.

---

## 1. Starting SHA

The brief names `afa553b`. The actual `develop` HEAD when this task began was
**`4b110d8`** ("Back the REPLAY specimens and print the query that actually
ran"), a commit by the repository owner made on top of `afa553b` before this
task. It already contained the REPLAY seeding mechanism, per-cell printed SPL,
the EVIDENCE caption rewrite and the INVESTIGATE landing tab.

I **audited it rather than redoing it**. Its own commit message states
"1291 passed, 3 deselected (was 1244)" (DOCUMENTED by that commit; I did not
re-measure the suite at that exact SHA). The brief's 1244 is the count at
`afa553b`, so the difference is attributable to that commit, not to drift.

## 2. Ending SHA

**`b68d0dd`** on `develop` (pushed; deployed to EC2 and confirmed as the host
HEAD). This report is untracked and uncommitted, so the ending SHA is the
deployed code.

Commits made in this task: `a2cd3dd`, `1ee36da`, `6d790db`, `b68d0dd`.

`1ee36da` is an **experiment commit** whose hypothesis was REFUTED (section 4).
It stays in history and is not reverted, because the seeder behaviour tests in
the same commit are real and kept.

## 3. Files changed (`4b110d8..b68d0dd`, 8 files, +559 / −110)

| File | Why |
|---|---|
| `scripts/build_lab_mcp_001_dashboard.py` | Cell 5 query printed via `with_spl`; `LIVE_RUN_NONE` sentinel; pair query transposed; panel stacking helper; two measured heights |
| `learning/level_1/LAB-MCP-001/dashboard.definition.json` | regenerated |
| `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_001.xml` | regenerated; test requires it to equal the definition |
| `src/agentsec/templates/attack_mcp.html` | paste instructions: select the `none` first |
| `tests/splunk/test_investigation_notebook.py` | +210 lines: drift, fallback, measured-height, transposition tests |
| `tests/splunk/test_replay_seeder_behavior.py` | **new**: behavioural tests of the seeder (21 cases from 9 test functions) |
| `tests/splunk/test_guided_learning.py` | explicit per-lab exception for the `none` default (justified below) |
| `tests/splunk/test_agentsec_ui_shell.py` | same exception |

Not touched: `scripts/splunk_hec_init.sh`, `scripts/apply_guided_learning.py`,
`src/agentsec/replay_specimens.py`, runtime schema 1.9.0, ExternalEvidence
1.0.0, CTRL-MCP-001. The three-stage dashboard pipeline regenerated only the
intended files; the other 30 views are byte-stable (OBSERVED in `git status`).

---

## 4. Exact cause of the missing REPLAY specimen

**Two separate causes. The first is the one the brief asked about; the second
was found while verifying the fix and the offline tests had not caught it.**

**Cause A — ownership gap (DOCUMENTED in `4b110d8`, audited here).** The
canonical specimen `163d11e2-e751-4282-9406-19b490542ed4` was real, but its
event bodies existed only under the gitignored `artifacts/` tree. No deployment
mechanism carried them to the EC2 Splunk, so the notebook's default specimen
selection pointed at an id nothing had ever indexed. Classification: a
**bounded defect in the owning mechanism**, not a stale id and not ordinary
deployment drift.

**Cause B — empty token blanked the pre-run notebook (MEASURED).** With the
specimen seeded, the INVESTIGATE tab *still* rendered blank before a learner
pasted a run.id: **55 panels showed "Set token value to render visualization"**.
Dashboard Studio treats an empty-string token as unset, and a search that
references an unset token never runs, so the specimen fallback in the SPL
(`OR "agentsec.run.id"="$run_id$"`) was unreachable. No offline test could see
this because it only exists in the rendered page.

I tested whether `defaults.tokens` with an empty value could fix it. It did
not: 60 unrendered panels (REFUTED, commit `1ee36da`). The fix that worked was
a non-empty sentinel (section 5).

## 5. Exact remediation

- **A. Specimen ownership.** Packs live at
  `learning/level_1/LAB-MCP-001/specimens/<run-id>.jsonl`, validated by
  `src/agentsec/replay_specimens.py`, mounted read-only into the HEC-init
  container, and seeded verbatim (original 2026-09-12 timestamps) by
  `scripts/splunk_hec_init.sh`. It is idempotent, refuses a partial specimen,
  and proves searchability **by running a search, not from the HEC 200**.
  `lab-up.sh --refresh-app` re-runs it after the Splunk restart. I added 21
  behavioural cases that execute the real script against stubbed `curl` and
  `mgmt_request`, mutation-verified (temporarily broke the script, saw the
  tests fail, restored it with `git checkout`).
- **B. Sentinel.** New input `LIVE run.id` defaults to `none`, and the base
  search becomes
  `"agentsec.run.id"="$live_run_id$" OR "agentsec.run.id"="$run_id$"`
  followed by `eval selected_run=if("$live_run_id$"=="none","$run_id$","$live_run_id$")`.
  While the box reads `none`, every cell investigates the REPLAY specimen;
  once a run.id is entered, that run is used. After the fix: **0** "Set token
  value" messages (MEASURED).

## 6. Replay indexing proof

All three canonical specimens, from the deploy of `b68d0dd`
(`docker logs agentsec_splunk_hec_init`, MEASURED):

```
SPECIMEN 163d11e2-e751-4282-9406-19b490542ed4: already indexed (7/7). No action.
SPECIMEN 5e8f55f3-eb46-47ee-b979-b72d9c9b1f49: already indexed (7/7). No action.
SPECIMEN 7a1d37b5-d589-4dfd-8322-25ebd0152dbc: already indexed (6/6). No action.
PASS — all 3 canonical REPLAY specimens are searchable.
```

"Already indexed" is determined by the seeder searching Splunk, so this is
indexed evidence, not HEC acceptance. Re-seeding across redeploys wrote nothing
twice (idempotent, OBSERVED over several deploys). Before any run.id is
entered, the INVESTIGATE tab renders the baseline specimen's rows in the real
browser (OBSERVED). Evidence class: **REPLAYED** — genuine historical runs,
never presented as new measurements.

**NOT OBSERVED:** the absent→seeded transition on a *fresh* Splunk volume. Every
environment I touched already held the specimens. That transition is covered
only by the stubbed behavioural tests, which are SIMULATED.

## 7. SPL single-source-of-truth design

One string per cell (`nb_*_spl`, and `live_pair_spl` for Cell 5) is passed to
both `search_ds(...)`, which builds the executed data source, and
`with_spl(body, spl)`, which substitutes it into the `<<SPL>>` slot of the
markdown that prints it. There is no second copy to drift. Cell 5 was the
exception in `4b110d8` (its query ran but was not printed); fixed in `a2cd3dd`.

## 8. Proof visible SPL == executed SPL

- **Static, every cell (PROVEN for the definition):**
  `test_every_search_on_investigate_is_printed_verbatim`,
  `test_every_notebook_search_is_printed_somewhere_in_the_notebook`,
  `test_comparison_query_is_printed_beside_the_table_it_produces`,
  `test_comparison_query_is_not_bound_to_a_run_id_token`.
- **Live (MEASURED), final build:** for ATTACK `adcc1a01-…` and RETEST
  `b5c10c74-…`, I typed the run.id with real keystrokes, scraped the printed SPL
  from the rendered notebook, and ran each of the six blocks **verbatim** in
  native Splunk Search: **12 of 12 executed and matched** the notebook (timelines
  7 and 6 events; decision, scope, state and pair cells as below). Scraped text
  and the results are in `/tmp/agentsec-reval/f_verbatim_results2.json`
  (scratch, not committed).
- Splunk resolves `$live_run_id$` / `$run_id$` in the printed markdown to the real
  ids, so the printed query is directly pasteable; no literal `$token$` was
  left in any printed block (OBSERVED).

## 9. Cell 2 decision-independence proof

Cell 2 asks what *executed*; it must not read the control decision.
`test_execution_question_never_reads_the_control_decision` checks the executed
query, and `test_execution_question_decision_independence_holds_for_the_printed_query`
checks the printed one. The printed Cell 2 query contains no
`agentsec.control.decision` (OBSERVED in the scraped text). Live, Cell 2
returned ATTACK `mcp.started` + `mcp.completed` (`executed=true`) and RETEST
only `pipeline.stopped` (MEASURED). **Claim: PROVEN** that Cell 2 is built
without the decision field.

## 10. Workbench handoff decision

**Decision: make behaviour match the promise.** The Workbench promised
INVESTIGATE and landed on the dashboard's default tab. Both Workbench links
now carry `?tab=layout_investigate`, resolved through
`LAB_TO_LANDING_TAB = {"LAB-MCP-001": "layout_investigate"}` in
`workshop_flows.py` and applied by `search_handoff.workshop_url`. Tests:
`test_handoff_lands_on_the_tab_the_workbench_promises`,
`test_a_named_landing_tab_exists_in_the_view_it_names`,
`test_handoff_resolves_views_from_the_module_that_writes_them`.

**Real-click proof (OBSERVED):** clicking `#open-notebook-primary` opened the
notebook on INVESTIGATE for both ATTACK and RETEST.

**Deliberately not done:** auto-binding the run.id into the page. Dashboard
Studio exposes no supported way to set a token from a URL, and
`test_run_id_handoff_does_not_fake_an_unsupported_token_binding` pins that. The
learner still pastes the id. The wording was fixed to say so.

**Residual hazard (OBSERVED, not fixed):** because the box is prefilled with
`none`, a naive click-then-paste produces `none<run-id>` and the notebook shows
no evidence. Mitigation is text only (the header and the Workbench copy tell the
learner to select the `none` first). See debt.

## 11. EVIDENCE leakage remediation

The ungated EVIDENCE tab stated outcomes ("Expect decision DENY, reason
tool_not_granted"). Captions were rewritten as investigative guidance in the
curriculum voice (what to look at and which question it answers), with no
outcome stated. Tests: `test_evidence_tab_guides_investigation_without_giving_the_answer`
(parametrized over the answer patterns) and
`test_answer_key_tab_may_still_state_outcomes` (PATH B is *meant* to). Live, EVIDENCE
rendered real specimen rows with no answer-leaking text (OBSERVED).

## 12. Cell 5 layout remediation

**What I got wrong first.** After `a2cd3dd`, my DOM check said both rows were
present and I almost accepted it. The earlier defect was precisely a row that
was in the DOM and invisible, so I looked at screenshots instead, and then
measured. At **1024px** the pair table was still clipped:

| Width | Finding before this fix (MEASURED, inner `scrollHeight − clientHeight`) |
|---|---|
| 1920 | none |
| 1440 | printed query block scrolls sideways (dx 190) |
| 1280 | event timeline +43px; printed-query panel +14px |
| 1024 | timeline +163px; printed-query panel +98px; **pair table +35px vertical, +127px horizontal (`last_seen` off-screen, RETEST row reachable only by scrolling inside the panel)** |

The earlier "≥ 560px" test was a guess. It was wrong for 1024.

**Fix (supported Studio/SPL mechanisms only; no JS, CSS or DOM injection):**
1. **Pair table transposed** with
   `| transpose 0 header_field=mode column_name=field`: one column per run, one row
   per field. Result columns are `field | ATTACK | RETEST`. No field dropped, no
   value truncated, and layout no longer depends on window width. Prose and
   description now say "column", not "row".
2. `viz_live_pair_intro` 760 → 920; `viz_nb4_r` 380 → 600 (both measured
   minimums plus margin).
3. INVESTIGATE panels are now **stacked from their heights** instead of
   hand-typed offsets. I diffed the generated definition against `HEAD`: every
   unchanged panel kept its exact offset; only the resized panels and those below
   moved (canvas 7404 → 7784).

**Re-measured after the fix (MEASURED):** no vertical overflow at any width
(1920 / 1440 / 1280 / 1024). **Screenshots read (OBSERVED):** at 1920 and 1024
both the ATTACK and the RETEST column are fully visible, with the full `reason`
sentence readable and spare room under the table.

New tests: `test_panels_are_not_shorter_than_their_measured_content`,
`test_comparison_table_is_transposed_so_width_cannot_clip_it`,
`test_comparison_panel_keeps_every_evidence_column`,
`test_comparison_prose_matches_the_transposed_orientation`,
`test_investigate_panels_are_stacked_with_a_constant_gap`.

**Still open at this layer:** the printed query's `<pre>` scrolls horizontally
at ≤ 1440px because the `stats` line is ~700 characters (dx 190 at 1440, 606 at
1024). The text is complete and copyable, but not visible without scrolling.
And the table's one-line subtitle is ellipsised at 1024px (its last clause,
"not a completeness answer", is cut off; it is complete in the definition and
visible at 1920). Both are debt, not evidence clipping.

## 13. New ATTACK run.id

`adcc1a01-f14c-4da8-8f57-a363bc38e1ac` — profile `vulnerable`, **MEASURED**,
fired through the Attack Service workbench UI behind a recorded prediction.
Not the reviewer's `eed80a6c-…`.

## 14. New RETEST run.id

`b5c10c74-dc08-4665-bd16-c740f214a512` — profile `defended`, **MEASURED**.
Not the reviewer's `cec35c22-…`.

## 15. Splunk evidence counts

In-container Splunk search, final probe (MEASURED). The first attempt of this
probe had broken quoting and returned **false zeros** (ATTACK `mcp.started` = 0
although it exists), which I caught because the positive control failed. The
numbers below are from the repaired probe, whose positive controls fired:

| Probe | ATTACK `adcc1a01-…` | RETEST `b5c10c74-…` |
|---|---|---|
| total events | **7** | **6** |
| `agentsec.control.decision` | ALLOW | DENY |
| `agentsec.mcp.started` / `.completed` | 1 / 1 *(positive control)* | 0 / 0 |
| `agentsec.pipeline.stopped` | 0 | 1 *(positive control)* |
| `agentsec.llm*` and `gen_ai.*` events | **0** | **0** |

Notes: `CTRL-MCP-001` remained the decision point throughout; Splunk only
read the evidence afterwards. `stats count by event.name` reports 3 per name,
which is a multivalued-extraction artifact (the reason notebook queries use
`mvdedup`); I read the totals, not those per-name counts. Raw output:
`/tmp/agentsec-reval/f_counts_final.txt`.

**Interpretation, bounded.** ALLOW on ATTACK is not proof of anything beyond
this run: `execution_state` (mcp.completed) is the execution fact, read
separately from `decision`. DENY on RETEST is not "secure"; it is one request,
one tool, one profile. **ATTACK ≠ universal compromise; RETEST ≠ universal
security.** Absence of `mcp.started` on RETEST supports "this copy shows no
execution event", not "nothing executed".

## 16. Full test-suite result

`uv run --extra test python -m pytest tests -q -m "not live_ollama and not live_splunk"`
→ **1327 passed, 3 deselected, exit 0** (MEASURED, this session). Brief baseline
1244 at `afa553b`; 1291 as stated in the `4b110d8` commit message (DOCUMENTED);
1327 now.

**Test changes that are not additive, and why:**
- `test_guided_learning.py`, `test_agentsec_ui_shell.py`: both pinned *every*
  LIVE lab's token default to the empty string. That assumption is exactly what
  caused Cause B. Replaced by an explicit, commented exception
  (`{"ws_lab_mcp_001": "none"}`), not by deleting or loosening the check for other
  labs.
- `test_investigation_notebook.py`: the guessed `h >= 560` test was replaced by
  measurement-based minimums and the stacking/transposition tests. This is a
  genuine spec change (the table is now transposed), not a weakened assertion.

## 17. Browser-tested items

Real Google Chrome 153 driven by Playwright over CDP (trusted input; JS used
only to *observe*), persistent profile, against the deployed `b68d0dd` (OBSERVED
unless stated):
- Attack Service lab page → record prediction → fire ATTACK → real `run.id` →
  real click on the handoff → INVESTIGATE; repeated for RETEST (`f2_golden.js`).
- Five notebook cells render; run.id entered by keyboard; Cell 2 independent.
- Pre-run INVESTIGATE renders the REPLAY specimen; 0 "Set token value".
- Comparison rehydration and Cell 5 at **1920** and **1024** (screenshots read).
- Overflow measured across **1920 / 1440 / 1280 / 1024** (MEASURED).
- All six printed SPL blocks × two runs executed verbatim in native Search.
- EVIDENCE tab renders specimen rows with no answer leakage.

## 18. NOT TESTED

- **200% browser zoom — NOT TESTED.** Not simulated by CSS transforms, DOM
  injection or viewport resizing, and not marked PASS. Manual browser
  qualification remains.
- **Upstream golden-path hops** (AcmeBank → Behind AI → MCP workshop → Predict)
  were **not re-walked in this pass**; I started at the Attack Service lab page.
  They were exercised in the earlier re-validation.
- **Fresh-volume seeding transition** (section 6): NOT OBSERVED.
- **Widths below 1024px**: not measured.
- **Browsers other than Chrome 153**: not tested.
- **DET-MCP-001** stays disabled and was not exercised.
- Live LLM generation was not exercised (the notebook runs are deterministic,
  zero LLM events).

## 19. Remaining debt

1. **Paste hazard (MEDIUM, OBSERVED).** Naive click+paste yields `none<run-id>`
   and a "no evidence" result. Text-only mitigation. Better fix needs either a
   supported way to clear a token on focus or changing the no-data message to
   say "if the box still starts with `none`, select all and paste again".
2. **Printed SPL scrolls sideways at ≤ 1440px** (LOW). Long `stats` line; could be
   reformatted onto several lines in the single source, identical execution.
3. **Cell 5 subtitle ellipsised at 1024px** (LOW); the `matched_events` caveat is
   cut. Could be restated in the intro prose.
4. **Shared MISSION guide panels** now show their no-data message instead of
   "Set token value" while the box reads `none` (side effect of the sentinel;
   the shared injector was deliberately left untouched).
5. **Comparison rehydration needs a complete pair** (MEDIUM-5 from the prior
   review), unchanged.
6. LOW items in the prior re-validation report, unchanged.
7. The refuted experiment `1ee36da` remains in history.

## 20. git status

```
?? .tmp-path-pre/
?? docs/reviews/AGENTSEC_PHASE1_NOTEBOOK_BROWSER_REVALIDATION.md
?? docs/reviews/AGENTSEC_PHASE1_NOTEBOOK_FINAL_REMEDIATION.md
```

Working tree has no modified tracked files. `develop` = `b68d0dd`, equal to the
remote `develop`. The untracked entries are pre-existing scratch/report files
and this report.

## 21. origin/main status

**Untouched:** `0178c70e20cfe0152648e2aafb8e607280625c40`, confirmed by
`git ls-remote`. No tag, no release, no merge.

---

## Security semantics preserved

ALLOW ≠ execution · DENY ≠ secure · finding ≠ incident · query ≠ validated
detector · empty result ≠ safe · ATTACK ≠ universal compromise · RETEST ≠
universal security · HEC acceptance ≠ evidence completeness · scanner finding ≠
authorization decision. CTRL-MCP-001 remains the PDP; Splunk is downstream
evidence. Runtime schema 1.9.0, ExternalEvidence 1.0.0 and CTRL-MCP-001
semantics are unchanged (pinned by `test_runtime_contract_versions_are_unchanged`
and `test_control_identity_is_unchanged`).

## What I should now be able to explain

1. Why does a search that references an empty Dashboard Studio token never run,
   and why did that make a fallback written *inside the SPL* unreachable?
2. Why does `HEC returned 200` not prove a specimen is readable, and what does
   the seeder do instead?
3. What does "visible SPL == executed SPL" require structurally, and why is one
   string feeding both the renderer and the data source stronger than two tests
   comparing two copies?
4. Why can ALLOW coexist with `mcp.started`/`mcp.completed` evidence, and what
   would "ALLOW but no execution event" mean (and not mean)?
5. Why was a DOM-presence check not enough to prove a table row was visible, and
   what did measuring `scrollHeight − clientHeight` add?
6. What is a positive control, and how did one expose that my first Splunk probe
   returned false zeros?
7. Why is transposing the comparison table a better fix than raising its height
   or dropping columns, and what does it preserve?
8. Which three Cell 5 claims may a learner legitimately make from one ATTACK/RETEST
   pair, and which do they not get to make?
9. Why is a refuted experiment commit kept in history rather than reverted?
10. Why is 200% zoom marked NOT TESTED rather than inferred from the 1024px result?

---

## Final verdict

**READY FOR INDEPENDENT FINAL RE-VALIDATION**
