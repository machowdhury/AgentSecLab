# AgentSec Phase 1 Investigation Notebook Browser Re-Validation

## Review Identity

| | |
|---|---|
| Review date | 2026-10-05 22:30 → 2026-10-06 00:05 (UTC-4) / runs timestamped 2026-10-06 03:12–03:26 UTC |
| Reviewer role | Independent browser re-validation. No code changed, nothing committed, nothing merged, no Phase 2 work. |
| Browser | Google Chrome (real `chrome` channel, not Chromium, not headless-shell) |
| Browser version | 153.0.8010.55 |
| Driver | Playwright 1.63.0 over the Chrome DevTools Protocol, headless |
| Input method | CDP `Input.*` events — browser-level trusted input. **No** JS-dispatched events, **no** DOM mutation, **no** `localStorage` edits, **no** programmatic token setting. See *Claim Boundaries*. |
| Viewports | 1920×1080 primary; 1440, 1280, 1024 for the responsive pass |
| Browser zoom tested | 200% attempted twice via Chrome's own persisted zoom preference; **could not be made to apply** → NOT TESTED |
| Candidate provided | `afa553b` on `develop` |
| Candidate observed | Git SHA is not surfaced anywhere in the deployed UI, so it is **NOT OBSERVED**. Packaged identity observed instead (below). |
| App build observed | **4** (Home → BUILD, sourced from `[install] build` in `app.conf`) |
| Product version observed | **1.1.0** (BUILD panel and the AcmeBank header) |
| Schema observed | **1.9.0** (BUILD panel, and PATH B text "Schema 1.9.0") |
| ExternalEvidence observed | **1.0.0** (BUILD panel) |
| Static asset digest observed | `589e739d0798fb44…` |

## Candidate Observed

Everything in §1 of the brief that the product actually reports was confirmed in
the browser: version 1.1.0, app build 4, schema 1.9.0, ExternalEvidence 1.0.0.

The git SHA is **not** observable from the browser. I did not mark it VERIFIED.
`origin/main` was not inspected — that is a repository fact, not a browser fact,
and this review did not touch the repository state.

## Fresh Run IDs

| Role | run.id | Mode | Profile | Indexed events |
|---|---|---|---|---|
| **ATTACK_RUN_ID** | `eed80a6c-4cf8-405b-833b-75cd8c2f9381` | ATTACK | vulnerable | 7 |
| **RETEST_RUN_ID** | `cec35c22-3f78-498c-8d7d-60998cfba292` | RETEST | defended | 6 |

Distinct: **yes**. Neither reuses a prior validation run.

A second pair was minted solely for the persistence test in §28, because session
history is per-browser-session and the two states had to exist in one continuous
session: ATTACK `29d8cfb5-01f2-4288-bc6c-b73cb7b841ba`, RETEST
`c3efad7c-a0e2-4719-81a9-f738e7058f89`. These are labelled wherever used.

Workshop URL: `http://3.17.29.24:8000/en-US/app/agentsec/ws_lab_mcp_001`
Notebook tab: `?tab=layout_investigate` (INVESTIGATE)
Splunk Search URL: `http://3.17.29.24:8000/en-US/app/search/search`

## Executive Result

**The notebook is real and it works.** Five visibly distinct guided cells render,
each with a question, a rationale, readable SPL, a live result, an observation
prompt and an evidence boundary. Typed run.ids drive every cell. Results change
correctly between ATTACK and RETEST. Every material claim the notebook makes was
independently reproduced in native Splunk Search. Nothing fabricated: both runs
return **zero** `agentsec.llm.*` events and no invented counters appear anywhere.

The remediation genuinely fixed the thing it set out to fix. A learner finishing
an ATTACK is no longer dumped into a blank search bar.

Five defects stand between this and a freeze. None corrupts evidence; three
affect what a learner is told or shown.

The most consequential: **the canonical REPLAY specimen that the notebook falls
back to has zero indexed events.** A learner who opens INVESTIGATE before running
anything — the documented entry path — sees five empty tables. The EVIDENCE tab,
which is built entirely on those specimens, is completely empty.

The most awkward: **the SPL displayed to the learner is not the SPL that ran.**
Cell 1 says "This is the SPL the table below runs." It is abbreviated. Copied
verbatim into Search it produces a table with four of six columns blank. In a
product whose entire thesis is that you check the claim against the evidence,
showing a query that does not reproduce the result is the wrong kind of wrong.

## 28-Item Re-Validation Checklist

| # | Item | Result | Evidence |
|---|---|---|---|
| 1 | Fresh ATTACK generated | **PASS** | `eed80a6c…` minted by real click on `#fire-attack` after a recorded prediction |
| 2 | Primary investigation handoff | **PARTIAL** | Reaches the workshop, not native Search — but lands on `tab=layout_mission`, not INVESTIGATE |
| 3 | INVESTIGATE visibly active | **PASS** | Real tab click; `aria-selected` flipped MISSION→false, INVESTIGATE→true; screenshot confirms underline and content |
| 4 | Five notebook cells visibly render | **PASS** | "1 of 5" … "5 of 5" all present and visible after scrolling; screenshots at top, middle, bottom |
| 5 | Cell 1 control-decision semantics | **PASS** | ALLOW + fail-open reason for the active run; states "ALLOW != EXECUTION" |
| 6 | Cell 2 execution independence | **PASS** | Visible SPL contains no `agentsec.control.decision`; explicitly says so |
| 7 | Cell 3 requested-vs-granted semantics | **PASS** | `customer:read` vs `policy:read`, labelled OBSERVED vs DOCUMENTED |
| 8 | Cell 4 data-driven timeline | **PASS** | 7 rows ATTACK / 6 rows RETEST, read from the index, no narrated sequence |
| 9 | Cell 5 claim boundary | **PASS** | PROVEN/SUPPORTED/OBSERVED/NOT PROVEN + "ATTACK != UNIVERSAL COMPROMISE · RETEST != UNIVERSAL SECURITY" |
| 10 | Fresh RETEST generated | **PASS** | `cec35c22…` |
| 11 | ATTACK/RETEST distinct run IDs | **PASS** | `eed80a6c…` ≠ `cec35c22…` |
| 12 | Notebook switches to RETEST evidence | **PASS** | State panel → RETEST/defended/6; Cell 2 → `pipeline.stopped` only |
| 13 | Physical-keyboard run-id entry | **PASS** | Typed character-by-character; field value and `form.live_run_id` in the URL both updated; panels repopulated |
| 14 | Clipboard/copy behavior | **PASS** | Control activation observed **and copied content verified** by real Cmd+V paste into LIVE run.id |
| 15 | 6604px canvas/layout | **PARTIAL** | All cells reachable, correct order, no overlap — but large dead space in most panels and a clipped comparison table |
| 16 | True 200% browser zoom | **NOT TESTED** | Two genuine attempts; Chrome's persisted zoom preference did not take effect under automation |
| 17 | Keyboard navigation/focus | **PARTIAL** | No trap, logical order, skip-nav link present — but 32 stops to reach the controls and no focus ring on LIVE run.id |
| 18 | Advanced Splunk Search remains secondary | **PASS** | Behind a disclosure on the workbench, at the foot of the notebook; correct public host |
| 19 | Mission answer leakage | **PASS** | States determinations, withholds outcomes explicitly |
| 20 | PATH B · ANSWERS behavior | **PASS** | Opens with "Stop — this tab contains the answers" and admits it cannot self-lock |
| 21 | EVIDENCE tab behavior | **PARTIAL** | Purpose is distinct and stated — but every panel is empty and the captions leak expected answers |
| 22 | Comparison persistence after navigation | **PASS** | Rehydrates from `/api/launches/…`; full pair restored |
| 23 | Comparison persistence after reload | **PASS** | Same after a real reload; matches session history exactly |
| 24 | Your Path regression | **PASS** | Renders, 32 cards, marking persists through reload and navigation |
| 25 | Build Information regression | **PASS** | 1.1.0 / build 4 / 1.9.0 / 1.0.0 |
| 26 | Independent ATTACK Splunk corroboration | **PASS** | Native Search reproduces every field |
| 27 | Independent RETEST Splunk corroboration | **PASS** | Native Search reproduces every field |
| 28 | Notebook vs independent Search consistency | **PASS** | 8 of 8 comparisons match |

## Learner Journey

Started at `http://3.17.29.24:5001/acmebank` with no prior state.

The read-only AcmeBank page renders correctly: WORLD 1 framing, profile
`defended`, model `llama3.2:1b`, version 1.1.0, a DOCUMENTED evidence label, and
Priya Chen's loan request shown as sample text with no form. Nothing submits.
The page correctly explains that AcmeBank listens only on the lab host's
loopback and that run.ids are minted by the launcher.

Forward navigation exists only inside a collapsed `See how the AI did this`
disclosure. Expanding it with a real click reveals the architecture explanation
and one link, *Investigate tool authorization in the AgentSec workshop* →
`/labs/LAB-MCP-001`. That click landed on the Tool Authorization Workbench.
The journey works, though the only way forward is hidden one disclosure deep.

The workbench gates launching behind a prediction: `#fire-attack` and
`#fire-retest` are both `disabled` until a control guess and an execution guess
are recorded. I predicted **control ALLOW / execution YES** before launching,
reasoning that the tool is outside the grant but the profile is vulnerable. The
buttons unlocked on recording, and the prediction card read back
`CONTROL ALLOW · EXECUTION YES`. This is good pedagogy and it is enforced, not
merely suggested.

## Investigation Handoff

| | |
|---|---|
| Source page | `http://3.17.29.24:5001/labs/LAB-MCP-001` |
| Control clicked | `#open-notebook-primary`, labelled **Investigate evidence**, in the NEXT INVESTIGATION section |
| Destination URL | `http://3.17.29.24:8000/en-US/app/agentsec/ws_lab_mcp_001?form.run_id=163d11e2-…&tab=layout_mission` |
| Destination tab | **MISSION** |
| Visible destination heading | "Where you are" / "What you are learning" / "What you do now" |

The important half passes: the primary action leads into the AgentSec workshop,
**not** into `/app/search/search`. Native Search is demoted to a disclosure
labelled *Advanced — open native Splunk Search instead*. Both `#open-notebook`
and `#open-notebook-primary` carry the absolute public host, and
`#open-search-primary` no longer exists in the DOM.

The other half does not. The workbench tells the learner the button "opens the
guided Investigation Notebook on the workshop's INVESTIGATE tab". It opens on
MISSION. The learner must notice the tab strip and click INVESTIGATE themselves.
MISSION does eventually point there, but only in a paragraph below the fold.

Pre-run the link is already absolute and correct (`http://3.17.29.24:8000/…`,
HTTP 303 to the login flow) — no `localhost`, no `127.0.0.1`, no relative path
resolving against port 5001.

## Notebook Visual Structure

Explicitly clicked the INVESTIGATE tab. `aria-selected` moved from
MISSION=`true` to INVESTIGATE=`true`, and the screenshot confirms the active
underline and the notebook content as the visible panel. This was not inferred
from text extraction.

All five cells render as visibly distinct sections with their own headings, and
each carries the full six-part shape:

| Cell | QUESTION | WHY | SPL | RESULT | OBSERVATION | BOUNDARY |
|---|---|---|---|---|---|---|
| 1 of 5 — What did the control decide? | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 2 of 5 — Did downstream execution occur? | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 3 of 5 — What was requested, and was it granted? | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 4 of 5 — What was actually indexed for this run? | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5 of 5 — What can you legitimately conclude? | ✓ | ✓ | n/a (synthesis) | comparison table | ✓ | ✓ |

Nothing is missing from the required structure. Each result table sits directly
under its own question rather than being stacked at the bottom, so the learner
meets one result at a time.

A header panel above Cell 1 states the business context and
`KNOWN TOOL != GRANTED TOOL`, and a state panel reports mode, profile,
`indexed_events` and evidence state read from the index. The header is honest
about a real limitation: observations are not saved, because Studio has no
supported learner-note store and inventing one would create a second state
system.

## Cell 1 — Control Decision

SPL is readable in the panel. Result for `eed80a6c…`:

| run_id | control_id | tool | decision | reason |
|---|---|---|---|---|
| eed80a6c… | CTRL-MCP-001 | lookup_customer_tier | **ALLOW** | `vulnerable_profile_fail_open:CTRL-MCP-001 known tool lookup_customer_tier is not in mcp_policy_agent allowed_tools; lab profile intentionally returns ALLOW (fail-open) so the handler executes` |

Bound to the active run, not a specimen. The cell teaches the separation
explicitly: *"The decision alone does not prove the requested tool executed …
ALLOW != EXECUTION. Question 2 is a separate query because it is a separate
fact."*

Independently confirmed in native Search — identical control id, decision,
reason, and `agentsec.operation.executed=false` on the decision event itself.

## Cell 2 — Execution

**This is the strongest part of the implementation.**

The visible SPL is preceded by: *"Note what this query does not reference: it
never reads `agentsec.control.decision`."* I read the displayed query and it
does not. The filter is `agentsec.mcp.started OR agentsec.mcp.completed OR
agentsec.mcp.failed OR agentsec.pipeline.stopped`. **The semantic check passes.**

ATTACK `eed80a6c…`:

| sequence | event_name | tool | executed |
|---|---|---|---|
| 4 | `agentsec.mcp.started` | lookup_customer_tier | true |
| 5 | `agentsec.mcp.completed` | lookup_customer_tier | true |

RETEST `cec35c22…`:

| sequence | event_name | tool | executed |
|---|---|---|---|
| 4 | `agentsec.pipeline.stopped` | | |

The two runs are distinguished purely by execution evidence, with the decision
field unavailable to the query. `ALLOW != EXECUTION` and
`DENY != EXECUTION EVIDENCE` both hold. The cell also preserves the right
caution: an absent `mcp.started` is *corroborating* evidence of non-execution,
not proof, because the index is a copy — the runtime handler count remains
authoritative.

## Cell 3 — Requested vs Granted

| run_id | tool | requested_scope | allowed_scope | scope_relationship |
|---|---|---|---|---|
| eed80a6c… | lookup_customer_tier | `customer:read` | `policy:read` | `requested != allowed` |

Identical row for the RETEST. That is the interesting part, and the notebook
handles it correctly.

The cell separates the three facts the brief asked me to check for. The scopes
are labelled **OBSERVED** indexed runtime fields. The grant list itself is
labelled **DOCUMENTED configuration** — "lab configuration you can read in the
repository, not something this query discovered". And the boundary is explicit:
*"A scope mismatch does not by itself tell you what the control decided, or
whether anything executed. Those are Questions 1 and 2."*

So MISMATCH OBSERVED, POLICY DECISION and EXECUTION stay three separate facts.
Nowhere does the notebook say the system "failed to notice" the mismatch. The
ATTACK row shows the mismatch *was* visible and the vulnerable profile allowed
the call regardless — which is the better lesson, and it is the one on screen.

## Cell 4 — Indexed Timeline

Data-driven. No hard-coded expected sequence is narrated anywhere in the cell.

ATTACK `eed80a6c…` — 7 rows:
`run.started` → `hop.started` → `control.decision` (CTRL-MCP-001, ALLOW,
executed=false) → `mcp.started` → `mcp.completed` → `hop.completed` →
`run.completed`

RETEST `cec35c22…` — 6 rows:
`run.started` → `hop.started` → `control.decision` (CTRL-MCP-001, DENY,
executed=false) → `pipeline.stopped` → `hop.completed` → `run.completed`

Native Search returned `Statistics (7)` and `Statistics (6)` for the same two
run.ids with the same ordering. **No discrepancy.**

Worth noting for teaching value: `agentsec.control.decision` carries
`executed=false` in *both* runs, with execution appearing separately at
sequence 4. The telemetry itself distinguishes deciding from doing.

**Defect found here** — see MEDIUM-2. The displayed SPL is an abbreviation and
does not reproduce the displayed table.

## Cell 5 — Claim Boundary

Visually present and complete. Asks for four written statements, each labelled
with the claim vocabulary (PROVEN / SUPPORTED / OBSERVED / NOT PROVEN).

It names the overclaims it refuses rather than hinting at them:

> **WHAT YOU SHOULD NOT WRITE.** "System compromised", "attack successful",
> "system secure" and "retest successful" are all claims about a whole system.
> One tool-authorization run does not reach any of them.

And the boundary:

> Even with both runs in front of you, this evidence covers one tool, one agent
> and one request shape. … **ATTACK != UNIVERSAL COMPROMISE · RETEST !=
> UNIVERSAL SECURITY.**

The omission the automated suite caught during implementation is genuinely fixed
and visible in the browser.

## ATTACK Evidence

Run `eed80a6c-4cf8-405b-833b-75cd8c2f9381`, profile `vulnerable`, 7 indexed events.

| Fact | Value |
|---|---|
| Control decision | ALLOW |
| Decision reason | `vulnerable_profile_fail_open:…` |
| `executed` on the decision event | `false` |
| Separate execution events | `agentsec.mcp.started` (seq 4), `agentsec.mcp.completed` (seq 5), both `executed=true` |
| Terminal sequence | seq 7 `agentsec.run.completed` |
| Workbench runtime handler count | 1 |
| Launcher terminal state | `completed_allowed` |
| `agentsec.llm.*` events | **0** |

Workbench five-state panel reported CONTROL DECISION=ALLOW, EXECUTION
EVIDENCE=EXECUTED ("Runtime handler count 1. Established from execution
evidence, not from the decision"), LAUNCHER TERMINAL STATE=COMPLETED, SPLUNK
EVIDENCE READINESS=WAITING FOR INDEXING, YOUR PREDICTION=CONTROL ALLOW ·
EXECUTION YES. The five states are presented as independent, and the execution
state explicitly disclaims derivation from the decision.

## RETEST Evidence

Run `cec35c22-3f78-498c-8d7d-60998cfba292`, profile `defended`, 6 indexed events.

| Fact | Value |
|---|---|
| Control decision | DENY |
| Decision reason | `tool_not_granted` |
| `executed` on the decision event | `false` |
| Execution events present | **none** |
| `pipeline.stopped` present | **yes**, seq 4 |
| Terminal sequence | seq 6 `agentsec.run.completed` |
| Workbench runtime handler count | 0 |
| Launcher terminal state | `completed_denied` |
| `agentsec.llm.*` events | **0** |

## Notebook vs Independent Splunk Reconciliation

Independent searches were composed by me in native Search, not copied from the
notebook, and run with `earliest=0`.

| Question | Notebook result | Independent Splunk result | Match? | Notes |
|---|---|---|---|---|
| State panel — ATTACK identity | ATTACK / vulnerable / 7 events | `Statistics (7)`, mode ATTACK, profile vulnerable | **YES** | |
| State panel — RETEST identity | RETEST / defended / 6 events | `Statistics (6)`, mode RETEST, profile defended | **YES** | |
| Cell 1 — ATTACK decision | CTRL-MCP-001, ALLOW, `vulnerable_profile_fail_open:…` | identical | **YES** | also confirmed `operation.executed=false` on the event |
| Cell 1 — RETEST decision | CTRL-MCP-001, DENY, `tool_not_granted` | identical | **YES** | |
| Cell 2 — ATTACK execution | `mcp.started` + `mcp.completed`, executed=true | `values(event.name)` = `agentsec.mcp.completed`, `agentsec.mcp.started` | **YES** | decision field never consulted |
| Cell 2 — RETEST execution | `pipeline.stopped` only | `agentsec.pipeline.stopped` only | **YES** | no `mcp.*` for the RETEST |
| Cell 3 — scope, both runs | `customer:read` vs `policy:read`, `requested != allowed` | identical for both run.ids | **YES** | |
| Cell 4 — ordered timeline | 7 rows / 6 rows as listed above | `Statistics (7)` / `Statistics (6)`, same order | **YES** | |
| No-LLM claim | notebook asserts this lab produces no LLM activity | `"event.name"=agentsec.llm.* \| stats count` → **0** | **YES** | no fabricated LLM evidence |

**8 of 8 comparable claims match.** The notebook teaches from evidence an analyst
can independently retrieve.

One caveat belongs in this section rather than being buried: the *executed*
queries agree with independent Search, but the *displayed* queries do not
reproduce the displayed tables. See MEDIUM-2.

## Mission Findings

Clicked MISSION explicitly and scrolled the full tab — this matters, because
Studio lazy-renders below the fold and an unscrolled capture misses half the tab.

MISSION contains two stacked panels. The first is the generic Academy guide
shell ("Where you are / What you are learning / What you do now"). Below it is
the remediated mission panel:

> **What you are determining** — The agent is granted `lookup_policy` /
> `policy:read`. The experiment requests `lookup_customer_tier` /
> `customer:read`, which this agent is not granted.
> Determine, from evidence rather than expectation: whether CTRL-MCP-001
> authorizes the requested tool; whether separate runtime evidence shows the
> handler executed; what differs between the ATTACK run and the RETEST run.
> **Predict each answer in the Attack Service workbench before you launch. The
> outcomes are deliberately not stated here — a prediction you have already been
> given the answer to teaches nothing.**

**No answer leakage.** MISSION never states that ATTACK will ALLOW, that ATTACK
will execute, that RETEST will DENY, or that RETEST will stop execution. It
names the tool and the grant — which is the setup, not the answer — and then
explicitly withholds the outcomes. §25 **PASS**.

Two blemishes, both LOW. The learner meets the generic guide shell first and the
purpose-built mission second. And the guide shell's step 4 says "Read the SPL and
the table on this tab" — there is no SPL table on MISSION; it is on INVESTIGATE.

## Evidence Tab Findings

Clicked EVIDENCE explicitly and scrolled.

The pedagogical separation is correct and stated plainly:

> **This tab is not the guided investigation.** The question-driven notebook for
> your own run lives on INVESTIGATE. Start there. Come here when you already
> know what you are looking for and want the underlying tables side by side.

It also enumerates what it adds that the notebook does not. No duplicated tables:
INVESTIGATE and EVIDENCE share no data source.

**But every panel on the tab returns "No search results returned."** All eight of
them — both What-Happened identity panels, both decision panels, both
Q-MCP-AUTHZ panels, both Q-MCP-EXECUTED panels. The tab delivers nothing.

I traced the cause in native Search: the specimen the tab and dropdown default to,
`163d11e2-e751-4282-9406-19b490542ed4`, returns **`count 0`**. It has no indexed
events. The canonical REPLAY specimens the tab promises do not exist in this
index. See HIGH-1.

Separately, the panel captions state the expected answers outright — *"Expect
decision DENY, reason `tool_not_granted`, execution_state
`no_mcp_execution_event`"*, *"Expect labeled fail-open ALLOW and execution_state
`mcp.completed`"*. EVIDENCE has no prediction gate, unlike PATH B. See MEDIUM-3.

## Path B · Answers Findings

Clicked PATH B · ANSWERS explicitly and visually confirmed the rendered panel.
(My first text extraction returned 13 characters and looked empty — that was a
parsing error on my side, not a rendering failure. The screenshot settles it.)

The tab opens with a gate panel as its first element:

> **Stop — this tab contains the answers**
> Everything below is an **answer key**. It states what CTRL-MCP-001 decides and
> what the execution evidence shows for each mode. Reading it before you predict
> and run removes the only part of this lab that teaches anything. A prediction
> you already know the answer to is not a prediction.
> **Do these first:** 1. Record your prediction in the Attack Service workbench.
> 2. Launch ATTACK, then RETEST. 3. Work through the five questions on
> INVESTIGATE using your own `run.id`.
> **This tab cannot lock itself.** Dashboard Studio has no supported mechanism to
> hide a panel until a condition is met, and faking one with injected JavaScript
> is not a supported extension. The gate is the warning you are reading.

The role is understandable, the tab label says ANSWERS, and the warning precedes
the content. The honesty about not being able to enforce the gate is the right
call — it does not pretend to a control it does not have.

**Can it reveal answers before prediction?** Yes — nothing stops a learner
clicking straight to it. That is a documented, intentional, clearly-labelled
property, not a defect. §26 **PASS**.

## Advanced Search Findings

Native Search survives in two places, both secondary.

On the workbench it is inside a collapsed disclosure, *Advanced — open native
Splunk Search instead*, below the primary Investigate evidence button. The href
resolves to the correct public host with a run-scoped query:

```
http://3.17.29.24:8000/en-US/app/search/search?q=search index=agentsec_telemetry
sourcetype=otel:agentic:json earliest=-1h "agentsec.run.id"="eed80a6c-…"
```

**Run context is preserved.** No `localhost`, no `127.0.0.1`, no wrong port.

At the foot of the notebook, *Advanced investigation — open in Splunk Search*
frames it correctly: *"The notebook above is the classroom. Native Search is the
analyst workbench… Native Search is an addition to this notebook, not a
replacement for it. Nothing you do there changes a control decision: SPLUNK !=
ENFORCEMENT."* The base search there uses the placeholder `"YOUR-RUN-ID"` rather
than the active run — a small missed convenience, not a defect.

## Run-ID Keyboard Entry

**PASS.**

Clicked into the LIVE run.id field, cleared it with Select-All + Backspace, and
typed all 36 characters of `eed80a6c-4cf8-405b-833b-75cd8c2f9381` individually
with a 35 ms inter-key delay, then pressed Enter.

Observed afterwards:
- the field's value read back exactly as typed
- the URL gained `&form.live_run_id=eed80a6c-4cf8-405b-833b-75cd8c2f9381`
- the state panel resolved to that run (ATTACK / vulnerable / 7 events)
- all five result panels repopulated with that run's data

Repeated with the RETEST id via a real paste (below) with the same outcome.

Studio accepts genuine typed input and the token propagates. See *Claim
Boundaries* for exactly what "real keyboard" means here.

## Clipboard Findings

**Control activation observed: yes. Copied content verified: yes.**

`navigator.clipboard` is **unavailable** on this origin — the workbench is served
over plain HTTP, so `window.isSecureContext` is false and Chrome refuses the
async clipboard API. The page's `document.execCommand('copy')` fallback is
therefore the path that actually runs in the deployed environment, and it works.

Clicking **Copy Run ID** produced the visible feedback *"Run ID copied. Use it to
correlate this experiment."*

To verify content rather than trust the message, I performed the real learner
action: switched to the notebook, clicked LIVE run.id, and pressed Cmd+V. The
field received `cec35c22-3f78-498c-8d7d-60998cfba292` — an exact match for the
RETEST run.id. The notebook then resolved to that run.

The notebook links also attach a copy-on-click handler, correctly guarded so it
does nothing when no run exists in the current page session.

## Comparison Persistence

**FIXED.**

Tested in one continuous browser session (necessary, because session history is
backed by `sessionStorage` under the key `agentsec.learner.session.v1`, which is
per-tab by design and correctly described on the page as "A reload keeps this
list in this tab").

Pair used: ATTACK `29d8cfb5-01f2-4288-bc6c-b73cb7b841ba`, RETEST
`c3efad7c-a0e2-4719-81a9-f738e7058f89`.

| State | Rich comparison | Contains "Not run"? | Agrees with session history? |
|---|---|---|---|
| Both runs live, same page load | Full 12-row table, ALLOW vs DENY, DIFFERENT | no | yes |
| After navigating to Splunk Search and back | Full 12-row table, identical | no | yes |
| After a real browser reload | Full 12-row table, identical | no | yes |

The previously reported defect — rich comparison resetting to "Not run" while
session history still listed a completed pair — **did not reproduce**. I observed
the rehydrate happening: four `GET /api/launches/<run-id>` requests returning
200, two per restore.

The restored table is substantive, not a stub: input fingerprint SAME, profile
vulnerable vs defended DIFFERENT, decision ALLOW vs DENY DIFFERENT, handler count
1 vs 0, outcome success vs prevented, and run.id "DIFFERENT — must differ". The
session-history footer independently reports the same pair. **No contradiction
between the two surfaces in any of the three states.**

One honest limitation of the fix, observed directly: the rehydrate requires a
*complete* pair in session history. After a reload with only an ATTACK recorded,
the comparison shows ATTACK as NOT MEASURED even though session history lists
that completed ATTACK. That is the same class of contradiction, in a narrower
case. Noted as MEDIUM-5 rather than a failure of item 22/23, which tested the
specified scenario.

## Canvas / Layout

Scrolled the full INVESTIGATE canvas top to bottom with real mouse-wheel input.

What is correct: all five cells are reachable, in the right order, each result
table directly beneath its question. No overlapping panels, no cells rendered
outside their containers, no floating controls covering content, no broken
vertical sequence, and the final cell is reachable. No horizontal page scrolling
at any width.

What is not: **most markdown panels are allocated noticeably more height than
their content uses.** From the screenshots, the header panel's text ends roughly
380 px above the panel boundary, and Cell 3 ends roughly 280 px above its own.
The pattern repeats across cells, so the learner scrolls through a good deal of
empty white between steps. I could not quantify this precisely — Studio renders
into its own scroll container and my geometry probe returned nothing usable — so
this is **OBSERVED from screenshots, not MEASURED**.

The brief says not to fail on intentional whitespace, and the sequence does still
read as a coherent guided progression. But the volume is beyond stylistic.

Separately and more concretely: **the ATTACK ↔ RETEST live-pair table at the foot
of Cell 5 visually clips its second row.** The panel is too short for two rows
once the long fail-open `reason` text wraps, so only the ATTACK row is visible.
Reproduced at both 1920 px and 1024 px. The RETEST row exists in the DOM — which
is exactly the trap the brief warned about — but a learner looking at the panel
sees one row where Cell 5 tells them to read two. See MEDIUM-4.

## 200% Zoom

**NOT TESTED.**

Chrome exposes no DevTools-Protocol API for page zoom, so I attempted the only
genuine route available: writing Chrome's own persisted zoom preference
(`profile.default_zoom_level`, `partition.default_zoom_level` and
`per_host_zoom_levels` = 3.8018, since Chrome stores zoom as 1.2^level and
1.2^3.8018 = 2.000) into a real Chrome profile before launch.

Two attempts, the second with Playwright's viewport override removed so Chrome's
own window governed layout. Verification in both cases: compare the CSS viewport
width against the 100% baseline at an identical window size. True 200% zoom
halves it.

| | innerWidth | outerWidth | devicePixelRatio |
|---|---|---|---|
| Baseline 100% | 1920 | 1920 | 1 |
| Zoom profile applied | 1920 | 1920 | 1 |

Ratio 1.000, expected ~2.000. **The zoom did not take effect**, so there is
nothing to report about rendering at 200%.

Per the brief I am not converting this to PASS and not substituting the viewport
results for it. Horizontal scrolling, clipped SPL, table readability, overlapping
cards, run-id input reachability and Cell 5 reachability at 200% are all
unmeasured. This gap is stated in the verdict.

## Keyboard / Accessibility

Real Tab traversal from the top of the loaded workshop, 80 presses recorded.

| Target | First reached at |
|---|---|
| Skip-navigation link | press 24 |
| Investigate specimen dropdown | press 32 |
| **LIVE run.id input** | **press 33** |
| INVESTIGATE tab | press 35 |
| Cell 1 content region | press 53 |

No keyboard trap: focus advanced to a distinct target on every press through 80
and continued into the notebook cells, whose panels are themselves focusable
regions with `outline: auto`. Order is logical — platform chrome, then
dashboard inputs, then tabs, then content in document order.

Two weaknesses. Reaching the learning controls takes 32 presses through Splunk's
own navigation; the skip-nav link at press 24 mitigates this but arrives late.
And the LIVE run.id input itself reports `outline-style: none` with no
compensating box-shadow, so it is the one control in the chain with no visible
focus indicator — on the single most important field in the notebook. Most
surrounding Splunk controls do render a focus shadow.

Marked PARTIAL. This is Splunk platform styling as much as AgentSec's, and
nothing here blocks a keyboard user.

## Responsive

| Width | Horizontal page overflow | Assessment |
|---|---|---|
| 1920 | none | clean |
| 1440 | none | clean |
| 1280 | none | clean |
| 1024 | none | text reflows, tabs and inputs all reachable, tables scroll internally |

No material layout breakage at any width. The live-pair row clipping described
above is present at 1024 as well, but it is a panel-height problem, not a
responsive one.

## Your Path Regression

Renders, not blank, 3701 characters of content, 32 workshop cards each with
state and *Mark in progress* / *Mark investigated* actions. LAB-MCP-001 appears
as "L1 · Tool Authorization · LIVE".

Framing is correct and unchanged: *"Browser-local learning navigation. Not
indexed evidence and not a security verdict… INVESTIGATED means you marked the
workshop, not that the system is safe."*

Progress persistence tested with a real click on a *Mark investigated* button:
counter moved from `INVESTIGATED 0 of 32` to `INVESTIGATED 1 of 32`, survived a
real browser reload, and survived navigating to Home and back. **PASS.**

(My click landed on a different card than intended because of a loose selector on
my side; the persistence behaviour under test is unaffected.)

## Build Information Regression

Home exposes tabs `START, ORIENT, PATH, SPLUNK, BUILD`. BUILD renders.

| Field | Observed | Source the panel cites |
|---|---|---|
| AgentSec version | **1.1.0** | `pyproject.toml` |
| Splunk app build | **4** | `[install] build` in `app.conf` |
| Static asset digest | `589e739d0798fb44…` | `splunk_app/static_cache_identity.json` |
| Telemetry schema | **1.9.0** | `agentsec.experiment.SCHEMA_VERSION` |
| ExternalEvidence contract | **1.0.0** | `agentsec.external_evidence.contract` |
| Curriculum | 11 levels, 19 labs, 12 checkpoints | `learning/academy/curriculum.json` |

All four expected values match. The panel is careful about what it does not
claim: *"SERVICE HEALTH ≠ EVIDENCE READINESS ≠ MODEL QUALITY"*, and it explains
the degraded KV Store as a MongoDB/kernel mismatch that does not affect
workshops. That explanation matches the console noise I observed.

One inconsistency: BUILD reports 19 labs + 12 checkpoints = 31, while Your Path
and the MISSION breadcrumb both say 32. LOW.

## Browser Console Findings

| Class | Observed | Assessment |
|---|---|---|
| Splunk platform 503s on `/app/launcher/home` and workshop loads | repeatedly | **Platform noise.** Consistent with the degraded KV Store the BUILD panel documents. |
| `SyntaxError: Unexpected token '<', "<?xml vers"... is not valid JSON` | on launcher home | **Platform noise.** Splunk receiving an XML error body where JSON was expected, downstream of the same KV Store state. |
| Repeated 404s for platform resources on Search and workshop pages | many | **Platform noise.** Missing Splunk static assets, not AgentSec files. |
| AgentSec-caused errors | **none** | No `pageerror` originated from AgentSec pages. |
| Attack Service pages (`/acmebank`, `/labs/LAB-MCP-001`) | **clean** | Zero console errors or warnings across every visit. |

No console error affected the learner journey. Every page I needed rendered and
every interaction I attempted worked.

## BLOCKER Findings

**None.**

## HIGH Findings

### HIGH-1 — The canonical REPLAY specimen has no indexed events, so the pre-run notebook and the whole EVIDENCE tab are empty

The `Investigate specimen` dropdown defaults to
`163d11e2-e751-4282-9406-19b490542ed4`. Independent search:

```
index=agentsec_telemetry sourcetype=otel:agentic:json
"agentsec.run.id"="163d11e2-e751-4282-9406-19b490542ed4" | stats count
```
→ **`count 0`**

Consequences observed in the browser:

- Every one of the eight EVIDENCE-tab panels shows "No search results returned".
- The notebook's documented fallback is broken. The header says *"Leave it empty
  to investigate the canonical REPLAY specimen chosen in Investigate specimen"*
  and MISSION says *"Canonical REPLAY specimens remain available in Investigate
  specimen if you have not run the experiment yet."* Neither is true here.
- A learner who opens INVESTIGATE before running anything — a natural first move,
  and the state the handoff lands them near — meets five empty tables.

The notebook's own caution ("No row here means this query matched nothing, which
is weaker than proof") partly softens this, but it reads as an evidence lesson
when the real cause is missing specimen data.

Evidence is not corrupted and the primary path (run → investigate) is unaffected.
I am rating this HIGH because a documented learner path is non-functional and the
failure is silent.

## MEDIUM Findings

### MEDIUM-1 — Primary handoff lands on MISSION, not INVESTIGATE

The workbench states the button "opens the guided Investigation Notebook on the
workshop's INVESTIGATE tab". Observed destination:
`…/ws_lab_mcp_001?form.run_id=163d11e2-…&tab=layout_mission`. The learner must
find and click INVESTIGATE unaided. The claim on the source page is inaccurate.

### MEDIUM-2 — The displayed SPL is not the SPL that ran

Cell 1 introduces its query with *"This is the SPL the table below runs."* The
displayed queries are abbreviated with a leading `...` and omit the token
disambiguation and several `eval` lines.

I ran Cell 4's visible SPL verbatim in native Search, as a learner would:

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0
("agentsec.run.id"="eed80a6c-…" OR "agentsec.run.id"="163d11e2-…")
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| table _time, sequence, event_name, control_id, decision, executed
| sort sequence
```

It returned 7 rows with **`event_name`, `control_id`, `decision` and `executed`
all blank** — four of the six promised columns — because the `eval` lines that
create them are not shown. It also omits `| where run_id==selected_run`, so with
a populated specimen it would merge two runs; it only looks correct here because
the specimen is empty (HIGH-1).

The executed query is correct and its results are independently corroborated.
The problem is the gap between what the learner is shown and what produced the
answer, in the one product surface built entirely on checking claims against
evidence.

### MEDIUM-3 — The EVIDENCE tab states expected answers with no gate

Panel captions include *"Expect decision DENY, reason `tool_not_granted`,
execution_state `no_mcp_execution_event`, outcome prevented"* and *"Expect
labeled fail-open ALLOW and execution_state `mcp.completed`"*. EVIDENCE sits
between INVESTIGATE and PATH B in the tab strip, carries no answer-key warning,
and is one click away at any time. PATH B was gated; this was not.

### MEDIUM-4 — The ATTACK ↔ RETEST live-pair table visually clips the RETEST row

Cell 5 instructs the learner to read "what changed between ATTACK and RETEST,
from the comparison below". The panel is too short for two rows once the
fail-open `reason` wraps, so only the ATTACK row is visible. Reproduced at 1920
and 1024. The row is in the DOM but not on screen, and the cell's own guidance
warns that "one row instead of two means you are not looking at your own pair" —
so the clipping actively misleads against the text beside it.

### MEDIUM-5 — Comparison rehydrate needs a complete pair

After a reload with only an ATTACK in session history, the rich comparison shows
ATTACK as NOT MEASURED while session history lists that completed ATTACK. The
specified reload/navigation scenarios pass; this narrower case still shows the
two surfaces disagreeing.

## LOW Findings

- **LOW-1** — MISSION shows the generic Academy guide shell above the
  purpose-built mission panel, so the learner meets boilerplate before the
  lab-specific framing.
- **LOW-2** — The guide shell's step 4 reads "Read the SPL and the table on this
  tab". There is no SPL table on MISSION; it is on INVESTIGATE.
- **LOW-3** — Curriculum counts disagree: BUILD reports 19 labs + 12 checkpoints
  (31); Your Path and the MISSION breadcrumb say 32.
- **LOW-4** — The LIVE run.id input has no visible focus indicator
  (`outline-style: none`, no box-shadow) while neighbouring controls do.
- **LOW-5** — Substantial unused vertical space in most notebook panels
  (visually ~280–380 px per panel), increasing scroll distance between steps.
- **LOW-6** — The notebook's advanced-search block uses the literal placeholder
  `"YOUR-RUN-ID"` rather than the active run, unlike the workbench link which
  carries real run context.
- **LOW-7** — AcmeBank's only forward navigation is hidden inside a collapsed
  `See how the AI did this` disclosure.

## NOT TESTED

- **True 200% browser zoom (§21).** Two genuine attempts; Chrome's persisted zoom
  preference did not apply under automation and the CSS viewport never halved.
  Not converted to PASS. Everything §21 asks about — horizontal scrolling,
  clipped SPL, unreadable tables, overlapping cards, hidden actions, run-id input
  accessibility, Cell 5 reachability at 200% — is unmeasured.
- **Candidate git SHA `afa553b`.** Not exposed anywhere in the deployed UI, so it
  could not be confirmed from the browser. Packaged identity was confirmed instead.
- **`origin/main` at `0178c70`.** A repository fact, outside a browser review.
- **Dead-space quantification.** Observed from screenshots; not measured, because
  Studio's internal scroll container defeated my geometry probe.
- **Screen-reader behaviour.** Out of scope for this brief and not attempted.

## Claim Boundaries

**On "real keyboard" and "real clicks".** Every interaction in this review was
delivered through the Chrome DevTools Protocol `Input` domain driving a real
Google Chrome 153.0.8010.55 binary. These arrive as trusted browser-level input
events — the same pipeline hardware input uses — and are categorically different
from `element.dispatchEvent(new Event('input'))`, from setting `.value`
programmatically, or from writing tokens directly. I used none of those, and I
did not edit `localStorage`, `sessionStorage` or any browser state by hand. That
said, this is automation, not a human at a physical keyboard, and I am naming the
distinction rather than letting "PASS" imply more than I measured.

**On JavaScript evaluation.** I used page evaluation only for *observation*
(reading `innerWidth`, computed focus styles, `isSecureContext`, listing storage
keys) and never to cause or simulate an interaction. Clipboard content was
verified by a real paste, not by reading the clipboard API.

**On text extraction.** Every visibility claim in this report is backed by a
screenshot or by `aria-selected` state after a real tab click. Where I initially
reached a conclusion from text alone and the screenshot contradicted it — PATH B
appearing empty — the screenshot won and the text-based reading is discarded.

**On the EVIDENCE/specimen finding.** I established `count 0` for the specimen in
native Search. I did not investigate *why* the specimen data is absent, whether it
was ever present in this index, or whether this is environment-specific. That
diagnosis is for the implementer.

**On what these two runs prove.** They demonstrate CTRL-MCP-001 behaving
differently under two profiles for one tool, one agent and one request shape.
They do not show the control is correct in general, and they do not prove nothing
else executed. `ATTACK != UNIVERSAL COMPROMISE`. `RETEST != UNIVERSAL SECURITY`.

**On Splunk's role.** Everything observed is consistent with Splunk as downstream
evidence. No dashboard made an authorization decision, DET-MCP-001 is packaged
disabled and the dashboard states it does not enable it, and both the notebook
and the workbench repeat `SPLUNK != ENFORCEMENT`.

## Final Verdict

**CONDITIONAL — NOTEBOOK REMEDIATION REQUIRED**

The notebook itself is good work and the core of the brief is met. Five distinct
guided cells render and are usable. The authorization/execution separation is
enforced in the query rather than asserted in prose, and it demonstrably
distinguishes the two runs without consulting the decision field. The
requested/granted distinction is preserved as three separate facts, including
the subtle and better lesson that the vulnerable profile saw the scope mismatch
and allowed the call anyway. Cell 4 is data-driven. Cell 5's claim boundary is
visibly present. Fresh ATTACK and RETEST runs work, the notebook follows the
selected run, and all eight independently comparable claims match native Splunk
Search. No fabricated LLM or tool-call evidence exists — both runs return zero
LLM events. The previously-reported comparison reset is fixed and I watched it
rehydrate. There is no BLOCKER.

It does not freeze, for three reasons.

**HIGH-1 is open and silent.** The canonical REPLAY specimen has zero indexed
events, so the EVIDENCE tab is entirely empty and the pre-run notebook — a
documented entry path, promised in two places — shows five blank tables with no
explanation of why.

**MEDIUM-2 undermines the remediation's own premise.** The notebook tells the
learner "This is the SPL the table below runs" and then shows a query that, run
verbatim, returns four of six columns blank. The whole point of making SPL
visible is that the learner can check the answer against the query. Right now
they cannot, and the discrepancy is invisible unless they try.

**§21 could not be measured.** True 200% browser zoom is a critical browser-only
requirement in this brief, and two genuine attempts failed to apply it. I will
not convert that to a PASS. This missing measurement independently prevents a
freeze verdict: accessibility at 200% is unknown, not acceptable.

MEDIUM-1, MEDIUM-3, MEDIUM-4, MEDIUM-5 and the LOW items are documented above and
do not individually block, but MEDIUM-4 deserves attention alongside HIGH-1
because both cause a panel to show the learner less than the surrounding text
promises.

Evidence integrity is intact throughout. Security semantics are intact
throughout. The golden path — predict, run, investigate, compare — is usable end
to end. What needs fixing is what the learner is shown, not what the system did.
