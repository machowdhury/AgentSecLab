# AgentSec Phase 1 — learner experience redesign (design proposal)

| | |
|---|---|
| Status | **DESIGN PROPOSAL.** No application code, Splunk content, schema, telemetry or test was changed. |
| Baseline | `b68d0ddf951349bf410fd7449ea3ed46b71d8a58` · AgentSec 1.1.0 · app build 4 · schema 1.9.0 · ExternalEvidence 1.0.0 |
| Priority order | REAL EVIDENCE CONTRACT > SECURITY SEMANTICS > SUPPORTED SPLUNK ARCHITECTURE > EXISTING FUNCTIONAL CONTRACT > INSTRUCTIONAL UX > VISUAL FIDELITY |
| Builds on | `docs/design/FIGMA_V2_PRODUCTION_MAPPING.md` (earlier mapping of the Figma v2 prototype to production). This pass does not repeat it. |
| Mockup | `docs/design/mockups/phase1-learner-ux.html` (static, no script) and PNG frames in `docs/design/mockups/frames/` |

## 0. Evidence basis and honest limits

Reconciliation with the supplied Figma v2 export is in §12.

| Label | Used for |
|---|---|
| **OBSERVED** | Seen in the real deployed product during the independent re-validation of this same candidate (screenshots, DOM). |
| **MEASURED** | Splunk counts and decisions from fresh runs `12f0269f-b06c-4db8-a224-6c42bc9521c0` (ATTACK) and `ea25befa-900b-4a2b-b04c-cbb09e7ae4a3` (RETEST), 2026-10-06. |
| **REPLAYED** | The committed baseline specimen `163d11e2-e751-4282-9406-19b490542ed4`. |
| **DOCUMENTED** | Repo docs and source (cited by path). |
| **CALCULATED** | WCAG contrast ratios computed from token values. Not re-measured in the deployed CSS. |
| **INFERRED** | UX judgement. Stated as judgement. |

Limits you should know about:

1. **No Figma file was created.** The Figma MCP namespace reported `needsAuth`, and the authentication call returned "already handled" without enabling any tool. I substituted a static HTML mockup, rendered in real Chrome and read frame by frame. The mockup is a faithful layout spec; it is not a Figma file. See §3.4 for how to build the Figma file from it.
2. **No new usability test was run.** The diagnosis comes from the validation evidence and from the product owner's own stumble ("when do I run baseline, attack, retest?"). That stumble is real evidence of a problem. It is one learner, not a study.
3. **I did not re-review every screen.** Academy Home, the full EVIDENCE tab and PATH B were reviewed in earlier passes and not re-opened here. Findings about them are marked.
4. **Readability at true 200% browser zoom was never established** (see D11). That gap carries into this design.

## 1. UX diagnosis

### 1.1 Findings, ranked

| # | Rank | Where a learner must infer | Evidence | Fix (section) |
|---|---|---|---|---|
| D1 | **BLOCKING LEARNING** | Whether the Studio control *selects evidence* or *performs an action*. The header reads "Investigate specimen: Baseline / Attack / Retest" beside "LIVE run.id `none`". "Attack" and "Retest" are the same words as the launch buttons. | OBSERVED (Studio header); product-owner question | §2 step 5, §4 Evidence Source Selector |
| D2 | **BLOCKING LEARNING** | What the whole path is and where they are. A stepper exists only on the Workbench (8 steps: Understand, Predict, Attack, Observe, Investigate, Retest, Compare, Explain). It is absent from AcmeBank, from Studio, and from Your Path. Studio's four tabs (MISSION, INVESTIGATE, EVIDENCE, PATH B · ANSWERS) do not map to the loop. | DOCUMENTED (`attack_mcp.html`), OBSERVED | §2, §4 Progress Rail |
| D3 | **BLOCKING LEARNING** | How to carry the run to the notebook. Today: copy run.id → open notebook → click the field → select `none` → paste → Enter. Pasting without selecting produces `none<run-id>`, which fails with a generic "No search results returned". | OBSERVED (typing and paste scenarios in the re-validation) | §2 step 5; **see §9.1, a URL deep link works** |
| D4 | **BLOCKING LEARNING** | When to run BASELINE, and why. BASELINE has no step. It appears as one sentence in the business story and as a dropdown value. DEFEND has no step either, so RETEST arrives with no explanation of what changed. | DOCUMENTED (template), product-owner question | §2 steps 2 and 6 |
| D5 | HIGH | What to do next after ATTACK. The Workbench page stacks: facts, decision chain, comparison, a "next investigation" section, and an Advanced section. The primary action "Investigate evidence" appears in two places and is not the visually dominant element. | DOCUMENTED (template), OBSERVED | §2 step 4, Frame 03 |
| D6 | HIGH | Whether the outcome is revealed before they investigate. Post-run fact cards show control decision and execution immediately, which undercuts the INVESTIGATE step. | DOCUMENTED (template) | §2 steps 4 and 8; decision O1 |
| D7 | HIGH | Whether SPL must be run. The notebook says "Copy any of them into Splunk Search" while results are already shown. The state query (13 lines) is printed on the first screen before Cell 1. | OBSERVED (INVESTIGATE top, default state) | §4 Expandable SPL, Frame 06 |
| D8 | HIGH | **The prose contradicts the selected evidence.** With the default Baseline selected, static text says "The run you are investigating requested `lookup_customer_tier`" while the table beneath shows `lookup_policy · ALLOW · tool_granted`. | OBSERVED (REPLAY baseline view: prose and table disagree) | §7 IMPROVE I-1 |
| D9 | HIGH | Whether evidence is LIVE or REPLAY. It is stated in prose in the state panel and in the lab-mode badge only. Nothing is persistent on screen. | OBSERVED | §4 LIVE/REPLAY badges |
| D10 | HIGH | Which tab matters. "PATH B · ANSWERS" is jargon, and a spoiler is one click away. Studio cannot lock it. | DOCUMENTED (builder comment: "Studio cannot conditionally hide a panel") | §6 row 8 |
| D11 | MEDIUM | At 200% browser zoom on a 1920×1080 window, Splunk's three-row navigation leaves a dashboard scroll region of only **132 CSS px** (726 px at 100%). Whether the notebook is comfortably readable through it was **not established** (screenshots under real zoom were unreliable; OS capture was denied). | MEASURED (DOM), visual NOT TESTED | §6 row 26; human check required |
| D12 | MEDIUM | Whether the red "Run ATTACK" button means compromise. It uses a danger style. | OBSERVED (Workbench screenshot) | §4 Experiment Card |
| D13 | MEDIUM | Notebook cell order: prose → printed SPL → result at the bottom. There is no hypothesis prompt and no "next question". | OBSERVED (page text order) | §4 Investigation Cell |
| D14 | MEDIUM | The notebook opens in a new tab (`target="_blank"`). Session state is per tab, so continuity is a coincidence of timing. | DOCUMENTED (template) | §6 row 24 |
| D15 | MEDIUM | The completion moment. "Mark investigated" lives on Your Path, a separate page, with no hand-off from the end of the lab. | OBSERVED (Your Path), DOCUMENTED | §2 step 9 |
| D16 | MEDIUM | The MCP diagram is a vertical stack in an 880×384 viewBox with 15-unit text, no DENY branch and no trust boundary. | DOCUMENTED (`flow-lab-mcp-001.svg`) | §5 |
| D17 | MEDIUM | Existing DENY amber text on its tint is **3.08:1**, below 4.5:1 for normal text. ALLOW blue is 4.86:1. | CALCULATED from the documented tokens `#B7791F/#F6EBD8` and `#3568A8/#E8EEF5` | §4 tokens |
| D18 | LOW | Known small items: Cell 5 subtitle ellipsised at 1024; Cell 4 clipped ~15 px at 1024; printed SPL scrolls horizontally at ≤1440; `appLogo.png` 404; "MODE · NOT RUN" jargon; "specimen/mode/profile/launch" vocabulary mix. | OBSERVED | polish |
| D19 | LOW | The AcmeBank page ends its captured viewport with no visible next-step control. Not verified below the fold. | INFERRED, **verify** | §2 step 1 |

### 1.2 What is already good and must not be disturbed

The two-question prediction (control vs execution), the ALLOW-is-not-green mapping, the `≠` fact pairing, "UNKNOWN is an honest answer", the Cell 2 independence from `agentsec.control.decision`, "Absent event is corroboration, not proof", REPLAY labelled as recorded, the closed launch request, and the three-world framing on AcmeBank and the Workbench. See §7 KEEP.

## 2. Golden learner journey (LAB-MCP-001)

Nine steps. **Surface** says where the step lives. Steps 5, 6 and 8 cross between the web app (port 5001) and Dashboard Studio (port 8000). The two surfaces cannot share state (§6 row 3), so each step is designed to stand alone and tell the learner what comes next.

| # | Step | Surface | Learner goal | Primary question | Primary action | Visible evidence | Hidden until requested | Next action |
|---|---|---|---|---|---|---|---|---|
| 1 | **LEARN** | Academy Home → Your Path → AcmeBank → Behind AI → lab brief (web app) | Understand the business story and the security question | "What is the agent allowed to do, and what am I about to test?" | Read the brief. Open "See how the AI did this" if curious. | DOCUMENTED business story; mission grid (normal tool, requested tool, control under test, attacker influence) | Architecture detail (Behind AI) | "Continue to BASELINE" |
| 2 | **BASELINE** | Web app step card → Studio INVESTIGATE (REPLAY) | See normal behavior before attacking | "What does the granted request look like in the evidence?" | "Inspect the recorded baseline evidence" (opens Studio with the REPLAY baseline loaded) | `lookup_policy` → `ALLOW` (`tool_granted`) → `mcp.started` and `mcp.completed` (REPLAYED) | Event names, SPL, run.id | "Baseline established. Now test a known tool it was not granted." → PREDICT |
| 3 | **PREDICT** | Web app | Commit to a hypothesis before seeing the result | "What *should* the control do?" and, separately, "Will the tool actually execute?" | Choose ALLOW/DENY/ERROR/UNSURE and YES/NO/UNSURE, then "Record prediction" | Nothing outcome-related | Privacy note (stays in this tab) | Unlocks ATTACK |
| 4 | **ATTACK** | Web app | Run the experiment | "What happens when the agent asks for a known but ungranted tool?" | "Run ATTACK experiment" | After the run: `LIVE · YOUR EXPERIMENT`, "ATTACK experiment complete", launcher status labelled "not a security verdict" | run.id, copy, native Search, launcher facts (decision/execution cards) | "Investigate what actually happened" → INVESTIGATE |
| 5 | **INVESTIGATE** | Studio INVESTIGATE (deep-linked to this run) | Establish facts from evidence | Cells 1–5 (§4 Investigation Cell) | Read each cell's evidence; write an observation | LIVE badge; five evidence results | SPL (demoted), run.id (technical line), raw events | "Next: DEFEND — what control changes?" |
| 6 | **DEFEND** | Web app | Understand what the control changes | "What control changed, why should it matter, what do we expect to change?" | Read; click "I understand what changed" | The vulnerable decision's own reason text (`vulnerable_profile_fail_open …`) | Profile details | RETEST |
| 7 | **RETEST** | Web app | Repeat the same request under the defended profile | "Does the same request now behave differently?" | "Run RETEST experiment" | `LIVE · YOUR EXPERIMENT` (RETEST / defended profile); "Now compare what actually changed." | run.id etc. | COMPARE |
| 8 | **COMPARE** | Web app comparison card and Studio Cell 5 | See what changed between the two runs | "Which facts differ, and which do not?" | Read the table; read "Check your prediction" | Requested tool, granted tool (DOCUMENTED), decision, execution started?, pipeline stopped?, outcome, events indexed | Raw events; reason strings | EXPLAIN |
| 9 | **EXPLAIN / PROVE** | Web app closing card → Your Path | State what you can and cannot claim | The five questions: what happened, what supports it, what does it not prove, what changed, what can you safely claim | Write answers where you control them, then open Your Path to mark the workshop | Safe and unsafe claim examples | Answer key tab | Next workshop on Your Path |

Notes on steps that need an honest constraint:

- **Step 2 is REPLAY, not a live baseline.** The launch contract is closed to two modes (`ATTACK|RETEST`). A live BASELINE launch would change that contract and is **FUTURE**. The UI says so plainly: "supplied as a recorded example so you can study normal behavior without running anything."
- **Step 6 has no toggle.** The defended profile is chosen server-side. DEFEND is an explanation step. Letting the learner flip the control would be **FUTURE**.
- **Steps 4→5 and 7→8 hand a run across surfaces.** Use the deep link (§9.1), keep the clipboard as fallback.
- **Marking INVESTIGATED (step 9)** stays on Your Path. Neither Studio nor the web app can write that browser storage (§6 row 21).

## 3. Figma frames

### 3.1 What exists

| Frame | File | Surface | What it proves |
|---|---|---|---|
| 01 | `frames/01-progress-rail.png` | web app | Rail states (done / current / next / later) by shape and word; world chips; LIVE vs REPLAY badges; narrow rail |
| 02 | `frames/02-baseline-and-predict.png` | web app | BASELINE and PREDICT step cards |
| 03 | `frames/03-attack-before-and-after.png` | web app | ATTACK before and after; one dominant next action; technical details |
| 04 | `frames/04-narrow-attack-complete.png` | web app, 390 | Narrow ATTACK complete |
| 05 | `frames/05-studio-evidence-header.png` | Studio | Evidence-source relabel; LIVE and REPLAY states; renamed tabs |
| 06 | `frames/06-notebook-cell.png` | Studio | One investigation cell, result first, SPL last |
| 07 | `frames/07-defend-and-retest.png` | web app | DEFEND and RETEST |
| 08 / 09 | `frames/08-compare.png`, `frames/09-narrow-compare.png` | web app | Desktop table and narrow stacked cards |
| 10 | `frames/10-explain.png` | web app | EXPLAIN / PROVE |
| 11 | `frames/11-diagram-system.png` | both | Diagram grammar, wide flow, vertical flow |

(The PNG file numbers follow render order. The labels inside the mockup read FRAME 01 to FRAME 10, with 08b for the narrow comparison, so file `11-diagram-system.png` is FRAME 10 in the HTML.)

### 3.2 What the frames use

Values are copied from the measured runs: ATTACK decision `ALLOW` with reason `vulnerable_profile_fail_open …`, `mcp.started` 1, `mcp.completed` 1, 7 events; RETEST decision `DENY` with reason `tool_not_granted`, `pipeline.stopped` 1, `mcp.started` 0, 6 events. Baseline: `lookup_policy`, `ALLOW`, `tool_granted`. The mockup draws **no** LLM, prompt, token or reasoning panel because LAB-MCP-001 emits no LLM events (MEASURED: 0 for both fresh runs). Learner choices in the frames (prediction, checklist) are examples of learning state.

### 3.3 Frames not drawn

Academy Home, Your Path, AcmeBank, Behind AI, and the full EVIDENCE and ANSWER KEY tabs are **not** redrawn. They are working and validated (Your Path is a hard guardrail in the earlier mapping). Their changes are small text changes, listed in §8 (P1/P2).

### 3.4 Building the Figma file

When Figma authentication works, build from `phase1-learner-ux.html`: one page per surface (web app, Studio), the tokens in §4.1 as Figma variables, and each component in §4 as a component with variants. Use the frame PNGs as the visual reference. Keep the surface tags on every frame so a Studio-constrained frame is never mistaken for a web-app frame.

## 4. Component system

Fourteen components. Each says where it can be built.

### 4.1 Tokens

| Token | Value | Use |
|---|---|---|
| ink | `#0B1F33` | primary text, primary button, control node |
| teal | `#00585D` on `#E1F2F2` | "you are here", next-step bar (7.12:1) |
| world 1 / 2 / 3 | `#5B4636/#F1EBE4` · `#2F3E8F/#E9ECF8` · `#00585D/#E1F2F2` | world chips (7.47 / 8.08 / 7.12:1) |
| ALLOW pill | `#234E8A` on `#E8EEF5` | informational, never "good" (7.11:1; existing token is 4.86:1) |
| DENY pill | `#7A4E00` on `#F6EBD8` | informational, never "safe" (6.10:1; existing token is **3.08:1**) |
| executed yes / no | white on ink · `#3D4654` on `#EEF1F4` | unchanged from the existing mapping |
| focus | 3 px `#00585D` outline, 2 px offset, white halo | all interactive elements |
| type | 16 px body, 14 px minimum supporting, 18–26 px headings | web app |
| target size | 44 px minimum | web app buttons and radio cards |

No green, no red anywhere. State is conveyed by shape, border style, glyph and a word.

### 4.2 Components

| Component | Purpose | Where buildable |
|---|---|---|
| **Learning Step Header** | "Step 4 of 9 · ATTACK" plus world chip(s) | web app; Studio as static markdown text |
| **Progress Rail** | 9 steps, done ✓ / current ring "You are here" / next / later; learning state only | web app (stateful); Studio static band (no state) |
| **Business Context Card** | The AcmeBank story for this step | web app; Studio markdown |
| **Prediction Card** | Two separate questions, "Record prediction" | web app only (existing mechanism) |
| **Experiment Card** | What you do / what gets recorded / what it will not tell you, plus one primary button (dark, not red) | web app only |
| **Evidence Source Selector** | One labelled area: "Recorded example (REPLAY)" dropdown plus "Your experiment run.id (LIVE) — advanced" input | Studio inputs (titles and item labels) |
| **LIVE Evidence Badge** | Solid ink, filled dot, "LIVE · YOUR EXPERIMENT" | web app; Studio via search-driven state panel |
| **REPLAY Evidence Badge** | Dashed border, ⟲, "REPLAY · RECORDED EXAMPLE" | same |
| **Investigation Cell** | Question → Why → Hypothesis → Evidence result → Your observation → Supports → Does not prove → Next question → SPL (last) | Studio stacked markdown + table blocks |
| **Evidence Result** | Table with literal text; independence caption where relevant (Cell 2) | Studio table |
| **Evidence Boundary** | "What this does not prove" block with its own label | Studio markdown |
| **Expandable SPL** | See §6 rows 9–13: in Studio it is a demoted block, not a collapsible | Studio demoted block; web app real `<details>` |
| **Next Question / Next Step Bar** | One dominant action and one sentence of "why" | web app; Studio markdown link |
| **ATTACK/RETEST Comparison** | Seven rows, "How it was established" column, "Check your prediction", "Do not conclude" | web app; Studio Cell 5 keeps the validated transposed pair |
| **Technical Details Disclosure** | run.id, copy, native Search, closed request | web app (real disclosure) |

A **Framework Context placeholder** is reserved as an empty slot below "Do not conclude" and renders nothing in Phase 1. It exists only so a future phase does not force a layout change. It must not display mapped frameworks, because no validated mapping exists for this lab.

### 4.3 Component rules that protect semantics

- A decision pill and an execution pill never share a cell, a colour or a sentence.
- "ALLOW" and "DENY" always render the literal word.
- Any count is labelled as a count, not a completeness guarantee.
- A REPLAY badge is never shown on a run the learner launched, and a LIVE badge never on a committed specimen. In Studio the distinction is computed: the three canonical specimen ids are REPLAY; any other loaded run id is LIVE.

## 5. Diagram system

### 5.1 Grammar

| Element | Treatment (not colour alone) |
|---|---|
| Actor | white, solid 2 px ink border, rounded |
| Request | white, **dashed** ink border (data, not authority) |
| Control / PDP | **filled ink with an inner white keyline**; the only filled node |
| Execution | white, **heavy 5 px teal** border |
| Stop | gray fill, dark left bar, "■" glyph |
| Evidence | **dotted** border, "◫" glyph; sits below the boundary |
| External system | double border, "↗" glyph |
| Trust boundary | large **dashed** rounded rectangle, labelled |
| Decision branch | ALLOW solid arrow, DENY dashed arrow, both labelled in words |

### 5.2 Rules

Desktop reads left to right and branches downward at the control. Primary labels 18–19 px, supporting text 15–16 px, tags 13 px (in the viewBox; Studio scales the SVG up). Telemetry is drawn **downstream and dotted**, with the line "It records what happened. It does not make the authorization decision." The existing diagram's text, "HANDLER START — only after ALLOW", is kept in meaning.

### 5.3 Deliverable shape

Two SVGs per lab: a wide one (`viewBox 1232×440`) and a narrow one (`360×700`). Studio uses only the wide file. The web app serves both and chooses with CSS. Media queries inside a single SVG are **unverified** in a Studio image panel and are treated as unsupported until a spike proves otherwise. Any change under `appserver/static/` requires an `[install] build` bump and `scripts/static_cache_identity.py --write` (DOCUMENTED guardrail).

## 6. Splunk implementation map

Classes: **S** = SUPPORTED · **C** = SUPPORTED WITH CONSTRAINTS · **N** = NOT SUPPORTED.

| # | Proposal | Class | Maps to | Constraint / reason |
|---|---|---|---|---|
| 1 | 9-step progress rail with state | **S** | AgentSec web app | State is per-tab `sessionStorage`; learning state only |
| 2 | Rail inside Studio | **C** | Dashboard Studio markdown | Static text only ("Step 5 of 9 · you are here"). Cannot show done/next |
| 3 | Rail state shared across web app and Studio | **N** | — | Different origins (5001 vs 8000); durable sharing needs server-side learner state = FUTURE |
| 4 | "Investigate your ATTACK evidence" opens Studio already loaded via `?form.live_run_id=<id>` | **C** | AgentSec web app link → Studio token | **OBSERVED to work on this deployment** (§9.1). Not confirmed in Splunk docs by my search. Needs a regression test; keep the clipboard fallback |
| 5 | Relabel Evidence Source controls (input titles, dropdown item labels) | **S** | Dashboard Studio inputs | Tokens and values unchanged |
| 6 | LIVE / REPLAY badge in the state panel | **C** | Studio, search-driven panel | Derived from event fields already used (`agentsec.testbed.mode`, `agentsec.security.profile`) and canonical-id membership; panel must keep "count ≠ completeness" |
| 7 | Dropdown of the learner's recent LIVE runs, replacing the paste | **C** | Studio dynamic dropdown | Needs a spike. Changes the validated token arrangement, so it needs re-validation. Do not start before §9.1 |
| 8 | Rename tab titles (ids and links unchanged) | **S** | Studio layout tabs | Titles only |
| 9 | Hide or collapse a panel on a condition | **N** | — | Documented in the builder: Studio has no supported mechanism |
| 10 | Reorder cell parts; demote SPL below the result | **S** | Studio layout | Pure positions and heights; keep `with_spl` single source |
| 11 | "SPL REFERENCE" fifth tab holding every printed query | **C** | Studio tab | Cleaner cells; costs one navigation hop. Printed text must stay identical to executed SPL (re-run the verbatim check) |
| 12 | "Copy SPL" button in Studio | **N** | — | No button or script is possible. Alternative: selectable code text, plus the native panel "Open in Search" icon |
| 13 | Real `<details>` collapse inside Studio markdown | **N** | — | Not verified to render; do not design around it |
| 14 | Prediction echoed inside Studio | **N** | — | Cross-origin. Studio shows a static "write down your hypothesis" prompt instead |
| 15 | Per-cell notes saved | **N** | — | No learner-note store (DOCUMENTED); keep "Not saved" |
| 16 | Wide left-to-right SVG in a Studio image panel | **S** | `splunk.image` + static asset | Build bump and static cache identity rewrite |
| 17 | Vertical reflow SVG in Studio | **N** | — | No viewport switching of an image |
| 18 | Vertical reflow in the web app | **S** | web app CSS / second SVG | — |
| 19 | Comparison card from this session's runs | **S** | web app (existing launch data) | Keeps "NOT MEASURED" for missing data, never "SAFE" |
| 20 | Studio Cell 5 transposed pair | **S** | Studio (already built) | KEEP |
| 21 | Auto-mark "INVESTIGATED" | **N** | — | Progress lives in the Splunk site's browser storage; neither Studio nor the web app can write it. Link to Your Path instead |
| 22 | Align Your Path wording with the 9-step vocabulary | **C** | Splunk Classic with JS | Any static change needs a build bump. Your Path is a hard guardrail: wording only, no behavior change |
| 23 | Same-tab navigation with a "Back to lab" link | **S** | web app link; Studio static link | — |
| 24 | Reduced-motion, focus styles, 44 px targets | **S** | web app CSS | Studio's native controls are not restyled |
| 25 | Framework Context placeholder | **S** (empty) | web app | Renders nothing in Phase 1 |
| 26 | Usable at 200% zoom | web app **S**; Studio **C** | — | Studio: the 132 px region (D11) is **unverified**. `collapseNavigation` already exists in the definition options (currently `False`); its effect is **unverified** |

Mapping by surface: **Dashboard Studio** (5, 6, 8, 10, 16 and the demoted SPL), **Classic/Simple XML** (22 only), **AgentSec web app** (1, 4, 18, 19, 23, 24), **shared navigation** (no change proposed; Home's nav stays), **native Splunk Search** (the advanced path; unchanged).

## 7. KEEP / IMPROVE / FUTURE

### KEEP (do not disturb)

- Cell 2 independent of `agentsec.control.decision`; the printed and executed SPL are one string.
- Two-question prediction; "UNKNOWN is an honest answer"; prediction never reaches the runtime.
- ALLOW is not green; DENY is not red; literal words always shown.
- Closed launch request (4 fields); launcher terminal state labelled "not a security verdict".
- REPLAY specimens, their ids, and the HEC init seeding.
- Studio Cell 5 transposed pair; the Workbench comparison data source.
- Your Path behavior, storage key and states.
- The ANSWER KEY warning banner (the honest gate, since Studio cannot lock).
- "Absent event = corroboration, not proof".

### IMPROVE (existing functionality and evidence only)

| ID | Change |
|---|---|
| I-1 | Make the INVESTIGATE intro mode-neutral so prose never contradicts the selected evidence (D8) |
| I-2 | Rename Evidence Source labels (D1); add the computed LIVE/REPLAY badge (D9) |
| I-3 | Deep-link hand-off with clipboard fallback; remove the `none` instruction from the primary path (D3) |
| I-4 | Add BASELINE and DEFEND steps to the web-app rail (D2, D4) |
| I-5 | One dominant "next step" bar after ATTACK and RETEST (D5) |
| I-6 | Move the launcher's decision/execution fact cards to COMPARE as a "Check your prediction" moment; keep the data and the `≠` pairing (D6) — **see decision O1** |
| I-7 | Notebook cells: result first, hypothesis prompt, observation prompt, next question, SPL last (D7, D13) |
| I-8 | Neutral ATTACK button; "UNSURE" wording (D12) |
| I-9 | Replace the MCP diagram with the grammar (D16) |
| I-10 | Darker DENY/ALLOW text tokens (D17) |
| I-11 | Same-tab navigation and a "Back to lab" link (D14) |
| I-12 | Rename Studio tab titles; label ANSWER KEY as spoilers (D10) |
| I-13 | Closing EXPLAIN card with a hand-off to Your Path (D15) |

### FUTURE (do not mix into Phase 1)

Live BASELINE launch · a defend toggle · server-side learner state (cross-surface rail, saved notes, auto-mark) · a prediction echo inside Studio · a dropdown of recent runs if it needs a new field or index · a Flask "evidence reader" with real collapsible SPL and Copy buttons (needs a server-side Splunk query path) · framework mapping content · rollout of the pattern to other labs · any LLM-oriented evidence panel (not applicable to this lab).

## 8. Implementation priority

**P0 — a learner cannot complete the flow without the instructor**

1. I-3 deep-link hand-off (removes the paste step and the `none<run-id>` hazard).
2. I-2 Evidence Source relabel + LIVE/REPLAY badge.
3. I-4 + I-5 rail with BASELINE and DEFEND, and one dominant next-step bar.
4. I-1 mode-neutral INVESTIGATE intro.

**P1 — significant comprehension gain**

5. I-7 notebook cell restructure; SPL demoted.
6. I-9 left-to-right MCP diagram (wide, plus a narrow SVG for the web app).
7. I-6 move launcher facts to COMPARE as "Check your prediction"; Defend and Explain cards (I-13).
8. I-8, I-10, I-11, I-12.

**P2 — polish**

9. Narrow-screen reflow, reduced motion, focus audit, 44 px targets.
10. Verified 200% zoom pass on Studio, and the `collapseNavigation` spike.
11. Optional SPL REFERENCE tab; optional recent-runs dropdown spike.
12. Figma file, from the mockup.

Each P0/P1 item that touches Studio content or static assets re-opens the **visible-SPL == executed-SPL** check and the REPLAY/LIVE state checks, and needs the build bump where `appserver/static/` changes. Tests that must exist before release: the deep-link URL is well formed; the Workbench still posts only the four allowed fields; no `agentsec.llm`/`gen_ai` name appears in the lab; Cell 2's printed query contains no `agentsec.control.decision`; the diagram SVGs contain no green/red fills; and a browser pass proves the field is filled by the link and the panels populate.

## 9. Findings that change earlier assumptions

### 9.1 A URL deep link into Studio works (contradicts a recorded decision)

The Phase 1 remediation note says "No URL token handoff … appending `?live_run_id=…` would be silently ignored", and `src/agentsec/search_handoff.py` carries `studio_token_binding: "NOT SUPPORTED / DO NOT BUILD"`.

I tested both forms on the deployed dashboard with the fresh ATTACK run (`?tab=layout_investigate`):

| URL parameter | run.id occurrences in the rendered notebook text |
|---|---|
| `form.live_run_id=12f0269f-…` | **18** (panels populated for that run) |
| `live_run_id=12f0269f-…` (no `form.` prefix) | **0** (ignored) |
| `form.live_run_id=ea25befa-…` (RETEST) | **18** |

**MEASURED.** The earlier note was right about the unprefixed form and, I infer, never tried the `form.` prefix. An earlier candidate's Workbench hand-off used `form.run_id=…` (DOCUMENTED in `docs/reviews/AGENTSEC_PHASE1_NOTEBOOK_BROWSER_REVALIDATION.md`), so there is precedent; the current source under `src/` contains no `form.*` link. Classified **SUPPORTED WITH CONSTRAINTS** (§6 row 4): it was observed on this deployment and browser only, I did not find it stated in the Splunk documentation I searched, and Splunk could change it. Keep the clipboard path as a fallback and add a regression test. The `studio_token_binding` flag should be reconciled when this is implemented.

### 9.2 Smaller corrections

- The INVESTIGATE intro prose is wrong whenever Baseline is selected (D8).
- The existing DENY text colour fails 4.5:1 (D17, CALCULATED).
- The 200% zoom region of 132 px (D11) means the learner's *primary* experience should live in the web app, which the design already does for steps 1–4 and 6–9.

## 10. Decisions the owner should make

| ID | Decision | Recommendation |
|---|---|---|
| O1 | Withhold the launcher's decision/execution cards until COMPARE (stronger prediction loop), or keep showing them after ATTACK (consistent with the validated FactCards)? | Withhold until the learner has opened INVESTIGATE or presses "Reveal launcher summary". The evidence still exists in Splunk and is never hidden from an advanced learner |
| O2 | Make BASELINE a soft gate (recommended, skippable) or a hard gate before ATTACK? | Soft gate. A hard gate punishes a returning learner and the baseline is REPLAY, so skipping loses nothing the system depends on |
| O3 | Ship the optional SPL REFERENCE tab? | Not in P0/P1. Re-evaluate after the demoted-SPL cells are seen by a real learner |
| O4 | Spike the recent-runs dropdown? | After §9.1 ships. It changes the validated token design |

## 11. Success test

| The learner can say | Where the design answers it |
|---|---|
| "I know where I am." | Step header + rail + world chip on every screen |
| "I know what I just did." | "ATTACK experiment complete" + LIVE badge |
| "I know what I'm looking at." | LIVE/REPLAY badge + evidence-source label |
| "I know what to do next." | One dominant next-step bar |
| "I understand why it matters." | "Why it matters" in each step and cell |
| "I can distinguish authorization from execution." | Two prediction questions; Cell 1 vs Cell 2; separate table rows |
| "I can distinguish LIVE from REPLAY." | Solid vs dashed badge, always visible |
| "I can explain what the evidence proves / does not prove." | "Supports" / "Does not prove" blocks; EXPLAIN card |

This is a design claim, not a measured result. Whether a first-time learner actually completes the flow without help is untested and needs a moderated walkthrough with someone who did not build it.

## 12. Reconciliation with the Figma v2 export

Input: `Design AgentSec Learning Platform_v2.zip`, a React/Vite prototype (`src/App.tsx` 500 lines, `src/index.css` 878 lines) with in-memory demo data. **OBSERVED:** I built it (`vite build`, succeeded) and screenshotted Your Path, AcmeBank, the MCP workshop and the Attack Workbench in Chrome at 1440 px. **DOCUMENTED:** I read the source for the attack result card, timeline, notebook and run loader. I did not run the interactive attack, notebook or narrow-viewport flows: an automated script for that was blocked, so those findings come from source only. A prototype is a design reference, not evidence. Every number in it is hard-coded.

### 12.1 Adopt

| Prototype idea | Why | Surface |
|---|---|---|
| "Implementation surface" chip (`AGENTSEC WEB`, `DASHBOARD STUDIO`) | Tells the learner they are changing tools. Fits the three-world model | Web app (SUPPORTED); Studio markdown (SUPPORTED) |
| "Authorization is not execution" lesson headline and the two-part prediction | Matches the PREDICT brief | Web app, SUPPORTED |
| "Prediction is browser-local, never in the request payload" disclosure | Preserves the closed launch contract | Web app, SUPPORTED |
| Decision card, `≠`, Execution card as separate facts | Already validated in the Workbench | Web app, SUPPORTED |
| Run ID as a copyable technical chip | Matches run.id progressive disclosure | Web app, SUPPORTED |
| "Advanced settings" disclosure with model / lab ID | Matches beginner → advanced disclosure | Web app, SUPPORTED |
| System Status that says reachability is not evidence | Matches the HEC-acceptance invariant | Web app, SUPPORTED |
| ALLOW in blue and DENY in amber (`#28598e`, amber), no green/red | Same principle as §4.1. Its exact text colours were not contrast-checked, so use the §4.1 tokens | Web app, SUPPORTED |

### 12.2 Adapt (right idea, wrong detail)

| Prototype | Problem | Adaptation |
|---|---|---|
| Eight-step stepper: Learn, Predict, Attack, Observe, Investigate, Retest, Compare, Explain | No BASELINE and no DEFEND. A learner would not learn when to run the baseline, which was the owner's original stumble | Use the 9-step rail in §2 |
| Two competing steppers on the Workbench (outer says step 3 Attack while the task bar says step 1 Predict) | Two "you are here" signals disagree | One rail, one task bar |
| Left sidebar with 14 items (Learn / Practice / Assess / Investigate) | Splunk has no shared sidebar. A cross-surface sidebar cannot be built (§6). Five items (Context Security, Agent Intent, Identity, Data & Memory, Blue Team) open the same single-lab page, and Mastery/Arena have no backing data | Keep the rail inside each surface. Use Splunk's own app nav |
| Notebook cell "Run Investigation" button revealing an output | Studio has no per-cell run button or reveal. Panels run when their search runs | Cells run on load. Reveal order is by position and demoted SPL (§6) |
| "In [n]" / "Out [n]" labels | Suggest a code notebook the product is not | Use the QUESTION → … → NEXT labels from §2 |
| "Load evidence by Run ID" as the notebook's primary control | Makes run.id the first thing the learner sees | Arrive with the run pre-filled (§9.1) and show the run.id as metadata |
| Text at 9–11 px (CSS has 58 declarations at 9 px, 40 at 10 px, 27 at 11 px: MEASURED by counting `index.css`) | Below the brief's 14 px floor | Tokens in §4.1 |
| "LIVE ENVIRONMENT" badge with a dot, shown in the top bar of every lab page | It is a static label, not a measured state. It says nothing about which evidence the learner is looking at (the prototype has no REPLAY state on those pages) | LIVE / REPLAY badge tied to the selected evidence (§4.2) |
| Concept diagram of 7 tiny boxes | Text too small | Diagram system (§5) |

### 12.3 Reject (conflicts with the real-evidence contract or Phase 1 scope)

| Prototype content | Conflict |
|---|---|
| Attack result "LLM calls: 4" and RETEST "LLM calls: 0" for LAB-MCP-001 | LAB-MCP-001 has **no LLM events**. This would be a fabricated metric |
| "Indexed evidence found · 3 events" and a timeline with fixed times and `splunk.indexed` | Hard-coded. The real ATTACK has seven events and a probe-based indexing state |
| Fixed run ids `5ff6c21f-…` and `09a4e621-…` | Fabricated. Real ids come from the launch response |
| Normal behavior: "uses `get_customer_transactions`" | The real baseline grants `lookup_policy` |
| Notebook outputs that are the same mini-card with only the label changed | Showing an answer without running a query. Violates "do not fake Splunk evidence" |
| "Launch RETEST" button inside the notebook | Studio cannot launch. RETEST launches from the Workbench |
| Labs for Denial-of-Wallet, Sensitive Disclosure and Multi-Agent with invented metrics ("28 LLM calls", "47.8s") | Out of scope, and the numbers are invented |
| Mastery percentages, Arena, "3 / 5 labs" tallies | No backing data. Arena and Mastery are FUTURE |
| Notebook footer "ATTACK investigation complete. RETEST creates a new Run ID." | Right sentence, wrong place. The Workbench owns that moment (§2 step 5) |

### 12.4 What the export does not change

None of the 26 rows in §6 changes classification. The export's own `CURSOR_SETUP.md` recommends the same split already adopted here: workshops and notebook in Dashboard Studio, Your Path in Classic, advanced search in native Search, AcmeBank and Workbench as web apps.

### 12.5 Practical consequence for the Figma file

If the owner builds the Figma file from this spec, start from the export's visual language (typography, teal accent, card layout) and replace the hard-coded content with the contract in §2 and the specimen ids in §0. Do not hand the prototype's data to an implementer as expected behaviour.

## What I should now be able to explain

1. Why the "Investigate specimen" dropdown selects evidence rather than launching an attack, and how the redesign makes that unmistakable.
2. Why BASELINE is a recorded REPLAY and not a live run in Phase 1, and what would have to change to make it live.
3. Why the progress rail is learning state, why it cannot sync between the web app and Studio, and what that implies for the design.
4. Why Cell 2 must not read `agentsec.control.decision`, and how the redesign keeps that visible.
5. What `form.live_run_id` does, why `live_run_id` alone does nothing, and why it is classified "supported with constraints".
6. Why Dashboard Studio SPL cannot be collapsed, and which supported alternatives were chosen.
7. How LIVE and REPLAY are told apart in Studio without a new telemetry field.
8. Why the ATTACK button stops being red, and why ALLOW and DENY are not green and red.
9. What the five EXPLAIN questions are, and which claims a learner may safely make from one ATTACK and one RETEST.
10. Which parts of this proposal are unproven: Figma, 200% zoom readability, and real-learner comprehension.
