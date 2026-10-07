# AgentSec P1 — Final Learner Experience Design

Status: **DESIGN PROPOSAL ONLY.** No application code, tests, Splunk app, or deployment was changed for this document. Nothing here is implemented.
Scope: LAB-MCP-001 golden path. The security architecture (CTRL-MCP-001 as PDP, Splunk as evidence, schema 1.9.0, app 1.1.0) is unchanged.

Companion artifacts (all in this repo, static, script-free):

| Artifact | Path |
|---|---|
| Interactive frame viewer (open in a browser, `#f01`…`#f15`) | `docs/design/mockups/p1/p1-frames.html` |
| Rendered frames (1920, 1024; 960 = 200% zoom equivalent; 480 = 400% reflow) | `docs/design/mockups/p1/frames/` |
| Annotation-free renders for review | `docs/design/mockups/p1/frames/*-plain.png` |

Evidence labels used below: **OBSERVED** (I saw it in a browser or file), **MEASURED** (taken from real run artifacts), **CALCULATED**, **DOCUMENTED** (stated in repo docs), **PROPOSED** (design, not built), **UNVERIFIED** (needs a spike on Splunk 10.2).

---

## 0. What the mockups are and are not

* The values shown in frames are **real**: BASELINE specimen `163d11e2…` (MEASURED: ALLOW `tool_granted`, 7 events, `mcp.started`/`mcp.completed` present), ATTACK run `a850e8c3…` (MEASURED: ALLOW fail-open, started 1, completed 1, stopped 0, 0 LLM events), RETEST run `4d34746a…` (MEASURED: DENY `tool_not_granted`, started 0, stopped 1, 0 LLM events). Both runs share input fingerprint `sha256:431e7baa…`.
* The frames are **static HTML renders**. Splunk frames (6, 7, 8, REFERENCE) are an **emulation of Splunk chrome** drawn to show layout and hierarchy. They are not screenshots of Dashboard Studio and must not be read as proof that Studio can render them. Every Splunk frame carries a supportability tag in its annotation bar.
* A frame that says "outcome deliberately NOT shown" (frame 5) is a design rule, not missing data.
* Evidence that is shown to a learner after running the lab is their own run (LIVE). The BASELINE page uses a recorded specimen and is labelled **REPLAY**; it is never presented as a fresh measurement.

---

## 1. Diagnosis: why P0 was rejected (owner complaints mapped to causes)

| Owner complaint | Root cause in current design | P1 response |
|---|---|---|
| Unclear what to click for BASELINE | Baseline is one of several equal links; no dominant action | Step 1 is its own screen with one CTA: **Explore baseline →** |
| Unclear when ATTACK begins | PREDICT, ATTACK and service scope share one long page | PREDICT and ATTACK are separate screens; ATTACK is "Run the attack" with one button |
| Attack page far too long | Service scope, auth, tenancy, internet, allowlist, parameters, SPL, env vars, trust labels, taxonomy all open | Moved behind three closed disclosures (Understand the attack / Lab safety & boundaries / Technical details) |
| Too much safety info before the action | Boundary text is above the primary action | Boundary text is still available, never above the CTA |
| Workshop has too many equal stages | Ten journey names displayed as ten destinations | Five phases, eight steps; one "you are here" |
| Notebook exposes SPL before reasoning | SPL is the visible artifact of each cell | Cell order: Question → Why → Evidence → Interpretation → Supports → Does not prove → SPL link → Next. SPL lives on REFERENCE tab |
| Evidence selection vs experiment execution | Two inputs with equal weight, one called "Recorded example" | One **CURRENT EVIDENCE** banner states LIVE or REPLAY in words; selectors become secondary |
| Engineering harness, not academy | Tool-operation language (run.id, tokens, profile) leaks into the beginner path | The beginner path never mentions run.id, SPL, HEC, tokens, profile internals, or allowlist implementation |

The design principle: **one screen → one learning objective → one dominant next action.** Every frame answers WHERE AM I / WHAT DO I DO / WHAT DO I CLICK / WHY / WHAT NEXT; the annotation bar on each frame states those five answers (the five-second test).

---

## 2. Information architecture

### 2.1 Journey: five phases, eight steps

```
UNDERSTAND      TEST                INVESTIGATE        IMPROVE            PROVE
1 Baseline      2 Predict           4 Investigate      5 Defend           7 Compare
                3 Attack                               6 Retest           8 Explain
```

* Landing ("LEARN") is a **Start screen**, not a step. It tells the story and has one CTA.
* LEARN, OBSERVE and the other canonical lifecycle names remain in docs and Your Path. The learner sees **five phase names**, with the current phase highlighted and a single "Step N of 8" line.
* "OBSERVE" is folded into the ATTACK-complete screen and the notebook; it is not a separate destination.
* Rail state is conveyed by **words and glyphs** (`✓ done`, `▶ you are here`, plain = upcoming), not color alone.

### 2.2 Surfaces

| Surface | Owns | Does not own |
|---|---|---|
| AgentSec web app (Flask :5001) | Steps 1, 2, 3, 5, 6, 7, 8 and Start; prediction; Lab safety page; Technical details | Evidence reading with SPL |
| Dashboard Studio `ws_lab_mcp_001` | Step 4 (INVESTIGATE) notebook; REFERENCE (SPL, recorded examples, answer key) | Running experiments, prediction, wizard navigation |
| Native Splunk Search | "Open in Search" targets | Teaching flow |
| Shared Splunk navigation | Existing 12 curriculum groups (pinned by test) | Any per-lab step navigation |

Studio tabs become **START / INVESTIGATE / REFERENCE** (replacing the current multi-tab layout for the learner path; existing tabs remain reachable under REFERENCE in the first implementation slice to preserve validated work).

---

## 3. Frames

Each frame lists: surface, supportability, primary action, five-second test. Supportability key: **SUPPORTED**, **SUPPORTED WITH CONSTRAINTS**, **NOT SUPPORTED**. Renders: `docs/design/mockups/p1/frames/<NN-name>-<width>.png`.

| # | Frame | Surface | Support | Primary action | Learner can answer in 5 s |
|---|---|---|---|---|---|
| 1 | Workshop landing / LEARN | Web app | SUPPORTED | **Start: see normal behavior →** | Where: start of LAB-MCP-001. Do: read the question. Click: Start. Why: story and question. Next: Step 1. |
| 2a | BASELINE start | Web app | SUPPORTED | **Explore baseline →** | Step 1: understand normal. `lookup_policy` is granted. REPLAY only. |
| 2b | BASELINE evidence (after exploring) | Web app | SUPPORTED WITH CONSTRAINTS (recorded specimen must be packaged with the app as a static fixture) | **Continue: make your prediction →** | Granted tool → ALLOW → tool ran. Labelled REPLAY. |
| 3 | PREDICT | Web app | SUPPORTED | **Lock prediction & continue →** (disabled until both answered) | Two questions: what will the control do (ALLOW/DENY/ERROR/UNSURE); will the tool run (YES/NO/UNSURE). Nothing is revealed. |
| 4 | ATTACK ready | Web app | SUPPORTED | **Run ATTACK experiment →** | One button. No run.id worry. Three closed disclosures below. |
| 5 | ATTACK complete | Web app → Splunk deep link | SUPPORTED (validated `form.live_run_id` link) | **Investigate evidence →** | "ATTACK experiment complete. Evidence is ready." Two questions. No ALLOW/DENY/executed shown. |
| 6 | INVESTIGATE overview | Studio | SUPPORTED WITH CONSTRAINTS | Read Question 1 below | CURRENT EVIDENCE: LIVE · Your ATTACK experiment. Five questions listed. |
| 7 | Investigation cell 1 (before answering) | Studio | SUPPORTED WITH CONSTRAINTS (SPIKE-2) | Choose what the evidence suggests | Evidence row, then a choice. SPL is one link away, not on the page. |
| 8 | Investigation cell 2 (after answering) | Studio | SUPPORTED WITH CONSTRAINTS (SPIKE-2) | Read the check; go to Question 3 | Counts, the learner's choice, what it supports, what it does not prove. |
| 9 | DEFEND | Web app | SUPPORTED | **Retest the same attack →** | Same request, different server configuration. No "apply defense" button. |
| 10 | RETEST ready | Web app | SUPPORTED | **Run RETEST →** | Same request again, defended configuration. |
| 11 | RETEST complete | Web app → Splunk deep link | SUPPORTED | **Compare ATTACK and RETEST →** | Evidence ready; no safe/secure/fixed wording. |
| 12 | COMPARE | Web app (+ optional Splunk verification) | SUPPORTED | **Continue: explain what you found →** | Side-by-side ATTACK vs RETEST table, raw evidence last. |
| 13 | EXPLAIN | Web app | SUPPORTED (browser-local) | **Finish this lab →** | Five answers in own words; supported vs not-supported claims. |
| 14 | Advanced technical details | Web app + Splunk REFERENCE | SUPPORTED | none (reference) | run.id, fingerprint, SPL, raw JSON. Not needed to finish. |
| 15 | Lab safety & boundaries | Web app | SUPPORTED | Back to lab | Local teaching lab, scope, what it will not do. |

### 3.1 Behavior rules per frame (the ones owners asked for explicitly)

**Frame 2 — BASELINE.** Shows REPLAY only. There is no "LIVE baseline" button: AgentSec does not run a fresh baseline in this slice, and the screen says "a recorded example". Content: tool requested `lookup_policy` (granted), ALLOW with reason `tool_granted`, `mcp.started`, `mcp.completed`. The "Open this recorded example in Splunk (optional)" link is secondary.

**Frame 3 — PREDICT.** Two required questions, both answerable with "unsure". Selected state is thick border + the word "Selected" + radio mark, not color alone. The "Lock" CTA is visibly disabled with a text explanation. The learner's prediction stays in the browser tab (sessionStorage, as in P0). It is never revealed or graded on this screen.

**Frame 4 — ATTACK ready.** Title "Run the attack". One diagram (left→right): Loan assistant → CTRL-MCP-001 → "?" (what happens next is what you investigate). One button. A reminder chip shows the learner's own locked prediction. Everything else is behind the disclosures: service scope, authentication, tenancy, internet, allowlist, parameter restrictions, SPL, environment variables, trust labels, attacker taxonomy.

**Frame 5 — ATTACK complete.** Deliberately does not show ALLOW, DENY, "executed", `mcp.started` or `mcp.completed` outside the closed "Technical details" disclosure. It states "Evidence is ready", poses the two questions, and has one CTA that deep-links to INVESTIGATE using the already validated `?tab=layout_investigate&form.live_run_id=<run.id>`. run.id is metadata, never the navigation mechanism.

**Frame 6–8 — Notebook cells.** Cell order is fixed: **QUESTION → WHY IT MATTERS → EVIDENCE → WHAT DOES THIS SUGGEST (learner interpretation) → WHAT THIS EVIDENCE SUPPORTS → WHAT THIS DOES NOT PROVE → SPL link → NEXT.** Each cell shows a one-line "Reading: LIVE · your ATTACK experiment" kicker so the evidence source is never ambiguous. The cell-2 "supports" sentence is derived from the three counts by a deterministic rule, not a canned per-lab answer.

**Frame 9 — DEFEND.** An explanation, not a control. "Same: the request. Different: the server's configuration." A caution banner: "A configuration is a claim; RETEST measures whether it does what it says." No toggle.

**Frame 10–11 — RETEST.** Causal continuity: "Same request. Defended configuration." The completed screen never says SAFE, SECURE, FIXED or PREVENTED. It says "Evidence for the same request under the defended configuration is ready."

**Frame 12 — COMPARE.** Table columns ATTACK / RETEST; rows: requested tool, control decision, reason recorded, execution started, pipeline stopped, observed outcome. Each row is marked SAME or DIFFERENT in text. Decision chips use glyphs (▶ ALLOW, ■ DENY) and neutral fills. Raw evidence is last. "Observed outcome" is a deterministic rule over recorded fields and never claims prevention.

**Frame 13 — EXPLAIN.** The five questions: what happened; what evidence supports it; what changed; what the evidence does not prove; what can you safely claim. Below, "Supported by your two runs" and "Not supported by your two runs" ("The system is secure", "Every ungranted tool is blocked", "Splunk blocked the request") lists, generated from the recorded fields.

---

## 4. Evidence-source clarity (owner request #6)

* A **CURRENT EVIDENCE** banner is the first panel on INVESTIGATE: `LIVE · Your ATTACK experiment` or `REPLAY · Baseline example`. The words LIVE and REPLAY always appear in text. run.id appears only under Technical details.
* "Explore a recorded example" (Baseline / Attack / Retest) is a secondary selector with a title that cannot be mistaken for "run".
* **Constraint (DOCUMENTED in P0.1):** in Studio, the dropdown still displays "Baseline" while LIVE is read. P1 cannot remove the dropdown. Mitigations: a banner above it, a per-cell "Reading:" kicker, and renaming its title to "Explore a recorded example".
* SPIKE-2 asks whether inputs can move onto the canvas (beside the banner) in Studio 10.2.

---

## 5. Components

| Component | Spec | Used in |
|---|---|---|
| Phase rail | 5 segments, 6 px top rule, text label + sub-label, `✓`/`▶` glyphs, "Step N of 8" line | All web frames |
| Step card | White, 1 px border, 12 px radius, 28–32 px padding, kicker + h1 + lead + one CTA | 1–5, 9–13 |
| Primary CTA | Teal `#006C72` fill, white text, 19–20 px, 52 px min height, arrow glyph, one per screen | All |
| Locked CTA | Dashed border, grey text, always with an adjacent sentence saying why | 3 |
| Secondary link | Underlined text link, ↗ for external | 2b, 12 |
| Disclosure row | Native `<details>`, title + right-aligned summary, closed by default | 1, 2–5, 9–13 |
| Flow diagram | Left→right nodes with arrows; vertical reflow ≤900 px | 1, 4 |
| Prediction option | Card with radio, label, one-line explanation; selected = thick border + "Selected" word | 3 |
| Decision chip | Glyph + word, neutral fill (ALLOW ▶, DENY ■); fill does not imply good/bad | 2b, 7, 12 |
| Evidence table | Header row, 16 px text, row labels in bold | 2b, 7, 12 |
| Banner (CURRENT EVIDENCE) | 4 px left rule, kicker, h2, one detail line | 6 |
| Claims lists | "Supported" and "Not supported" two-column, text-labelled | 13 |
| Annotation bar | Review scaffolding only; not part of the product | Mockups |

## 6. Typography, spacing, CTA hierarchy

* **Type scale (PROPOSED, CSS px):** h1 40–44 / lead 20 / body 18 / table 16 / label 14 uppercase +0.06em / mono 16. **No text below 14 px.** (Figma v2 used 9–11 px; rejected.)
* **Spacing:** 8 px base; card padding 32; section gap 24; max reading width 1000 px content; line length ≤ 70 ch for leads.
* **CTA hierarchy:** (1) Primary teal (one per screen), (2) text link secondary, (3) disclosure rows. Never two filled buttons on one screen.
* **Color:** teal for progress and the primary action; navy for "you are here"; neutral chips for decisions. Caution amber only for "claims you cannot make" and the DEFEND caveat.

## 7. Diagrams

* Desktop: left→right, nodes sized to use the card width (frames 1, 4).
* ≤900 px: nodes stack vertically with a down arrow (frame 4 at 480).
* Diagrams are HTML/CSS in the web app (no image dependency). In Studio, diagrams are not attempted in this slice (SVG image panels would need a static-asset build bump and `scripts/static_cache_identity.py --write`, DOCUMENTED).

## 8. Accessibility

* **Color is never the only signal:** rail uses words+glyphs; selected prediction uses border+word; decisions use glyph+word; ALLOW is not styled "good" and DENY is not styled "safe".
* **Shared DENY contrast debt (DOCUMENTED, not fixed here):** `WARNING="#B7791F"` in `src/agentsec/workshop_flows.py` is used as a text color on light backgrounds and fails 4.5:1. P1 proposes darkening the text-use token (≈ `#8A5A00`, to be CALCULATED and tested in the implementation slice) and keeping the original as a fill/border only. The mockup frames use the darker text color.
* **Focus and keyboard:** native `<details>`, `<input type=radio>`, `<a>`, `<button>` give a correct tab order; visible 3 px focus ring on every interactive element; the mockup uses a native `disabled` button with an adjacent text explanation; the implementation should evaluate `aria-disabled` so the CTA stays focusable (PROPOSED, not tested). The 3 px focus ring is in the mockup CSS but was not exercised with a keyboard.
* **Zoom/reflow (mockup renderer, OBSERVED):** all 16 frames rendered at 1920 and 1024 with no horizontal overflow. Representative web frames (1, 3, 4, 5, 12, 13) were rendered at 960 (≈200% on a 1920 window) and 480 (≈400%) with no page-level overflow; the compare table restacks into ATTACK / RETEST labelled rows at ≤560 px. Frames 2a, 2b, 9, 10, 11, 14, 15 were not rendered at 960/480; they use the same card, rail and table components.
* **Studio at 200% / 400%:** the Studio scroll region measured 132 CSS px at 200% in P0.1 (OBSERVED) and the nav wraps to 3 rows; P1 cannot change either (shared nav, platform). Studio frames 6–8 at 480 show horizontal overflow in the mockup emulation (205 px / 159 px): **NOT TESTED in real Studio, platform-dependent**; do not claim 400% reflow for Studio.
* Navigation height at 1024: the nav wraps; the proposal keeps the existing 12 groups (pinned by test) and does not add a second nav.

## 9. Splunk implementation map

| Proposal | Surface | Support | Notes / fallback |
|---|---|---|---|
| Wizard steps, prediction, CTAs, rail | Web app | SUPPORTED | Extends `attack_mcp.html` flow and sessionStorage |
| Disclosures for scope/safety/technical | Web app | SUPPORTED | Native `<details>` |
| Deep link to INVESTIGATE | Web app → Studio | SUPPORTED | `form.live_run_id`; already validated |
| Tabs START / INVESTIGATE / REFERENCE | Studio | SUPPORTED | `layout.tabs` |
| CURRENT EVIDENCE banner | Studio table | SUPPORTED (shipped in P0.1) | Search-driven |
| Cell order Question→…→Next | Studio markdown + tables | SUPPORTED | Order is panel order |
| Collapse / hide SPL in a cell | Studio | **NOT SUPPORTED** | No conditional hide. Closest: move SPL to REFERENCE and link; keep "visible SPL == executed SPL" there |
| Learner chooses an answer, feedback appears | Studio input + token-gated panel | SUPPORTED WITH CONSTRAINTS | Needs inputs on canvas (SPIKE-2); fallback: "write it down" prompt then reveal panel via second input |
| Radio input type | Studio | UNVERIFIED (SPIKE-1) | Fallback: dropdown (as in frames) |
| Image-panel alt text | Studio | UNVERIFIED (SPIKE-3) | Fallback: markdown text rail |
| Click-through image button, tokens in markdown links | Studio | UNVERIFIED (SPIKE-4) | Fallback: markdown links |
| Phase rail as images | Studio | NOT SUPPORTED in this slice | Markdown text rail |
| Cross-surface global progress navigation | Shared nav | **NOT SUPPORTED** | Nav is shared and pinned |
| Studio JS/CSS injection, Splunk Core patches | — | **NOT SUPPORTED** (prohibited) | — |
| Fictitious Figma content | — | **REJECTED** | See section 11 |

## 10. Contract changes the implementation will need (DOCUMENTED current pins)

P0/P0.1 tests currently pin: the ten-name journey order, control title ≤24 chars, tab and panel order on LAB-MCP-001, "Service scope" text on the attack page, CURRENT EVIDENCE first panel, notebook cell structure (question/why/SPL/result/observation/boundary), shared nav group list. Files: `tests/splunk/test_learner_ux_p0.py`, `test_p0_1_learner_evidence.py`, `test_lab_mcp_001_dashboard.py`, `test_agentsec_ui_shell.py`, `test_investigation_notebook.py`. P1 implementation must update these deliberately as **CONTRACT CHANGE** edits with reasons, not delete them.

## 11. Figma v2: adopted vs rejected

**Adopted:** whitespace and hierarchy, card layout, phase progress, single strong CTA, prediction option cards, storytelling headline, reduced density, separating business / security / evidence.

**Rejected as runtime content:** "LLM calls = 4" and any LLM telemetry (LAB-MCP-001 has zero LLM events); invented run ids and event counts; `get_customer_transactions`; canned notebook answers; Phase 2 labs; fictional controls; fake buttons (including "apply defense"); cross-surface global nav; 9–11 px text.

## 12. Proposed implementation slicing (not started)

1. **Slice A (web app only, lowest risk):** split `attack_mcp.html` into Start/Baseline/Predict/Attack/Defend/Retest/Compare/Explain; add three disclosures; move safety text to the disclosures and a dedicated Lab safety & boundaries page (frame 15; route to be decided); add ATTACK-complete screen without outcome. Tests: new web-app flow tests; update pinned text tests.
2. **Slice B (Studio):** reorder notebook cells; move SPL to REFERENCE; update banner and kickers. Tests: notebook structure, VISIBLE SPL == EXECUTED SPL.
3. **Slice C (spikes):** SPIKE-1…4 on the live Splunk 10.2 instance before committing to input-driven feedback.
4. **Slice D:** accessibility token fix in `workshop_flows.py` plus contrast tests.
5. **Slice E:** browser re-qualification at 1920 / 1024 / 200% with real evidence.

## 13. Owner decisions needed

* **D-1 Baseline location.** Inline in the web app as a packaged recorded specimen (frames assume this) versus opening a Studio REPLAY view. Inline is simpler and avoids a Splunk hop on step 1.
* **D-2 Interaction fallback.** If SPIKE-2 fails, accept "choose from a dropdown above the cell" versus "reveal by next-question link".
* **D-3 Studio tab set.** Replace current tabs immediately or keep them under REFERENCE for one release.
* **D-4 DENY color.** Approve darker text token (design) before the contrast fix is implemented.

## 14. Honest limits

* No real Studio rendering of frames 6–8 has been done. Those frames are an emulation.
* No usability test with a real learner was performed; the five-second tests are my own design checks (INFERRED), not measured user results.
* The 200% / 400% renders are browser viewport equivalents of the web frames, not real OS zoom on a deployed instance.
* SPIKE-1…4 are unverified. Nothing in this document claims Studio supports them.
* No Splunk query was run for this design; all numeric values come from existing artifacts or P0.1 reports.

---

## What I should now be able to explain

1. Why separating PREDICT from ATTACK reduces cognitive load, and why the prediction is never graded on-screen.
2. Why the ATTACK-complete screen deliberately hides ALLOW/DENY/execution status, and where the learner reads it instead.
3. The difference between LIVE and REPLAY evidence, and how the CURRENT EVIDENCE banner removes ambiguity.
4. Why ALLOW is not "execution", DENY is not "secure", and how COMPARE avoids those claims.
5. Which proposed interactions are SUPPORTED, SUPPORTED WITH CONSTRAINTS, NOT SUPPORTED, or UNVERIFIED in Splunk Dashboard Studio, and what each fallback is.
6. Why SPL moves to a REFERENCE tab instead of being collapsed inside each cell.
7. Which Figma v2 elements were rejected and why (fictional telemetry, LLM events, fake buttons).
8. Why CTRL-MCP-001, not Splunk, is the policy decision point.
