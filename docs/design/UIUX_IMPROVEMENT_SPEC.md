# UI/UX improvement specification (planning only)

**Status:** proposal for a later release. **Nothing in this document is implemented in v1.3.0 RC1**, and no application code changes with it. It exists so the redesign is scoped, testable and reviewed before anyone builds it.

## 1. Why
Today the product is two interfaces that look and read differently:
- the **Academy** (React, served at `/learn`): Home, Curriculum, Loan Desk mission, MCP and other labs, EVAL Center, Risk Center, Governance Center, Security Assurance;
- the **classic Attack UI** (server-rendered Jinja at `/`, `/labs/*`, `/academy/*`, `/attack/*`, and the AcmeBank pages), which an expert still uses to launch and retest attacks. Behind the HTTPS gateway the classic pages are **not routed** (known v1.3.0 limitation); a dedicated route such as `/attack-service/` is a separate gateway investigation.

Observed problems (from the RC1 journeys and screenshots, not from opinion):
1. **Verbosity.** Stage pages repeat a fixed block (what you are doing, why it matters, what to do, evidence to inspect, what you will learn) around every step, and lab pages restate the same boundaries several times. Learners scroll past text to reach the one action that matters.
2. **Inconsistent chrome.** The Attack UI, the classic Academy, AcmeBank and the React Academy differ in layout, density, button language and status wording, although they share tokens.
3. **Workflow is implicit.** Loan Desk has seven stages with locks, but other labs and the assurance centers do not show where the learner is, what is next and what is blocked, or why.
4. **Evidence is secondary.** Evidence state (LIVE, RECORDED, REPLAYED, SIMULATED, NOT VERIFIED) is a small badge; the first thing a learner sees is explanation, not what was measured.

## 2. Goals and non-goals
Goals: a professional, consistent interface across all applications; less text per screen; an obvious workflow; evidence first; accessibility to WCAG 2.2 AA; usable on a phone and on a wide desktop.
Non-goals: new product features, new labs, changes to attack execution, authorization, telemetry, gateway routing, Splunk integration or evidence semantics; dark mode; a new framework or a Splunk UI React dependency; changes to AcmeBank's bank branding (it is a simulated third-party product, not AgentSec chrome).

## 3. Design principles
1. **Evidence first.** Every result view opens with the evidence card: state, provenance (who produced it, when, with what), and what it does and does not prove. Explanation follows and is collapsible.
2. **One primary action per screen.** Secondary actions are visually quieter; destructive or state-changing actions say what they will do and name the run they affect.
3. **Say it once.** A boundary or definition appears where it is needed, once, and is linked elsewhere (a glossary pattern, not repetition). Target: at most 120 words of prose above the first action on any stage page, with the rest behind "Details".
4. **State is visible.** Loading, empty, degraded, unavailable and not-verified are designed states with plain wording, never a blank area or a green badge that means only "reachable".
5. **Honest wording over reassurance.** Keep the existing rule that a badge never claims more than was measured (see `tests/test_badge_semantics.py`).

## 4. Scope by application
| Application | Direction |
|---|---|
| **Attack UI (classic)** | Professional redesign as an operator console: lab list with filter and state, a launch panel (specimen, mode, expected control), a live run timeline, and an evidence/compare drawer; remove duplicated prose; share the Academy shell (top bar, sidebar, breadcrumbs). It stays a separate surface for experts; any gateway exposure is a separate reviewed route. |
| **Academy home and curriculum** | Progress-led home (continue, next, blocked), compact curriculum map; remove repeated mission pitch. |
| **Loan Desk mission** | Keep the seven stages and locks; replace the five-block guide with a one-line goal, the action, and a "why this matters" disclosure; keep prediction before attack. |
| **EVAL Center** | One results table pattern with filters and an evidence column; comparison view shares the Loan Desk compare component; export is one clear step. |
| **Risk Center** | Register first, method second; show what is source-backed versus analyst judgment inline; shorter forms. |
| **Governance Center** | Framework relationships as a matrix with evidence links; no marketing language; one export. |
| **Security Assurance** | The assurance steps use the same stepper and evidence card as the mission. |
| **AcmeBank** | Unchanged branding; only accessibility and responsive fixes. |

## 5. Workflow navigation
A shared **workflow bar** (stepper) for any multi-step page: current step, completed steps, locked steps with the reason ("Lock your prediction first"), and a single "Next" action. Breadcrumbs name the product area and the lab. In gateway mode the bar and sidebar only link to routes the gateway serves (the `AGENTSEC_GATEWAY_MODE` rule introduced in RC1 stays).

## 6. Evidence-first presentation
A single **EvidenceCard** component for every result:
- state chip with the existing non-colour cues (LIVE ●, RECORDED ▣, REPLAYED ↻, SIMULATED ◇, NOT VERIFIED △);
- provenance line (run id, specimen, profile, time, source: runtime, Splunk, recorded pack);
- "proves / does not prove" pair, one sentence each;
- link to the raw record and to the Splunk search (hidden in gateway mode when Splunk Web is not published).
LIVE is reserved for measured live data; explanation and teaching labels use the neutral info style.

## 7. Splunk-aligned design tokens
Reuse the existing `--sp-*` palette block (`src/agentsec/static/tokens.css`, duplicated verbatim in `academy-ui/src/splunk-tokens.css`, kept identical by `tests/test_splunk_tokens.py`) and the `--as-*` Figma contract (`docs/design/figma_v2_tokens.json`). No new hard-coded colours: fills, borders and chart colours come from the palette; text colours come from the accessible `--sp-ink-*` tokens that pass 4.5:1 on their tints. Typography and spacing scales are defined once and used by all applications. Charts use the categorical series in order and never rely on colour alone.

## 8. Accessibility (WCAG 2.2 AA)
Contrast 4.5:1 text and 3:1 UI components; visible focus on every control; full keyboard operation including the workflow bar and drawers; one `h1` per page and a logical heading order; landmarks and a skip link; names for every control; status changes announced (`role="status"`); no information by colour alone; reduced-motion respected; target size at least 24 px; zoom to 400 % and text spacing overrides without loss. Keep the strict axe baseline (zero allowed serious or critical findings) and extend it to the redesigned pages.

## 9. Responsive layouts
Breakpoints at 390, 768, 1280 and 1920 px. Mobile: single column, the sidebar becomes a drawer (as today), tables become labelled cards, the workflow bar collapses to "Step n of m" with a menu, the primary action is reachable without scrolling past prose. Wide desktop: a bounded reading width for prose and a two-pane layout (action, evidence) for investigation pages. No horizontal page scroll at any width (already asserted at 390 px in the RC1 journey).

## 10. Constraints the redesign must keep
- Attack execution, authorization, telemetry, evidence semantics and the gateway allowlist do not change.
- Existing tests are the safety net and must keep passing without being weakened: axe baseline, control inventory (named links, no dead links), badge semantics, token identity and contrast tests, the gateway browser tests (launch from the real control on 443 and a non-standard port, crawl of every link).
- Generated bundle only through `scripts/build_academy_ui.sh` (frozen lockfile), committed, reproducible.
- Verbosity cuts are content changes: each needs a reviewer who confirms no safety boundary or evidence caveat was lost.

## 11. Acceptance criteria
1. Every page in section 4 uses the shared shell, stepper (where multi-step) and EvidenceCard.
2. Words above the first action are at most 120 on any stage or lab page; measured by a script over the rendered pages.
3. axe: zero serious or critical findings on every page at 390 and 1280 px; manual keyboard and screen-reader pass on the mission, EVAL and Risk flows.
4. No horizontal scroll at 390, 768, 1280, 1920 px; screenshots reviewed for each.
5. Token tests pass; no literal hex colours outside the token files (except AcmeBank's own theme).
6. Browser tests through the gateway pass with no dead links.
7. A learner test (five people unfamiliar with the product) completes Loan Desk without help in the planned 45 minutes; time-to-first-action and error counts recorded.

## 12. Plan (phases, each separately reviewed)
1. Inventory and measurement: word counts per page, a screenshot atlas, the keyboard map, a content-audit table (keep, merge, move to Details, delete).
2. Components: EvidenceCard, Stepper, PageHeader, DataTable, EmptyState in the React app with tests; token audit.
3. Academy pages (Home, Loan Desk, EVAL, Risk, Governance, Assurance) one at a time, behind the existing routes.
4. Attack UI redesign (after a decision on how, and whether, the classic console is exposed behind the gateway).
5. Accessibility and responsive verification, learner test, release candidate.

## 13. Risks
Content cuts can remove a safety or evidence caveat (mitigate with a per-page review); visual changes can break the strict test baselines (change tests only through a recorded, reviewed update, never to match a regression); redesign scope creep (every item here is presentation; behaviour changes need their own proposal).
