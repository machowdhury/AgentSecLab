# Figma v2 → AgentSec production mapping

Phase 1 Gate B artifact. This document is the production design contract for
translating **Design AgentSec Learning Platform v2** into the real AgentSec
architecture. No Phase 1 production implementation begins before this document
is complete.

| | |
|---|---|
| SOURCE A | AgentSecLab repository at `c6370e048e5cf8f12a1301c7ddd3736c81af8ee7` (branch `develop`) |
| SOURCE B | `Design AgentSec Learning Platform_v2.zip` — React/Vite prototype, `src/App.tsx` (500 lines), `src/index.css` (878 lines) |
| Conflict priority | REAL EVIDENCE CONTRACT > SECURITY SEMANTICS > SUPPORTED PLATFORM ARCHITECTURE > EXISTING FUNCTIONAL CONTRACT > FIGMA UX > PIXEL FIDELITY |

SOURCE B states its own status in `CURSOR_SETUP.md`: *"Its interactions currently
use in-memory demonstration data; it is not yet connected to the Attack Service,
Splunk REST APIs, HEC, OTEL, or persistent learner-progress storage."* Every
value rendered by the prototype is therefore a demonstration value until proven
otherwise against SOURCE A.

---

## 1. Authoritative curriculum count

Section 6 of the Phase 1 brief records conflicting observed reporting of 31, 32
and 33 workshop items. All three numbers are real, they count different things,
and the differences are legitimate.

| Count | What it counts | Derived from |
|---|---|---|
| **31** | **Authoritative curriculum entries** — 19 level labs + 12 checkpoints | `learning/academy/curriculum.json` |
| **32** | **Your Path visible workshops** — the 31 above plus `ws_agentsec_mastery` | `agentsec_learner_path.js` `CATALOG` |
| 33 | Navigable workshop views — the 32 above plus `ws_agentsec_arena` | `nav/default.xml` |
| 34 | All `ws_*` views — the 33 above plus `ws_agentsec_home` | `data/ui/views/ws_*.xml` |
| 36 | All views — the 34 above plus `learner_path` and `open_attack` | `data/ui/views/*.xml` |
| 36 | Nav entries — 35 app views plus Splunk core `search` | `nav/default.xml` |

Mode split, consistent across both authoritative sources:

| | LIVE | REPLAY | Total |
|---|---|---|---|
| Curriculum level labs | 7 | 12 | 19 |
| Curriculum checkpoints | 0 | 12 | 12 |
| **Curriculum total** | **7** | **24** | **31** |
| Your Path `CATALOG` | 7 | 25 | 32 |

The single Your Path delta is `ws_agentsec_mastery` (REPLAY, L10), injected by
`scripts/apply_guided_learning.py:workshop_rows()` lines 179–188. Mastery Check
is an assessment surface, not a curriculum lab or checkpoint, so its absence
from `curriculum.json` is correct and its presence on Your Path is correct.

**Static / reasoning workshops:** 21 of the 32 Your Path entries carry no run-id
token and therefore render the orientation band only, with no evidence table.
The 11 remaining Your Path entries plus `ws_lab_scanner_runtime_evidence`,
`ws_lab_mcp_005`, `ws_lab_mcp_006` and `ws_lab_mcp_catalog` make up the 13 views
that carry `viz_guide_events` and `viz_guide_summary`.

**Is this a defect?** No. Counts already derive from authoritative data rather
than duplicated constants:

- `CATALOG` is spliced into the JS by `write_path()` from `workshop_rows()`.
- `workshop_rows()` reads `curriculum.json`.
- The Your Path tally renders `CATALOG.length`, not a literal.
- The guide shell's `step N of {total}` uses `len(rows)`, not a literal.

No change to the curriculum is required or permitted in Phase 1. The one
honest gap is that the prototype's `curriculumStats.total` of 11 is a
demonstration number with no relationship to any of the above.

---

## 2. Prototype-only data — must never become production evidence

Everything in this table is a hard-coded literal in `src/App.tsx`. None of it
may be promoted into a production surface.

| Prototype value | `App.tsx` | Production reality in SOURCE A |
|---|---|---|
| `workshops` object: 4 labs | 262 | Authoritative catalog is 31 curriculum entries / 32 Your Path entries. 3 of the prototype's 4 labs are Phase 2 and out of scope. |
| `pathLevels`: 3 levels, 11 labs | 270 | 11 levels, 19 labs + 12 checkpoints. |
| `curriculumStats.total` = 11 | 276 | 31 / 32 per §1. |
| `domains`: 8 domains with `3 / 5 labs` style counts | 83 | No domain-rollup data source exists. Counts are invented. |
| Run ID `5ff6c21f-90e2-4d8b-97aa` | 383, 447 | Real run IDs are UUIDv4 minted by `RunContext.mint` (`events.py:112`). |
| Run ID `09a4e621-c4a8-482d` | 383 | Same. |
| `attackMetrics` `["LLM calls","4"]` | 262 | **LAB-MCP-001 emits no `agentsec.llm.*` event at all.** See §3. |
| `retestMetrics` `["LLM calls","0"]` | 262 | Same — the field does not exist in telemetry. |
| `evidence` array rows | 395 | Invented event names and control IDs. See §3. |
| Timeline `14:32:08` … `Evidence indexed` | 391 | `splunk.index` is not an AgentSec event name. |
| `Indexed evidence found · 3 events` | 388 | Real ATTACK run emits 7 events. |
| `services` health array | 487 | No health data source exists in the Splunk app. |
| `Interest rate 3.20%`, balances, transactions | 207, 232 | AcmeBank has no accounts or transactions domain. See §5. |
| `Total foundation time 46 min`, `5 lessons` | 184 | No foundations surface exists. |
| Mastery `rows` `[["Prompt Security",4,5], …]` | 482 | Mastery Check has no data sources; it is 16 markdown blocks. |
| Arena 6 cards incl. 3 Phase 2 scenarios | 478 | Arena is 7 Attack Service deep links. |

---

## 3. Evidence contract conflicts — the highest-priority corrections

The prototype's SPL and evidence tables use field names that **do not exist**.
Any SPL copied from the prototype returns zero rows. Real telemetry uses flat
dotted `agentsec.*` keys, enforced by `schemas/security_event.schema.json` with
`additionalProperties: false` against a closed 15-value `event.name` enum.

| Prototype field | Exists? | Real name |
|---|---|---|
| `run.id` | No | `agentsec.run.id` |
| `event.name` | **Yes** | `event.name` |
| `control.id` | No | `agentsec.control.id` |
| `decision` | No | `agentsec.control.decision` |
| `reason` | No | `agentsec.control.reason` |
| `attempted` | No | `agentsec.operation.attempted` |
| `executed` | No | `agentsec.operation.executed` |
| `terminal` | **No — not telemetry at all** | HTTP response body only. Nearest telemetry is `agentsec.outcome`. |
| `llm_call_count` | **No — not telemetry at all** | HTTP response body only. |
| `tool_call_count` | **No — does not exist anywhere** | Nearest is `handler_invoke_count` (HTTP body). |
| `duration_ms` | Not bare | `agentsec.duration_ms`, only on `*.completed` events |
| `agent.id` | No | `gen_ai.agent.id` |
| `identity`, `scope` | No | `agentsec.mcp.requested_scope` / `agentsec.mcp.allowed_scope` |

| Prototype literal | Real value |
|---|---|
| `control.id = mcp-authz-01` | `CTRL-MCP-001` |
| `control.id = transfer-tool` | Not a control. `lookup_policy` / `lookup_customer_tier` are tools. |
| `event.name = control.authorization` | `agentsec.control.decision` |
| `event.name = agent.tool.requested` | No equivalent |
| `event.name = tool.execution` | `agentsec.mcp.started` / `agentsec.mcp.completed` |
| `event.name = splunk.index` | No equivalent |
| `event.name = agentsec.request.created` | No equivalent. Real first event is `agentsec.run.started`. |
| `agent.llm.*`, `agent.tool.*` | `agentsec.llm.*`, `agentsec.mcp.*` |
| reason `fail-open` | `vulnerable_profile_fail_open:CTRL-MCP-001 known tool lookup_customer_tier is not in mcp_policy_agent allowed_tools; lab profile intentionally returns ALLOW (fail-open) so the handler executes` |
| reason `input_pattern_matched` | `tool_not_granted` |

### Observed LAB-MCP-001 event sequences

OBSERVED by executing the MCP pipeline in-process with `write_evidence=False`.

**ATTACK** — `LAB-MCP-001:ATTACK`, specimen `MCP-002`, profile `vulnerable`,
tool `lookup_customer_tier`, terminal `completed_allowed`, `handler_invoke_count=1`:

| seq | `event.name` |
|---|---|
| 1 | `agentsec.run.started` |
| 2 | `agentsec.hop.started` |
| 3 | `agentsec.control.decision` — ALLOW / `vulnerable_profile_fail_open:…` |
| 4 | `agentsec.mcp.started` |
| 5 | `agentsec.mcp.completed` |
| 6 | `agentsec.hop.completed` — `agentsec.outcome=hop_allowed` |
| 7 | `agentsec.run.completed` — `agentsec.outcome=completed_allowed` |

**RETEST** — identical payload, profile `defended`, terminal `completed_denied`,
`handler_invoke_count=0`:

| seq | `event.name` |
|---|---|
| 1 | `agentsec.run.started` |
| 2 | `agentsec.hop.started` |
| 3 | `agentsec.control.decision` — DENY / `tool_not_granted` |
| 4 | `agentsec.pipeline.stopped` — `agentsec.stop.reason=denied` |
| 5 | `agentsec.hop.completed` — `agentsec.outcome=hop_denied` |
| 6 | `agentsec.run.completed` — `agentsec.outcome=completed_denied` |

**Consequence for the Evidence Notebook.** The prototype's Question 3, "What did
the agent and model do?", reports 4 LLM calls. LAB-MCP-001 emits **no
`agentsec.llm.*` events on either run**. The MCP path is a direct tool
invocation and never calls the model. Question 3 must therefore be rewritten
against evidence that exists — requested versus allowed scope, and the
`agentsec.mcp.*` execution pair — or the honest answer is NOT OBSERVED.

**Consequence for DET-MCP-001.** The detector fires on DENY-then-start. The
LAB-MCP-001 ATTACK path is ALLOW-then-start, so the detector is correctly
**silent on the ATTACK run**. Silence is not SAFE. DET-MCP-001 stays disabled.

---

## 4. Surface map

Ten attributes per surface as required by §4 of the brief.

### 4.1 AgentSec Academy Home

| | |
|---|---|
| FIGMA SURFACE | `Home` — hero, novice start route, three-worlds grid, progress card, 8 domain cards, workflow strip, recent-investigations table |
| CURRENT AGENTSEC SURFACE | `ws_agentsec_home.xml` — Studio, 4 tabs, 13 markdown blocks + 1 image, no data sources |
| PRODUCTION OWNER | Splunk |
| IMPLEMENTATION TECHNOLOGY | Dashboard Studio `splunk.markdown` + `splunk.image` |
| SUPPORTED DIRECTLY? | Partly |
| ADAPTATION REQUIRED? | Yes. Markdown cannot produce the card grid, progress bars or domain tiles. Layout must be expressed as Studio grid blocks with one markdown block per card. |
| RUNTIME DATA SOURCE | None. Home is static orientation. |
| INTERACTION CONTRACT | Links only. `/app/agentsec/<view>` locale-relative. |
| ACCESSIBILITY | Markdown headings give the heading tree. Link text must be self-describing. |
| PHASE 1 ACTION | Add the **three-worlds** framing (AcmeBank → AgentSec → Splunk) as the primary orientation band. Do not add progress %, domain counts or a recent-investigations table — no data source exists and the prototype's numbers are invented. |

### 4.2 AI & Agent Foundations

| | |
|---|---|
| FIGMA SURFACE | `Fundamentals` — 5 lessons, agent orbit diagram, vocabulary panel, reflection textarea |
| CURRENT AGENTSEC SURFACE | **None.** Nearest is the Home `ORIENT` tab (`viz_orient_agent`, `viz_orient_context`). |
| PRODUCTION OWNER | Splunk |
| IMPLEMENTATION TECHNOLOGY | Studio markdown; diagram as a pre-rendered SVG `splunk.image` matching the existing `flows/flow-lab-*.svg` pattern |
| SUPPORTED DIRECTLY? | No |
| ADAPTATION REQUIRED? | Yes. Lesson selection state, the "Explore the answer" reveal and the free-text box all require JS that Studio does not support. |
| RUNTIME DATA SOURCE | None |
| INTERACTION CONTRACT | Tabs substitute for lesson selection. Reveal becomes a visible section. Reflection prompt becomes text, not an input. |
| ACCESSIBILITY | Tab bar is native Studio; no custom widgets. |
| PHASE 1 ACTION | **Not implemented.** Out of the golden path. Record as Phase 2 candidate. |

### 4.3 AcmeBank + AI Assistant + Behind the AI

| | |
|---|---|
| FIGMA SURFACE | `AcmeBank` — overview/accounts/transactions/assistant; chat thread; "See how the AI did this" → Behind-the-AI side panel with a 7-node flow and three expandable explainers |
| CURRENT AGENTSEC SURFACE | `src/agentsec/bank_app.py` + `templates/acmebank.html` — a single-shot **home-loan application form**. No chat. No accounts. No transactions. |
| PRODUCTION OWNER | AgentSec-controlled application (Flask, port 5000) |
| IMPLEMENTATION TECHNOLOGY | Jinja template + `agentsec.css` + `agentsec-ui.js` |
| SUPPORTED DIRECTLY? | Partly — see the conflict below |
| ADAPTATION REQUIRED? | **Yes, substantially.** |
| RUNTIME DATA SOURCE | `POST /process` → `run_id`, `terminal`, `llm_call_count`, `final_output`. `GET /api/v1/agents` → the 4 pipeline agents. |
| INTERACTION CONTRACT | Submit → run → show terminal state and run.id. Behind-the-AI must be labelled DOCUMENTED architecture, not measured runtime evidence, unless it renders fields from the actual response. |
| ACCESSIBILITY | Native form controls, `aria-live` status region already present. |
| PHASE 1 ACTION | See the conflict decision in §5. |

### 4.4 Your Learning Path

| | |
|---|---|
| FIGMA SURFACE | `PathPage` — summary strip, "Next up" card, 3 levels, lab rows with state pills, reset row |
| CURRENT AGENTSEC SURFACE | `learner_path.xml` (Classic 1.1, `script="agentsec_learner_path.js"`) + 516-line JS |
| PRODUCTION OWNER | Splunk Classic / Simple XML |
| IMPLEMENTATION TECHNOLOGY | Custom JS rendering into `#agentsec-progress` |
| SUPPORTED DIRECTLY? | Yes — this is the one surface where custom JS is supported |
| ADAPTATION REQUIRED? | No |
| RUNTIME DATA SOURCE | `localStorage["agentsec.learner.progress.v1"]`. Browser-local learning state, never evidence. |
| INTERACTION CONTRACT | States remain exactly `NOT STARTED` / `IN PROGRESS` / `INVESTIGATED`. `setState` throws on anything else. |
| ACCESSIBILITY | 4px left border per status so state is not colour-only; `aria-label` on the summary. |
| PHASE 1 ACTION | **HARD GUARDRAIL — DO NOT REGRESS.** Already live-verified: mounts, tally, 32 cards, next-workshop guidance, persistence, reset. Already matches the prototype's information architecture (hero → summary → next → cards → reset). **No change planned.** Any change to `appserver/static/` requires an `[install] build` bump and `scripts/static_cache_identity.py --write`. |

### 4.5 MCP Tool Authorization workshop

| | |
|---|---|
| FIGMA SURFACE | `Workshop` — lab header, AcmeBank business story band, 8-step stepper, Learn column, prediction aside |
| CURRENT AGENTSEC SURFACE | `ws_lab_mcp_001.xml` — Studio, 4 tabs, 30 `ds.search`, 2446 lines. Tab 4 is a single 22,580-pixel answer-key scroll. |
| PRODUCTION OWNER | Splunk Dashboard Studio |
| IMPLEMENTATION TECHNOLOGY | `splunk.markdown` + `splunk.table` + `splunk.image` |
| SUPPORTED DIRECTLY? | Partly |
| ADAPTATION REQUIRED? | Yes. No stepper component; no prediction radio inputs in Studio. |
| RUNTIME DATA SOURCE | `index=agentsec_telemetry sourcetype=otel:agentic:json` bound to `$run_id$` (REPLAY dropdown) or `$live_run_id$` (text input) |
| INTERACTION CONTRACT | Tabs + token inputs only. |
| ACCESSIBILITY | Native Studio tabs and inputs; evidence tables keep literal text alongside colour. |
| PHASE 1 ACTION | Add an explicit **BUSINESS STORY / NORMAL BEHAVIOR / SECURITY CONCEPT / CONTROL UNDER TEST / YOUR MISSION** separation to the MISSION tab, and render the 8-stage loop as a text stepper band. Prediction stays in the Attack Service, which has real radio inputs. |

### 4.6 Predict

| | |
|---|---|
| FIGMA SURFACE | Two radio fieldsets (ALLOW/DENY/ERROR/UNKNOWN and YES/NO/UNKNOWN), optional notes, "Record Prediction" gating launch |
| CURRENT AGENTSEC SURFACE | `attack.html:227-246` and `attack_mcp.html:71-89` — the same two fieldsets already exist |
| PRODUCTION OWNER | Attack Service |
| IMPLEMENTATION TECHNOLOGY | Native radio inputs + `sessionStorage` |
| SUPPORTED DIRECTLY? | Yes |
| ADAPTATION REQUIRED? | Minor |
| RUNTIME DATA SOURCE | `sessionStorage["agentsec.learner.session.v1"]` → `session.predictions[labId]` |
| INTERACTION CONTRACT | **Prediction must never reach the runtime.** Verified: the launch body is exactly `{lab_id, specimen_id, mode, execution}` and `parse_launch_body` rejects any other key with `unknown_fields` before `LaunchService` is reached. |
| ACCESSIBILITY | Native `fieldset`/`legend`/`radio`. |
| PHASE 1 ACTION | Keep the existing mechanism and server-side allowlist. Adopt the prototype's **"Record Prediction" gate before Launch** and the explicit privacy note. Prediction remains revisable before launch. |

### 4.7 Attack Workbench

| | |
|---|---|
| FIGMA SURFACE | `Workbench` — header with AcmeBank context, lab facts strip, stepper, task panel, 3-column predict/configure/observe, FactCard pair separated by a literal `≠`, Splunk evidence card, event timeline |
| CURRENT AGENTSEC SURFACE | `templates/attack_mcp.html` (425 lines) for LAB-MCP-001 |
| PRODUCTION OWNER | AgentSec Attack Service (Flask, port 5001) |
| IMPLEMENTATION TECHNOLOGY | Jinja + `agentsec-workbench.css` + `agentsec-ui.js` |
| SUPPORTED DIRECTLY? | Yes |
| ADAPTATION REQUIRED? | Yes — information hierarchy, not architecture |
| RUNTIME DATA SOURCE | `POST /api/launch` response; `GET /api/launches/<run_id>/evidence` |
| INTERACTION CONTRACT | Five independent state dimensions must not contradict one another: control decision, execution, launcher terminal, evidence state, learning state. |
| ACCESSIBILITY | `aria-live="polite"` on the status region; status text never colour-only. |
| PHASE 1 ACTION | Adopt the FactCard `decision ≠ execution` pairing. **Fix the known defect**: `attack.html:985-987` lets the evidence label overwrite the terminal label in the single `#ui-status` pill, so a completed ALLOW run reads `WAITING FOR INDEXING`. Split into separate persistent indicators. |

### 4.8 Attack Workbench status semantics

| Figma tone | AgentSec token | Applies to |
|---|---|---|
| informational blue | `--state-info` `#3568A8` on `#E8EEF5` | `ALLOW` |
| amber | `--state-warning` `#B7791F` on `#F6EBD8` | `DENY` |
| strong navy | `--chrome-navy` `#0B1F33`, white text | `executed=true` |
| muted gray | `#3D4654` on `#EEF1F4` | `executed=false` |

Already implemented exactly this way in the `columnFormat` / `matchValue` blocks
of `viz_guide_events` and `viz_guide_summary` across 13 views. **ALLOW is never
green.** Both columns render their literal text so status is never colour-only.
Phase 1 carries the same mapping into the Attack Service FactCards.

### 4.9 Evidence Notebook

| | |
|---|---|
| FIGMA SURFACE | `Investigation` — surface note, run loader by Run ID, AcmeBank business context block, 5 notebook cells each with `In [n]:` rail, question, visible SPL, "Run Investigation" button, output, learning note; footer "Open in Splunk Search" |
| CURRENT AGENTSEC SURFACE | `ws_lab_mcp_001.xml` tabs 2–3 — tables with no question framing and no per-question narrative |
| PRODUCTION OWNER | Splunk Dashboard Studio |
| IMPLEMENTATION TECHNOLOGY | `splunk.markdown` + `splunk.table` + `ds.search` bound to a token |
| SUPPORTED DIRECTLY? | Partly |
| ADAPTATION REQUIRED? | Yes — see the three constraints below |
| RUNTIME DATA SOURCE | `index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="$live_run_id$"` |
| INTERACTION CONTRACT | One `input.text` token drives every cell. Cells render on token change. |
| ACCESSIBILITY | Native inputs and tables; SPL in markdown code fences is selectable text. |
| PHASE 1 ACTION | Build the notebook as alternating markdown-question / table-output pairs on a dedicated tab, driven by the existing `live_run_id` token, with the real SPL visible in each markdown block. |

Three Studio constraints and their supported alternatives:

| DESIGN TARGET | PLATFORM CONSTRAINT | SUPPORTED ALTERNATIVE |
|---|---|---|
| Per-cell "Run Investigation" button that reveals output | Studio has no per-panel run control; searches run on load and on token change | A single "Load evidence" affordance — the `live_run_id` token. Panels show the shared `noDataMessage` until a run id is entered. Zero rows are explained, never hidden (`hideWhenNoData: false`). |
| `In [n]:` / `Out [n]:` notebook rail | No custom DOM in Studio | Markdown heading convention `## Question n` and a panel titled `Out [n]` |
| "Mark Investigated" button inside the notebook | Studio cannot write `localStorage`; only Classic views may carry `script=` | Link to Your Path, where the supported Mark-investigated control already lives. The guide shell already states "Opening this page does not mark the workshop investigated." |

### 4.10 The five MCP notebook questions

Rewritten against fields that exist. `$run_id$` stands for the bound token.

**Q1 — What did CTRL-MCP-001 decide?**

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="$run_id$" "event.name"=agentsec.control.decision
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| table _time control_id decision reason
```

Does not prove: execution. `agentsec.operation.executed` is hard-coded `false`
on every control-decision event by construction.

**Q2 — Did downstream execution occur?**

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="$run_id$" ("event.name"=agentsec.mcp.started OR "event.name"=agentsec.mcp.completed OR "event.name"=agentsec.mcp.failed)
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| eval outcome=mvindex(mvdedup('agentsec.operation.outcome'),0)
| table _time event_name executed outcome
```

`agentsec.mcp.started` means the handler **began**, including runs where it then
raised. Zero rows is not proof of non-execution on an incomplete copy; the
runtime `handler_invoke_count` is authoritative for this lab.

**Q3 — What did the agent request, and what was it granted?** *(replaces the
prototype's LLM-call question, which has no evidence basis in this lab)*

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="$run_id$" "event.name"=agentsec.control.decision
| eval agent_id=mvindex(mvdedup('gen_ai.agent.id'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| table agent_id tool requested allowed
```

**Q4 — Which evidence was indexed for this run?**

The existing `ds_guide_events` search, unchanged — 11 columns, `| sort sequence`.

**Q5 — What can you legitimately conclude?**

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="$run_id$"
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval executed=mvindex(mvdedup('agentsec.operation.executed'),0)
| stats values(decision) as decisions values(executed) as executed_values dc(_raw) as indexed_events by event_name
| sort event_name
```

### 4.11 ATTACK vs RETEST comparison

| | |
|---|---|
| FIGMA SURFACE | `Comparison` — two FactCard columns, principle banner, "Mark Investigated" |
| CURRENT AGENTSEC SURFACE | `ws_lab_mcp_001.xml` tab 3 — paired ATTACK/RETEST tables bound to hard-coded REPLAY UUIDs |
| PRODUCTION OWNER | Splunk Dashboard Studio, with the pair handoff built by the Attack Service |
| IMPLEMENTATION TECHNOLOGY | Two `input.text` tokens + paired tables; `POST /api/compare-handoff` already builds pair SPL and rejects `attack_run_id == retest_run_id` |
| SUPPORTED DIRECTLY? | Yes |
| ADAPTATION REQUIRED? | Add a second live token so a learner can compare two **fresh** runs, not only the canonical REPLAY pair. |
| RUNTIME DATA SOURCE | Two distinct `agentsec.run.id` values |
| INTERACTION CONTRACT | Distinct run IDs enforced server-side (`launch_service.py:708`). |
| ACCESSIBILITY | Tables, literal text, semantic colour. |
| PHASE 1 ACTION | Required comparison language is factual, not verdict language: "ATTACK: control ALLOW observed, downstream execution observed. RETEST: control DENY observed, downstream execution not observed." Never "ATTACK FAILED / RETEST SUCCEEDED". |

### 4.12 Arena

| | |
|---|---|
| FIGMA SURFACE | 6 scenario cards with difficulty/mode/duration |
| CURRENT AGENTSEC SURFACE | `ws_agentsec_arena.xml` — 1 markdown block, absolute layout, 7 Attack Service deep links |
| PRODUCTION OWNER | Splunk |
| IMPLEMENTATION TECHNOLOGY | Studio markdown; generated by `apply_guided_learning.py:write_arena()` |
| SUPPORTED DIRECTLY? | Partly — no card grid in markdown |
| ADAPTATION REQUIRED? | Yes if cards are wanted |
| RUNTIME DATA SOURCE | None |
| INTERACTION CONTRACT | Links only |
| ACCESSIBILITY | Markdown list |
| PHASE 1 ACTION | **No change.** 3 of the prototype's 6 Arena cards are Phase 2 labs. Changing Arena risks importing them. |

### 4.13 Domain Mastery

| | |
|---|---|
| FIGMA SURFACE | 6 domain cards with `done / total` and a progress bar |
| CURRENT AGENTSEC SURFACE | `ws_agentsec_mastery.xml` — 7 tabs, 16 markdown blocks, zero data sources |
| PRODUCTION OWNER | Splunk |
| IMPLEMENTATION TECHNOLOGY | Studio markdown |
| SUPPORTED DIRECTLY? | No |
| ADAPTATION REQUIRED? | Yes — per-domain progress would need browser-local progress, which Studio cannot read |
| RUNTIME DATA SOURCE | Would require `localStorage`, unavailable to Studio |
| INTERACTION CONTRACT | Read-only |
| ACCESSIBILITY | Tabs + markdown |
| PHASE 1 ACTION | **Not implemented.** The prototype's counts are invented and the real data lives in a store Studio cannot reach. Note that Mastery already uses a *fourth* status vocabulary (`NOT ATTEMPTED / IN PROGRESS / DEMONSTRATED / NEEDS REVIEW`); do not unify it in Phase 1. |

### 4.14 System Status

| | |
|---|---|
| FIGMA SURFACE | 5 service cards with Ready/Degraded, overview banner, "Run checks" |
| CURRENT AGENTSEC SURFACE | **None anywhere in the Splunk app.** Greenfield. |
| PRODUCTION OWNER | Splunk, for build identity. Attack Service `/health` already reports service reachability. |
| IMPLEMENTATION TECHNOLOGY | Studio markdown for static build identity |
| SUPPORTED DIRECTLY? | Build identity yes; live service health no |
| ADAPTATION REQUIRED? | Yes. Studio cannot poll a non-Splunk HTTP endpoint. |
| RUNTIME DATA SOURCE | `app.conf` (`version = 1.1.0`, `build = 4`), `splunk_app/static_cache_identity.json`, `SCHEMA_VERSION = 1.9.0`, `EXTERNAL_CONTRACT_VERSION = 1.0.0` |
| INTERACTION CONTRACT | Static text, regenerated at build time |
| ACCESSIBILITY | Markdown definition list |
| PHASE 1 ACTION | Implement a **bounded Build Information** panel only: product version, app build / static cache identity, schema, ExternalEvidence, curriculum count. Do **not** render live service health in Splunk. The required separation must be stated on the surface: SERVICE HEALTH ≠ EVIDENCE READINESS ≠ MODEL QUALITY. Attack Service HTTP 200 does not prove a lab works; HEC health does not prove indexing; a listed Ollama model does not prove generation quality; degraded KV Store does not mean the Academy is unavailable. |

---

## 5. The AcmeBank business-story conflict

This is the single largest Figma-versus-reality gap in Phase 1 and it needs an
explicit decision.

**DESIGN TARGET.** The prototype's golden path opens with a retail-banking chat:
the customer asks *"What were my last three transactions?"*, the assistant calls
`get_customer_transactions`, and the attack is an out-of-scope call to
`lookup_customer_tier`.

**PLATFORM CONSTRAINT.** None of the retail-banking layer exists.

- AcmeBank is a **home-loan application** form, not a retail bank. There are no
  accounts, no balances and no transactions anywhere in the runtime.
- There is **no chat interface**. `GET /` is a single textarea and a Submit
  button; `POST /process` runs four sequential LLM hops and returns once.
- **`get_customer_transactions` does not exist.** A repo-wide search returns zero
  matches. The MCP tool catalog is exactly two tools: `lookup_policy`
  (granted, scope `policy:read`) and `lookup_customer_tier` (known but
  **ungranted**, scope `customer:read`). That ungranted tool is precisely the
  LAB-MCP-001 specimen.
- The four loan-pipeline agents hold **no tools at all**. The MCP agent
  `acme-agent-mcp-001` is separate and is documented as "Not a loan-pipeline hop."

So the prototype's "normal behavior" sentence — *"The assistant uses
`get_customer_transactions` to return only the customer's permitted activity"* —
has no runtime backing. Implementing it literally would mean inventing a tool,
a data domain and a chat surface, and would change the MCP grant surface that
LAB-MCP-001 exists to teach.

**SUPPORTED ALTERNATIVE.** Keep the real runtime and tell its story truthfully.
The normal scenario becomes the granted call the lab already makes:

> A customer submits a home-loan application. The AcmeBank MCP policy agent is
> permitted to call `lookup_policy` with scope `policy:read` to retrieve lending
> guidance. That is the normal, authorized behavior. The learner then
> investigates what happens when the agent requests `lookup_customer_tier`,
> a known tool outside its granted scope.

This preserves the identical pedagogy — *authorization is not execution*, a
granted baseline versus an ungranted request — against evidence that genuinely
exists (`BASELINE` specimen `MCP-001` is exactly this granted call, already
implemented and already emitting a real ALLOW / `tool_granted` decision).

Per the conflict priority, REAL EVIDENCE CONTRACT and SECURITY SEMANTICS both
outrank FIGMA UX, so the supported alternative wins. The prototype's retail
framing is recorded here as a Phase 2 product question, not a Phase 1 defect.

---

## 6. Architecture decisions that are not negotiable

| Prototype assumption | Decision |
|---|---|
| Single React/Vite SPA replaces the AgentSec frontend | **Rejected.** §5 of the brief. The prototype is a UX reference. Three production surfaces remain: Splunk app, Attack Service, AcmeBank. |
| Persistent left sidebar with 5 nav groups | **Rejected.** Splunk owns app navigation. The existing 13-collection / 36-entry `nav/default.xml` stays. |
| `workshops` / `pathLevels` as the catalog | **Rejected.** `curriculum.json` remains authoritative. |
| Global CSS/JS injected into every page | **Rejected.** Studio supports no custom JS or CSS. Only Classic views may carry `script=`, and only `learner_path.xml` and `open_attack.xml` do. |
| Client-side routing between workshop and workbench | **Adapted.** Cross-surface navigation is locale-relative `/app/agentsec/...` inside Splunk and `learnerHref`-rewritten links out to the Attack Service. |
| `topbar` LIVE ENVIRONMENT pulse badge | **Adapted.** A pulse animation must respect `prefers-reduced-motion`; the prototype already does at `index.css:876`. |

### Visual system

The prototype's tokens are already an AgentSec palette. No migration is needed.

| Figma `index.css` | AgentSec `agentsec.css` | Match |
|---|---|---|
| `--navy #0b1f33` | `--chrome-navy #0B1F33` | identical |
| `--teal #007f86` | `--accent-teal #007F86` | identical |
| `--blue #3568a8` | `--state-info #3568A8` | identical |
| `--bg #f5f7fa` | `--bg-page #F6F8FB` | near |
| `--text #172536` | `--text-primary #17202A` | near |
| `--muted #5f6b76` | `--text-secondary #3D4654` | differs |
| `--line #dce3ea` | `--border #D9E0E7` | near |
| `--amber #946213` | `--state-warning #B7791F` | differs |

Phase 1 keeps the **AgentSec** values as authoritative, since they are already
encoded in the Studio `matchValue` formatting across 13 views and in the Your
Path injected stylesheet. Adopting the prototype's hex values would desynchronise
the Splunk tables from the web surfaces for no learner benefit.

Breakpoints to honour: 1180px, 820px, 620px, plus `prefers-reduced-motion`.
Splunk Studio grid is fixed at `width: 1440` with `display: auto-scale`, so the
responsive requirement applies to the Attack Service and AcmeBank only; Studio
behaviour at narrow widths is a platform limitation, not an AgentSec defect.

---

## 7. Phase 2 boundary

These appear in SOURCE B and must not be implemented, registered, or given
controls or telemetry in Phase 1.

| Prototype id | Code | Control in prototype | Phase 1 status |
|---|---|---|---|
| `wallet` | LAB-GOV-004 | CTRL-RUNTIME-004 | NOT IMPLEMENTED |
| `disclosure` | LAB-DATA-003 | CTRL-DATA-003 | NOT IMPLEMENTED |
| `multiagent` | LAB-A2A-005 | CTRL-A2A-005 | NOT IMPLEMENTED |

They also appear in the prototype's `pathLevels` (Level 2 and Level 3) and in 3
of the 6 Arena cards. Any change to Your Path, the curriculum or Arena must be
checked against this table.

---

## 8. Gate B checklist

| Requirement | Status |
|---|---|
| All primary Figma surfaces mapped | 14 of 14 — §4 |
| Production owner identified | Yes — §4 |
| Supported mechanism identified | Yes — §4, with alternatives in §4.9 and §5 |
| Prototype-only data identified | Yes — §2 and §3 |
| Unsupported assumptions identified | Yes — §6 |
| Authoritative curriculum count established | Yes — §1 |
| Phase 2 boundary recorded | Yes — §7 |
