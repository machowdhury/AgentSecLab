# AgentSec Splunk learning interaction matrix

**Status:** Phase 14A RESEARCH / CONTRACT. **No Studio implementation.**  
**Sources:** Splunk Dashboard Studio docs (help.splunk.com, inspected 2026-09-19), AgentSec UI/KO skills, live Pass-2 workshop behavior.  
**Do not invent capabilities.** Do not start Phase 14B from this file.

---

## Skills that informed this matrix

Repository:

| Skill / rule | Governs |
|--------------|---------|
| `.cursor/rules/33-splunk-agent-skills.mdc` | KO workflow; hunt ≠ detection; no SPL-first |
| `.cursor/skills/splunk-ko-review/SKILL.md` + `reference.md` | Official Splunk Agent Skills mapping |
| `.cursor/skills/spl-validate/SKILL.md` | SPL correctness before any new query |
| `.cursor/skills/dashboard-studio-review/SKILL.md` | Studio technical/teaching review |
| `.cursor/skills/ui-review/SKILL.md` | Learner-facing visual QA |
| `.cursor/skills/logic-proof/SKILL.md` | Evidence claims vs runtime |
| `.cursor/rules/32-ui-design-system.mdc` | Visual grammar; no GFM in `splunk.markdown` |
| `.cursor/skills/build-workshop/SKILL.md` | Workshop construction (later phases) |
| `.cursor/skills/learning-review/SKILL.md` | Teaching quality |

Official Splunk Agent Skills consulted as **read-only mapping** (not executed as KO changes):

| Official skill | Why it applies to 14A |
|----------------|------------------------|
| Splunk Product Question Navigator | Current Studio interaction behavior |
| Search and Dashboard Troubleshooter | Tokens, empty results, Open in Search |
| HEC Setup and Troubleshooting | HEC 200 ≠ searchable |
| Knowledge Object Governance | Reuse Q-*; do not duplicate hunts for UI |
| Dashboard, Report, and Alert Performance Advisor | No auto-refresh polling as a learning crutch |
| Alerting and Notable Workflows | Explicitly **out**: no ES notable to complete a lab |
| Custom Visualization Builder | Explicitly **out** unless native paths fail |

Not used: Cloud admin, indexer clustering, SAML, ES notables.

---

## Capability classes

| Class | Meaning |
|-------|---------|
| SUPPORTED DIRECTLY | Native Studio/Search; AgentSec already uses or can use without JS |
| SUPPORTED WITH LINK/DRILLDOWN | Native link to Search, URL, or Attack Service |
| SUPPORTED WITH PREBUILT DATASOURCE | `ds.search` bound to validated SPL + token |
| REQUIRES CUSTOM APP/JS | Do not build in 14B unless this matrix is revised with evidence |
| NOT SUPPORTED / DO NOT BUILD | Violates AgentSec boundaries or Splunk role |

---

## Desired interactions

| Interaction | Class | Honest mechanism | Do not |
|-------------|-------|------------------|--------|
| Open Search with `run.id` context | SUPPORTED WITH LINK/DRILLDOWN | Studio “Link to custom search” / Open in Search; or markdown URL to `/en-US/app/search/search?q=…` with token | POST from Studio; hide Open in Search |
| Display SPL | SUPPORTED DIRECTLY | `splunk.markdown` code (no GFM tables) | Assume markdown copy-button exists |
| Copyable SPL | SUPPORTED DIRECTLY | Learner selects markdown; OS copy | Custom clipboard JS |
| Solution reveal | SUPPORTED DIRECTLY | Dropdown token + conditional panel visibility (Studio hide/show); or a SOLUTION sub-tab | Custom accordion JS; always-on spoiler wall as the only path |
| Execute solution search | SUPPORTED WITH PREBUILT DATASOURCE | Bind existing `Q-*` with `__RUN_ID__` | New hunt files that clone Q-* |
| Display output | SUPPORTED DIRECTLY | `splunk.table` + standard empty-state sentence | Infer DENY from empty |
| Dynamic canonical `run.id` | SUPPORTED DIRECTLY | Investigate specimen dropdown (already shipped) | Shared dropdown+free-text token (Studio limitation already documented) |
| Dynamic **fresh LIVE** `run.id` in Studio | REQUIRES CUSTOM APP/JS **or** learner paste into Search | Prefer Search link from Attack Service JSON | Auto-write Studio tokens from Flask |
| Attack launch | SUPPORTED WITH LINK/DRILLDOWN | Link to Attack Service `:5001` | Studio HTTP POST; Splunk savedsearch that calls runtime |
| Poll evidence readiness | NOT SUPPORTED / DO NOT BUILD as the default | Learner re-runs Search; optional Studio refresh is not a completeness oracle | Auto-refresh loops; treat `$job.resultCount$` as SAFE |
| HEC health in the workshop | NOT SUPPORTED / DO NOT BUILD | `lab-ready.sh` / ops, not learner UI | Equate HEC 200 with EVIDENCE_READY |
| Set token from table click | SUPPORTED DIRECTLY | Studio table interactions / `$row.field.value$` | Use as authorization |
| Link Studio → Attack Service | SUPPORTED WITH LINK/DRILLDOWN | Custom URL; tokens escaped by default in modern Studio | iframe Attack Service (already rejected in IA) |
| Custom visualization / Jupyter widget | REQUIRES CUSTOM APP/JS | Out of scope | New viz framework to look like PortSwigger |
| Button that fires ATK-002 inside Studio | NOT SUPPORTED / DO NOT BUILD | Button input sets tokens / interactions, not AcmeBank POST | Studio as launcher |
| Auto-refresh until events appear | REQUIRES CUSTOM APP/JS plus capability (`auto_refresh_dashboards` on newer Splunk) | Do not depend on this for teaching | Silent polling |

---

## AgentSec-specific Studio limitations (OBSERVED)

- Two inputs cannot safely share one empty hunt token; custom `run.id` remains Search.
- `splunk.markdown` GFM tables rendered as pipe text on this lab’s Splunk — labeled lists remain mandatory.
- Combobox labels ellipsis; full UUID on evidence cards.
- Native tabs are not a custom stepper; LEARN→PROVE labels are enough.

---

## Search is the investigation workbench

Splunk Search remains the place the learner **types and thinks**. Studio is the syllabus and the answer key. Prefer:

1. Path A: Open Search
2. Path B: reveal SPL + bound table

Do not replace Search with more Studio datasources for every question.
