# Phase 16D learner-journey validation

**Evidence class:** OBSERVED (product copy, nav, Attack Service HTML, Studio markdown) plus INFERRED walkthrough.  
**Not MEASURED:** a human stranger completing every LIVE launch in this phase.  
**Not LIVE Splunk:** this file does not claim fresh indexed runs.

Curriculum source: `learning/academy/curriculum.json` (16C map, 16D product).

---

## Intended journey (beginner)

1. **HOME START** — what AgentSec is; Start Learning → Direct Prompt Injection.
2. **ORIENT** — LLM, agent, tool, MCP, RAG, memory, goal, identity claim, trust boundary, control, PDP, telemetry, Splunk role / non-role.
3. **PATH** — L0–L5, LIVE vs REPLAY, competency stages, capstone after L1–L3 LIVE.
4. **SPLUNK** — bootcamp (index/sourcetype/quoted run.id/sequence/control.decision) + Path A/B + CHECK claims.
5. **LAB-PI-001** — predict → Attack Service launch → copy run.id → Search Path A → hints → optional Path B → DEFEND → RETEST → COMPARE → PROVE → CONNECT to MCP-001.
6. **LAB-MCP-001** — REQUEST ≠ GRANT; then REPLAY 003/004 or continue to RAG.
7. **RAG then Memory** — context is data; WRITE vs RECALL remain distinct.
8. **Goal then Identity** — tool ≠ goal; claim ≠ authentication.
9. **Confused Deputy REPLAY** — do not collapse deputy into identity.
10. **Capstone** — reconstruct retrieve/write/recall; Path B is a review key; Debrief.

Menus match this order. Historical phase numbers are not the primary path.

---

## Beginner walkthrough (conceptual + OBSERVED UI)

Assume: basic cybersecurity, some Splunk vocabulary, almost no agentic AI, no repo knowledge.

| Step | Can they proceed without repo knowledge? | Friction |
|------|------------------------------------------|----------|
| Find Home | Yes — default nav view | Splunk login is platform chrome (documented limitation) |
| Know where to start | Yes — START LEARNING / Direct Prompt Injection | Must open ORIENT for glossary; progressive disclosure |
| Understand LIVE vs REPLAY | Yes — PATH labels; Attack Service is LIVE only | Nav titles do not suffix LIVE/REPLAY (intentional; Home carries the badge) |
| Predict before launch | Yes — Attack Service Predict before ATTACK + what attacker does not control | Learner must actually write the prediction; UI cannot force it |
| Get a run.id | Yes — existing LIVE launch + copy buttons | Evidence-ready wait remains |
| Investigate in Search | Yes — Open Splunk Search; index/sourcetype documented | Must type SPL; Studio tokens are not the fresh id |
| Path A then Path B | Yes — stacked notebook + disclosure | Path B is still on the same tab (Studio cannot hide it); disclosure is pedagogical |
| Defend / retest / compare / prove | Yes — existing 14E–16B contracts | Unchanged experimental reasoning |
| Next lab | Yes — CONNECT + Attack Service NEXT LAB | After MCP-001, next curriculum lab is REPLAY (no launcher). Honest, not a dead end: Search + Investigate specimen |
| Capstone without skipping | Yes — MISSION Before you start | Gate is messaging, not an access control |

**Defect if repository knowledge is required:** not OBSERVED for the normal path after 16D copy/nav changes. Splunk Web app install still requires an operator (`./scripts/lab-up.sh`). That is environment setup, not syllabus.

---

## Advanced walkthrough (SOC practitioner)

| Need | Support |
|------|---------|
| Skip elementary explanation | START primary action is the first lab; ORIENT/PATH are optional tabs |
| Reach labs quickly | Grouped nav, human titles |
| Path A without Path B | Path A is first; Path B labeled optional / review key |
| Open Search | Home + every LIVE/REPLAY workshop + Attack Service |
| Copy technical identifiers | run.id copy controls unchanged |
| Exact controls | DEFEND/PROVE still name CTRL-* and PDP vs OBSERVE |
| Reach capstone | Last nav group; not before Goal/Identity |

They are not trapped in beginner narration. They can ignore Home ORIENT.

---

## Remaining friction (not P0)

- Splunk Enterprise chrome and login are not AgentSec-designed.
- Path B cannot be physically gated in Studio 10.2 without unsupported JS.
- REPLAY labs still use HUNT tab name (workshop shell), not INVESTIGATE.
- 768px remains diagnostic.
- No progress persistence (P3, correctly not built).
