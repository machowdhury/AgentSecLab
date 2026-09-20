# AgentSec lab execution modes

**Status:** Phase 14A DESIGN ONLY. **Not implemented** as a Studio control.  
**Do not start Phase 14B from this file.**

A workshop may support more than one mode. Labels must be visible in text, not color alone.

---

## LIVE

Learner (or instructor) generates a **new** `run.id` through the runtime.

- `execution.mode=LIVE`
- `telemetry.fidelity=OBSERVED` when export actually happened
- Evidence readiness follows `WAITING_FOR_EVIDENCE` → `EVIDENCE_READY`
- Never implied by “the dashboard has tables”

**Do not claim LIVE** unless an actual launch path exists for that specimen (Attack Service, AcmeBank, or documented `POST /mcp/invoke` procedure).

---

## REPLAY

Canonical previously generated evidence. Investigate specimen dropdown binds validated run.ids at build time.

- This is the current default for published workshops
- Full UUID remains on evidence cards
- Must not be captioned as a newly executed experiment
- `splunk.verified` is a property of **that copy**, not of a new launch

REPLAY is honest teaching when the indexed copy is complete. Empty REPLAY tables mean the copy is not on this volume — not DENY.

---

## GUIDED

Hints, solution SPL, expected result, and interpretation are available (Path B).

GUIDED is orthogonal to LIVE vs REPLAY:

| Combination | Meaning |
|-------------|---------|
| REPLAY + GUIDED | Canonical ids + hidden-then-revealed solution (first 14C candidate) |
| LIVE + GUIDED | Fresh launch + same investigation questions |
| REPLAY without GUIDED | Current workshops: tables visible, SPL secondary |
| LIVE without GUIDED | Launch + Search only (ADVANCED / CHALLENGE) |

SIMULATED `makeresults` fixtures (DET-MCP-001 positive control) are **not** LIVE and **not** REPLAY of a runtime pack. Keep the SIMULATED label.

---

## What must stay SAME vs DIFFERENT

On ATTACK vs RETEST:

| SAME (typical) | DIFFERENT (typical) |
|----------------|---------------------|
| Task / payload / tool / resource as the lab defines | Profile or the specific control under test |
| Instruction / retrieved document / memory blob when that is the experiment | Goal-integrity / MCP grant / input control decision |

Do not call RETEST successful because Splunk has no row. Runtime handler counts remain authoritative where the lab already established that.

---

## Mode selector (designed, not built)

If Studio later exposes a mode, use words:

- Investigate canonical REPLAY specimens
- Launch LIVE (opens Attack Service)
- Guided investigation (Beginner / Intermediate / Advanced / Challenge)

Do not use a single dropdown that silently switches LIVE tables onto REPLAY ids.
