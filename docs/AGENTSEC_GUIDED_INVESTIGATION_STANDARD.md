# AgentSec guided investigation standard

**Status:** Phase 14A DESIGN ONLY. **Not implemented.** No new SPL. No new Studio views.  
**Reuse:** existing validated `Q-*` hunts (`docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md`).  
**Do not start Phase 14B from this file.**

---

## Purpose

Each evidence question has two paths. Path A is the default. Path B is a teaching cell, not a spoiler wall.

```text
QUESTION
  → (Path A) hints + OPEN SPLUNK SEARCH
  → (Path B) QUERY → OUTPUT → EXPLANATION → NEXT QUESTION
```

Do not ship only precomputed tables.

---

## Cell contract (solution SPL)

| Slot | Required |
|------|----------|
| QUESTION | Security question in learner language |
| WHY WE ASK | Which property / plane |
| HINTS | Progressive; see difficulty modes |
| SPL | Read-only; reuse `Q-*` with `__RUN_ID__` |
| EXPECTED OUTPUT | What rows/fields should look like for this specimen |
| WHAT IT MEANS | Interpretation |
| WHAT IT DOES NOT PROVE | Limitations; empty ≠ SAFE |
| NEXT INVESTIGATION | Next question or DETECT/DEFEND |

Queries must remain read-only. No `delete`, `update`, `outputlookup` unless a future lab is separately reviewed.

Do not duplicate hunt files solely for UI. Bind `__RUN_ID__` as today’s workshops already do.

---

## Path A — INVESTIGATE YOURSELF

Show:

- SECURITY QUESTION  
  Example: “What retrieved context entered the agent?”
- Progressive hints (Beginner): index → sourcetype → useful fields → `run.id` → `event.name` → control id
- Conceptual action: **OPEN SPLUNK SEARCH**

Do **not** immediately expose full SPL.

Native mechanism: markdown link or visualization interaction **Link to custom search** / **Open in Search** (Splunk Dashboard Studio). Pass the `run.id` token into the query string. Custom JavaScript is not required for this path.

---

## Path B — SHOW SOLUTION

Reveal the cell contract. Output visualization may be a Studio table bound to the same `Q-*` hunt (prebuilt datasource). That table is the **answer key**, labeled as such, not “what just happened live” unless the bound id is the LIVE id.

Use a **solution-visibility token** (dropdown: Hidden / Show solution) plus Studio conditional visibility if the installed Splunk version supports hide/show panels. That is a native input, not custom JS.

Do not use GFM tables inside `splunk.markdown` (AgentSec local Studio renders pipes as text). Use labeled lists.

---

## Progressive difficulty (contracts only)

| Mode | Learner sees | Hidden |
|------|----------------|--------|
| BEGINNER | Question + full hint ladder + solution control | Full SPL until Show solution |
| INTERMEDIATE | Question + limited field hints (`event.name`, control id) | Index/sourcetype may be omitted; SPL hidden |
| ADVANCED | Security question only | Hints and SPL |
| CHALLENGE | Question; **no run.id** | Learner discovers the execution from a time window / other evidence |

Do not implement mode switching in 14A. Default published workshops today behave closest to REPLAY tables always visible (not CHALLENGE).

CHALLENGE must not require a new detector. Discovery is Search, not DET-*.

---

## DETECT tab remains detection engineering

CONTEXT ≠ HUNT ≠ DETECTION ≠ INCIDENT.

A lab may still end **DETECTION ANALYZED — NO NEW DETECTOR**. Do not add DET-* to complete a guided cell. DET-MCP-001 stays scoped to execution after tool DENY.

---

## CONNECT (after PROVE)

Every workshop should eventually close with:

1. AgentSec invariant(s) actually exercised
2. Adjacent labs (not a dump of all LAB ids)
3. Trust boundary in architecture terms
4. OWASP Agentic/LLM **only where already verified in that lab’s docs**
5. MITRE ATLAS **only where already verified** (e.g. PI ATK-002 `AML.T0054`)
6. NIST **only if the lab already cited it**
7. Production design considerations (what would change outside the range)
8. What remains unproven

Framework mapping follows the demonstrated property. It does not drive the lab.

CONNECT is copy + links, not a new detector and not a new Studio app.

---

## ATTACK tab before execution

Before launch (LIVE) or before inspecting the ATTACK specimen (REPLAY), the learner must see:

| Field | Intent |
|-------|--------|
| ATTACK OBJECTIVE | What we are trying to make the agent do |
| WHY THIS MATTERS | Property / invariant |
| WHAT WILL CHANGE | The experimental variable |
| WHAT WILL NOT CHANGE | SAME inputs |
| WHAT I EXPECT TO SEE | Prediction prompt |
| WHAT SECURITY PROPERTY IS BEING TESTED | One sentence |

The learner should predict before clicking Attack Service or opening ATTACK evidence.
