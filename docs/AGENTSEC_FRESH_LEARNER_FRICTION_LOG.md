# AgentSec fresh-learner friction log (Phase 17B)

Learner-facing only. Operator setup is out of scope unless it appears inside a lesson.

Severity: **P0** learner cannot continue or learns an incorrect security concept. **P1** major confusion or hidden prerequisite. **P2** friction but proceed. **P3** polish.

| ID | PERSONA | SURFACE | LEARNING STAGE | PROBLEM | WHY IT MATTERS | SEVERITY | PROPOSED FIX | IMPLEMENTED? | VALIDATION RESULT |
|----|---------|---------|----------------|---------|----------------|----------|--------------|--------------|-------------------|
| F-17B-001 | A/B/C | Goal ATTACK | ATTACK | Launch without WHY/PREDICT; first lines were overlay ALLOW and handler 1 | Why-before-click failed on an advanced distinction | P0 | PI-style WHY / attacker vs server / PREDICT then launch | YES | OBSERVED pass17b Goal ATTACK |
| F-17B-002 | C | Capstone ATTACK | ATTACK | Predict cards lived on MISSION, not ATTACK | Capstone felt like another click-to-launch lab | P0 | WHY/PREDICT on ATTACK tab | YES | OBSERVED pass17b Capstone ATTACK |
| F-17B-003 | A/B | REPLAY LEARN | LEARN | Headers said LIVE EVIDENCE / Phase 5C–9D LIVE while HUNT said REPLAY | Taught the wrong evidence class | P0 | REPLAY SPECIMEN + historical specimens | YES | MEASURED rebuilt XML; HUNT still REPLAY workshop |
| F-17B-004 | A/B | Attack Service + PI empty hunt | HUNT | Open Search always available; empty table readable as DENY | HTTP 200 / empty table ≠ prevention | P0 | Wait for EVIDENCE READY; empty ≠ DENY | YES | OBSERVED pass17b Attack Service |
| F-17B-005 | A | Memory ATTACK | ATTACK | CTA labeled LAB-MEMORY-001; authz/exec-on-recall not restated at the button | Two-run model easy to hunt the WRITE id | P1 | Launch ATTACK (LIVE); hunt RECALL run.id | YES | OBSERVED pass17b Memory ATTACK |
| F-17B-006 | C | Capstone PROVE | PROVE | No NEXT after Capstone | Dead end before Mastery Check | P1 | NEXT Mastery Check, not a certificate | YES | OBSERVED in PROVE body; MEDIUM below-fold |
| F-17B-007 | C | MCP DEFEND | DEFEND | `src/agentsec/mcp/authorize.py` in learner copy | Repository knowledge | P1 | “the tool PDP” | YES | MCP-001/003/004 |
| F-17B-008 | C | PI COMPARE / PROVE | COMPARE | pytest and artifacts/<run-id>/ as learner next steps | Operator path inside the lesson | P1 | Drop pytest; local evidence pack wording | YES | PI COMPARE/PROVE |
| F-17B-009 | C | Goal/Memory PROVE | PROVE | Phase 15D / “Phase 15D not started” | Build history, not curriculum | P1 | Later-lab wording | YES | Goal/Memory PROVE |
| F-17B-010 | B | REPLAY Path B | HUNT | Bound tables without YOU SHOULD SEE / MEANS / DOES NOT MEAN | Path B revealed SPL shape, not interpretation | P1 | Four-line interpret card | YES | REPLAY HUNT banners |
| F-17B-011 | A | Home ORIENT | ORIENT | overlay / fingerprint / source_run_id unexplained until late labs | Hidden vocabulary | P1 | ORIENT definitions | YES | OBSERVED pass17b ORIENT |
| F-17B-012 | C | Home START | START | No skip for people who already know agents | Forced beginner prose | P1 | Skip ORIENT; still launch → Search | YES | OBSERVED pass17b Home START |
| F-17B-013 | A | RAG/Memory/Identity LEARN | CONNECT | Related labs listed as LAB-PI-001 · MCP-001/… | Internal IDs | P1 | Human titles | YES | three LEARN ladders |
| F-17B-014 | A | Mastery FOUNDATIONAL | MASTERY | NONE-evidence cards still said Open Splunk Search | False prerequisite | P1 | You do not need Search | YES | OBSERVED pass17b FOUNDATIONAL |
| F-17B-015 | A | Attack Service last launcher | CONNECT | “Capstone is the last LIVE launcher” with no Mastery | Dead end | P1 | Keep phrase; add Mastery Check | YES | attack.html |
| F-17B-016 | B | REPLAY HUNT | HUNT | export.json filesystem path if empty | Operator troubleshooting in Path A | P1 | Empty ≠ DENY; specimen may be absent | YES | MCP-003/004 HUNT |
| F-17B-017 | A | Several PROVE tabs | PROVE | knowledge-check.md filesystem path | Repository knowledge | P1 | Answer from evidence on this tab | YES | LIVE+REPLAY PROVE |
| F-17B-018 | B | REPLAY DETECT/COMPARE | DETECT | Remaining Phase 5C/6C/7C labels on some DETECT copy | Historical phase numbers | P2 | Backlog: strip remaining phase numbers | NO | backlog |
| F-17B-019 | C | Studio 10.2 Path B | HUNT | Path B cannot be hidden | Advanced skip still sees answer key | P2 | Disclosed; not a 17B architecture change | NO | accepted Studio limit |
| F-17B-020 | A | Tall PROVE cards | PROVE | Ownership lines below first screen at 1440 | Scroll required | P3 | Keep 16D density | NO | backlog |

P0/P1 in this table were copy-only. No schema, PDP, detector, or launcher-authority change. Playwright pass17b defects array was empty.
