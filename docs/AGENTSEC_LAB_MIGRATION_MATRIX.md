# AgentSec lab migration matrix

**Status:** DESIGN (Phase 15A). No labs are migrated by this document.  
**Supersedes** `docs/AGENTSEC_CROSS_WORKSHOP_READINESS_MATRIX.md` for planning (that file is a 14A snapshot).

Learning value is **educational payoff**, not a contest score. Dependency readiness is whether the 14E loop can attach without new PDPs or schema.

Path A = Search workbench hunts. Path B = solution SPL / investigations.json. Both are learning UX, not access control.

---

## Lab experience standard (migration checklist)

Every migrated lab must eventually answer, **only with supported facts**:

1. What am I learning?  
2. Why should I care?  
3. What system am I attacking?  
4. Where is the trust boundary?  
5. What security property should hold?  
6. What am I about to change?  
7. What is not changing?  
8. What do I predict?  
9. How do I launch the experiment?  
10. What `run.id` did I get?  
11. What should I look for in Splunk?  
12. Can I find it myself?  
13. What hints are available?  
14. What is the solution SPL?  
15. What output should I expect?  
16. What does that output mean?  
17. What does it not prove?  
18. Where is the actual defense?  
19. How do I retest?  
20. Is RETEST using equivalent adversarial input?  
21. What changed?  
22. What did not change?  
23. What can I prove?  
24. What can I not prove?  
25. How does this connect to the next concept?

Do not fake LIVE, RETEST, or detectors to fill the list.

---

## Matrix

| Lab | Learning value | Dependency readiness | LIVE ATTACK | LIVE RETEST | Path A | Path B | Existing SPL | Detection | Studio | Attack Service work | Recommended order |
|-----|----------------|----------------------|-------------|-------------|--------|--------|--------------|-----------|--------|---------------------|-------------------|
| LAB-PI-001 | HIGH | READY (14D/14E done) | YES | YES | YES | YES | Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-EXECUTED, Q-LLM-AFTER-DENY | NONE JUSTIFIED | existing (14E loop) | none | Reference — do not remigrate |
| LAB-MCP-001 | HIGH | READY (14E done) | YES | YES | YES | YES | Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-AFTER-DENY, Q-MCP-SCOPE, Q-MCP-PARAMS, Q-MCP-RESULT, Q-MCP-RESULT-TRUST | DET-MCP-001 disabled | existing (14E loop) | none | Reference — do not remigrate |
| LAB-MCP-003 | HIGH | READY | LATER (operator LIVE exists) | LATER | PARTIAL (Q-MCP-* exist; not 14E Path A UX) | NO | Q-MCP-* family | DET-MCP-001 reuse | redesign to 14E GRID | small | **Wave 1 first** |
| LAB-MCP-004 | HIGH | READY (after 003 in the lesson) | LATER | LATER | PARTIAL | NO | Q-MCP-* + Q-MCP-RESOURCE-AUTHZ | DET-MCP-001 reuse | redesign | small | **Wave 1 second** |
| LAB-MCP-005 | HIGH | PARTIAL (two-hop; INV-002) | LATER | LATER | PARTIAL | NO | Q-MCP-* + Q-MCP-RESULT-AUTHORITY | NONE JUSTIFIED | redesign | moderate | Wave 2 |
| LAB-MCP-CATALOG | HIGH | PARTIAL (INV-002 + catalog fixtures) | LATER | LATER | PARTIAL | NO | Q-MCP-* + Q-MCP-CATALOG-AUTHORITY | NONE JUSTIFIED (candidate later) | redesign | moderate | Wave 2 |
| LAB-SCANNER-RUNTIME-EVIDENCE | MEDIUM | PARTIAL (evidence plane) | NO (not a launcher) | NO | PARTIAL | NO | Q-SCANNER-WHO, Q-SCANNER-ARTIFACT, Q-SCANNER-FINDINGS, Q-SCANNER-RUNTIME-CORRELATION + Q-MCP | NONE JUSTIFIED | redesign as REPLAY/DESIGN | none / N/A | Wave 2 after catalog |
| LAB-RAG-CONTEXT | HIGH | PARTIAL (`/rag/retrieve` + follow-on MCP) | LATER | LATER | PARTIAL | NO | Q-RAG-CONTEXT-AUTHORITY + Q-MCP-* | NONE JUSTIFIED | redesign | moderate | Wave 3 |
| LAB-MEMORY-001 | HIGH | PARTIAL (two run.ids) | LATER | LATER | PARTIAL | NO | Q-MEMORY-CONTEXT-AUTHORITY + Q-MCP-* | NONE JUSTIFIED | redesign | moderate | Wave 3 after RAG |
| LAB-MCP-006 | HIGH | PARTIAL (two-agent pipeline) | LATER | LATER | PARTIAL | NO | Q-MCP-* + Q-MCP-DELEGATION | NONE JUSTIFIED | redesign | moderate | Wave 4 |
| LAB-AGENT-DELEGATION-001 | HIGH (concept) / MEDIUM (path) | BLOCKED for 14E loop (no Studio) | LATER | LATER | PARTIAL (hunt exists) | NO | Q-AGENT-DELEGATION-AUTHORITY + Q-MCP-* | NONE JUSTIFIED | **missing** | architectural | Wave 4 after 006 + new view |
| LAB-AGENT-GOAL-INTEGRITY-001 | HIGH | PARTIAL (needs tool-grant fluency) | LATER | LATER | PARTIAL | NO | Q-GOAL-INTEGRITY-AUTHORITY + Q-MCP-* | NONE JUSTIFIED | redesign | moderate | Wave 5 |
| Home | HIGH (orientation) | READY as directory | N/A | N/A | N/A | N/A | N/A | N/A | existing; IA later | N/A | Evolve in a dedicated IA phase, not Wave 1 |

---

## Migration waves (design only)

### Wave 1 — Scope then resource (LAB-MCP-003, LAB-MCP-004)

**Why now:** Completes REQUEST≠GRANT on the same CTRL-MCP-001 and `POST /mcp/invoke` that 14E already launched. Highest curriculum increment per unit of Attack Service work.  
**Prerequisites:** 14E PASS; MCP-001 LEARN→PROVE as the template.  
**Reuse:** ExperimentContext, launch catalog pattern, Path A/B chrome, Q-MCP-*, DET-MCP-001 (still disabled, still DENY-then-start only).  
**Lab-specific:** Scope vs resource teaching copy; specimens; COMPARE fingerprints for MCP-003/004 payloads.  
**LIVE/REPLAY:** Target LIVE ATTACK+RETEST; keep REPLAY dropdown.  
**Blocker:** Must add ExperimentDefinition rows and Attack Service pages — **that is 15B work, not 15A**.  
**Done:** 14E loop on both labs; equivalent-input RETEST; no schema change; no new detector; PI-001/MCP-001 unchanged.

### Wave 2 — Result, catalog, scanner evidence

**Why:** INV-002 after grant anatomy. Scanner is not LIVE Attack Service.  
**Prerequisites:** Wave 1 (or at least MCP-001 + 003 conceptually).  
**Reuse:** OBSERVE classifier teaching from catalog/result already in Studio.  
**Lab-specific:** Two-hop result; catalog hash; scanner sourcetype join.  
**LIVE/REPLAY:** Result + catalog candidates for LIVE; scanner stays REPLAY/DESIGN.  
**Blocker:** Result RETEST must keep the same malicious result bytes; catalog must not imply metadata PDP.  
**Done:** DATA≠AUTHORITY taught with honest modes.

### Wave 3 — RAG then memory

**Why:** Context → persistence. Memory is RAG-across-time.  
**Prerequisites:** INV-002 (Wave 2 or strong DESIGN EXERCISE).  
**Reuse:** Context-authority hunts; MCP follow-on.  
**Lab-specific:** Retrieve→tool; write `run.id` then recall `run.id`.  
**LIVE/REPLAY:** LIVE valuable if two hops/runs stay closed and equivalent. Else REPLAY.  
**Blocker:** Attack Service currently one-shot definitions; memory needs linked launches.  
**Done:** Retrieved/recalled content never taught as grant.

### Wave 4 — Deputy then identity

**Why:** Two different “delegation” stories; 006 has Studio, identity does not.  
**Prerequisites:** Tool grant (Wave 1).  
**Reuse:** Q-MCP-DELEGATION, Q-AGENT-DELEGATION-AUTHORITY.  
**Lab-specific:** Identity workshop XML (new); no A2A transport.  
**LIVE/REPLAY:** 006 LIVE later; identity LIVE only if closed definitions stay in-process.  
**Blocker:** Identity Studio missing; risk of collapsing 006 with A2A-001.  
**Done:** Claim ≠ authentication ≠ grant; still no live A2A.

### Wave 5 — Goal integrity loop

**Why:** Authorized tool ≠ authorized goal requires a learner who already believes tool grants are real.  
**Prerequisites:** Wave 1; workshop already exists as GRID.  
**Reuse:** 13E Studio, Q-GOAL-INTEGRITY-AUTHORITY, CTRL-GOAL-INTEGRITY-001.  
**Lab-specific:** Attack Service definitions for GOAL-001 equivalent RETEST.  
**LIVE/REPLAY:** LIVE improves COMPARE; REPLAY already teaches the inequality.  
**Blocker:** Learners skipping to goal will treat goal DENY as MCP DENY.  
**Done:** 14E loop; no DET-GOAL; MCP remains sole tool PDP.

### Later — Level 8–9 capstone, Home academy IA, MLTK lessons

Not a lab migration. See capstone and Splunk skill docs. **Do not implement from 15A.**

---

## What must remain lab-specific (never share as policy)

Specimens, trust-path copy, hunt questions, solution SPL, fingerprints, profile names.  
Do **not** share PDPs. CTRL-INPUT-001 ≠ CTRL-MCP-001 ≠ CTRL-GOAL-INTEGRITY-001. OBSERVE classifiers never become grants.
