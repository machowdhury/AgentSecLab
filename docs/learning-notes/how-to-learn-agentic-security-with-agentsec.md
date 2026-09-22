# How to learn agentic security with AgentSec

**Audience:** the repository owner and future learners.  
**Status:** teaching note for Phase 15A. Not policy. Not a launcher spec.

## WHAT IS IT?

AgentSec is a **hands-on range** for agentic security: you launch (or replay) a controlled experiment, hunt the telemetry in Splunk, name the trust boundary, and prove what the runtime actually did.

It is not a production AI-security product. Completing it is not “I clicked every dashboard.”

## WHY DOES IT EXIST?

Agents mix untrusted text, tools, retrieval, memory, identity claims, and goals. People confuse **influence** with **authority**. AgentSec exists so you can practice the difference with evidence.

## HOW DOES IT WORK?

The locked loop (Phase 14E):

LEARN → PREDICT → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Platform roles:

- **Studio** = syllabus  
- **Splunk Search** = your investigation workbench  
- **Attack Service** = closed launcher (today: PI-001 and MCP-001 only)  
- **Runtime** = enforcement  
- **Splunk** = evidence copy, not the PDP  
- **Lesson YAML** = teaching metadata, not grants  

## WHERE DOES IT SIT IN AGENTSEC?

Start at Home. Take **Direct Prompt Injection**, then **Tool Authorization**. Those two are the only full LIVE purple-team loops today. Other workshops are real labs with real hunts; treat them as REPLAY or operator-LIVE until they are migrated. Do not pretend they are Attack Service LIVE.

## WHAT IS THE TRUST BOUNDARY?

Different in every lab. User prompt, tool request, tool result, catalog text, scanner JSON, retrieved document, recalled memory, identity claim, deputy ambient grants, task/goal. Your first job is to **point at it**.

## WHAT COULD AN ATTACKER CONTROL?

Only what that lab’s source actually is: prompt text, requested tool/scope/resource, result bytes, description text, retrieved doc, memory note, delegation JSON, task expansion. They must **not** control the server-owned profile or grant list via the browser.

## WHAT CAN GO WRONG?

You will be tempted to say “Splunk blocked it,” “DENY means nothing ran,” “the knowledge base authorized the tool,” or “one RETEST means we are safe.” Those are the course.

## WHAT TELEMETRY SHOULD EXIST?

Enough to reconstruct: `run.id`, lab, control id, decision, reason, requested vs granted, whether execution started. If the copy is missing, you have a telemetry problem, not a proof of prevention.

## HOW WILL SPLUNK SHOW IT?

Early: filter `run.id` and read the sequence. Later: correlate scope/resource/result/catalog, then retrieval/memory/identity/goal with MCP. Dashboards teach; Search proves you can hunt.

## WHAT CONTROL COULD CHANGE THE RESULT?

The **runtime** control for that boundary (CTRL-INPUT-001, CTRL-MCP-001, goal integrity, etc.). OBSERVE classifiers and scanners do not grant. Splunk does not grant.

## WHAT TEST PROVES THE LOGIC?

A `run.id` you can explain: same attack bytes on RETEST when LIVE, different profile, execution started or did not, limitations named. Pytest passing is not a purple-team proof.

## Suggested path (today)

1. Home — what Splunk is and is not.  
2. LAB-PI-001 LIVE — untrusted input.  
3. LAB-MCP-001 LIVE — request ≠ grant.  
4. MCP-003 / 004 workshops — scope then resource (REPLAY until Wave 1).  
5. MCP-005, catalog, scanner — data and findings ≠ authority.  
6. RAG, then memory — context, then persistence.  
7. MCP-006, then identity hunts — deputy vs identity claims.  
8. Goal integrity — authorized tool ≠ authorized task.  
9. Capstone — not built yet; do not skip here.

## What I should now be able to explain

1. Why Studio is a notebook and not a policy engine.  
2. Why only PI-001 and MCP-001 are Attack Service LIVE today.  
3. Why REQUEST ≠ GRANT is not the same lesson as RETRIEVED CONTENT ≠ AUTHORITY.  
4. Why MCP-003 belongs before catalog in the curriculum.  
5. Why MCP-006 and LAB-AGENT-DELEGATION-001 must not be collapsed.  
6. Why a scanner finding never authorizes `lookup_customer_tier`.  
7. Why Path B is pedagogy, not a lock.  
8. Why DET-MCP-001 exists and why most labs correctly have no DET-*.  
9. Why MLTK, if it ever appears, must not ALLOW or DENY.  
10. What you still cannot claim after one successful RETEST.
