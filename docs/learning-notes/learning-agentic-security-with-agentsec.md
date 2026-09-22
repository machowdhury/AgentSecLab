# Learning agentic security with AgentSec

**Audience:** a technically competent learner who did not build this repository.  
**Status:** teaching note after Phase 17B. Not policy. Not a launcher spec.

## WHAT IS IT?

A hands-on academy: you launch or replay a controlled experiment against a lab agent, hunt the telemetry in Splunk, and prove what was authorized versus what executed.

## WHY DOES IT EXIST?

Agents mix untrusted text, tools, retrieval, memory, identity claims, and goals. People confuse influence with authority. AgentSec exists so you can practice the difference with evidence.

## HOW DOES IT WORK?

ORIENT → LEARN → PREDICT → ATTACK → OBSERVE → HUNT → DEFEND → RETEST → COMPARE → PROVE → CONNECT → MASTERY

- Studio = syllabus
- Attack Service = closed LIVE launcher
- AcmeBank = enforcement
- Splunk Search = notebook
- Mastery Check = reasoning practice, not a certificate

## WHERE DOES IT SIT IN AGENTSEC?

Start at Home. If agents/tools/RAG are new, read ORIENT. If you already know them, skip to Direct Prompt Injection, then Attack Service, then Search.

## WHAT IS THE TRUST BOUNDARY?

Different in every lab. Point at it: user prompt, tool request, retrieved document, recalled memory, proposed goal, identity claim.

## WHAT COULD AN ATTACKER CONTROL?

Only the closed specimen bytes for that lab. Not the server-owned profile or grant list.

## WHAT CAN GO WRONG?

Saying Splunk blocked it, DENY means nothing ran, retrieved text granted a tool, stored memory is trusted, MCP ALLOW means the goal was authorized, or one RETEST means the system is safe.

## WHAT TELEMETRY SHOULD EXIST?

Enough to reconstruct run.id, control id, decision, reason, requested vs granted, and whether execution started.

## HOW WILL SPLUNK SHOW IT?

A searchable copy in `index=agentsec_telemetry` sourcetype `otel:agentic:json`. HEC 200 is not ready. Empty is not DENY.

## WHAT CONTROL COULD CHANGE THE RESULT?

The named PDP for that lab. Some controls only OBSERVE. Splunk never authorizes.

## WHAT TEST PROVES THE LOGIC?

ATTACK and RETEST with the same adversarial bytes and different server-owned configuration, plus runtime execution counts. Pytest is not the learner proof.

## What I should now be able to explain

1. Why you predict before you launch.
2. Why LIVE and REPLAY are different skills.
3. Why REQUEST is not GRANT.
4. Why ALLOW is not execution.
5. Why OBSERVE is not ALLOW.
6. Why memory needs two run.ids.
7. Why an authorized tool can still be the wrong goal.
8. Why an identity string is not authentication.
9. Why empty Search is not prevention.
10. What Capstone synthesizes, and why Mastery Check is not a certificate.
