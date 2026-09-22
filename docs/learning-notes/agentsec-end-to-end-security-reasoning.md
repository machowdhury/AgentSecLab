# End-to-end security reasoning (AgentSec)

AgentSec is a **localhost learning range**. You do not finish it by opening every dashboard. You finish a lab when you can walk one experiment from untrusted bytes to a control decision to execution evidence in Splunk — and say what that evidence cannot prove.

## What is it?

A reusable reasoning chain. Every LIVE lab is a different **trust boundary** on the same chain.

## Why does it exist?

Agent security incidents look like “the model did something weird.” That sentence mixes source, influence, request, grant, and execution. The chain forces you to unmix them.

## How does it work?

```text
SOURCE → PROVENANCE → TRUST BOUNDARY → INFLUENCE
  → REQUEST / CLAIM → AUTHORITY → POLICY DECISION
  → EXECUTION → TELEMETRY → SPLUNK → EVIDENCE / PROOF
```

Provenance is “where the bytes came from.” Trust is “may we treat them as instruction.” Authority is “is this tool/scope/resource granted.” Those are three different facts.

## Where does it sit in AgentSec?

Studio teaches the chain. Attack Service launches a **frozen** experiment (not a policy store). AcmeBank runtime enforces. Splunk stores a copy. Learning JSON is not authorization.

## What is the trust boundary?

Depends on the lab: input string (PI), tool request (MCP), retrieved document (RAG), recalled memory (memory), server-owned task (goal), identity claim (delegation). The capstone (not built) fuses RAG + memory + MCP on purpose.

## What could an attacker control?

Only what the closed catalog injects: loan text, tool name, document body, memory body, instruction, claim JSON. They cannot choose the real grant list from the browser.

## What can go wrong?

If you treat OBSERVE as ALLOW, or a document as a grant, or caller_agent_id as login, or empty Splunk as blocked, you will write the wrong incident report.

## What telemetry should exist?

`run.id`, sequence, control.id, decision, reason, plus the domain fields (rag.*, memory.*, goal.*, identity.*, mcp.*). Execution events if the dangerous operation started.

## How will Splunk show it?

You write Path A searches. Path B is the answer key after you try. Dashboards are the syllabus, not the investigation.

## What control could change the result?

The **PDP** for that boundary (CTRL-INPUT-001 or CTRL-MCP-001). Classifiers (RAG/memory/identity) change labels, not grants. Goal changes the **task**, not the tool allow-list.

## What test proves the logic?

ATTACK and RETEST with **equivalent** adversarial bytes and different server-owned configuration. Runtime counts are authoritative; Splunk corroborates a complete copy.

---

## Inequalities (learn in order, not as a poster)

REQUEST ≠ GRANT. PROVENANCE ≠ TRUST. TRUST ≠ AUTHORITY. IDENTITY CLAIM ≠ AUTHENTICATION. DELEGATION CLAIM ≠ AUTHORIZATION. CALLER ID ≠ GRANT. RETRIEVED CONTENT ≠ AUTHORITY. STORED MEMORY ≠ TRUSTED INSTRUCTION. AUTHORIZED TOOL ≠ AUTHORIZED GOAL. OBSERVE ≠ ALLOW. ALLOW ≠ EXECUTION. DENY ≠ PROOF OF NON-EXECUTION. MISSING EVENT ≠ PREVENTION. HEC ACCEPTANCE ≠ SEARCHABLE EVIDENCE. SPLUNK ≠ ENFORCEMENT. ANOMALY ≠ INCIDENT. BASELINE ≠ SAFE. RETEST ≠ UNIVERSAL SECURITY.

---

## What I should now be able to explain

1. Why provenance, trust, and authority are different.
2. Why Splunk cannot be the PDP even when DET-MCP-001 exists.
3. Why RAG OBSERVE plus MCP ALLOW is not “the document authorized the tool.”
4. Why memory needs two `run.id`s.
5. Why goal RETEST can DENY the task while MCP still ALLOWs `lookup_policy`.
6. Why identity LIVE does not prove authentication.
7. Why MCP-006 (confused deputy) is not the identity lab.
8. Why some labs correctly have no detector.
9. What a future capstone should hide from the learner (the failing domain name).
10. What finishing today’s six LIVE labs still does not prove (real A2A, HITL, capstone, production).
