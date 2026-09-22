# AgentSec graduate profile (Phase 16C)

**Status:** DESIGN. Capabilities supported by the **actual** curriculum after 16B.  
Not a certificate. Not a hiring bar for production agent-security engineering.

---

## A person completing AgentSec (Levels 1–5 as mapped) should be able to

- Explain major agentic trust boundaries (input, retrieved context, memory, tool request, task/goal, identity/delegation claim).
- Distinguish data from authority, including retrieved content, stored memory, tool results, and catalog text.
- Understand tool authorization: request, coded grant, scope/resource (REPLAY), decision, execution.
- Reason about RAG and persistent memory as influence planes that do not mint grants.
- Reason about agent identity/delegation **limitations**: claims are not authentication; A+B does not create grants; real A2A/OAuth is NOT PROVEN here.
- Reason about task/goal integrity: authorized tool ≠ authorized purpose.
- Launch controlled, server-owned attacks (seven LIVE labs) without choosing grants in the browser.
- Perform Splunk investigations (Path A) on `index=agentsec_telemetry sourcetype=otel:agentic:json`.
- Reconstruct execution using runtime handler/LLM counts, with Splunk as corroboration.
- Identify the PDP (CTRL-INPUT-001, CTRL-MCP-001, CTRL-GOAL-INTEGRITY-001 as applicable) vs OBSERVE classifiers.
- Compare ATTACK vs RETEST with equivalent adversarial bytes.
- Understand evidence limitations (HEC, incomplete copy, overlay, localhost, no multi-tenant).
- Distinguish hunting from detection; explain why DET-MCP-001 silence is not SAFE.
- Explain why Splunk observes rather than authorizes.
- Rule out an irrelevant security domain when the instrumented experiment does not require it (capstone Goal/Identity).

---

## The graduate is NOT yet trained to

- Design or operate production agent IAM (OAuth/OIDC/JWT/SPIFFE, real A2A).
- Build or enable production detectors beyond understanding DET-MCP-001’s narrow invariant.
- Use MLTK / behavioral analytics as authority or as a required skill.
- Perform HITL / human-approval engineering.
- Run vector-database RAG, LangChain apps, or Kubernetes agent meshes.
- Steal or defend real secrets, sandbox escapes, or destructive actions.
- Claim OWASP/NIST/ATLAS certification or “the application is secure against all RAG/memory attacks.”
- Treat MCP-003/004/005/006/catalog/scanner as Attack Service LIVE (they are REPLAY unless later migrated).
- Assume Level 0 orientation existed in the product (it is still DESIGN).

---

## Honest completion statement

“Completed AgentSec as implemented” means: LIVE PI, MCP-001, RAG, Memory, Goal, Identity, and capstone purple-team loops, plus recommended REPLAY grant/INV-002/deputy workshops, with Path A investigations and proof classification.

It does **not** mean: finished every historical phase document, enabled DET-MCP-001, or secured a production agent platform.
