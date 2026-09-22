# Phase 17A fresh-learner walkthrough

**Persona:** basic IT/security, minimal Splunk, does not know AgentSec, does not know this repository, does not know historical phases.  
**Class:** DOCUMENTED intent + OBSERVED Playwright after restage (see `docs/PHASE17A_UI_UX_VALIDATION.md`).  
**Not claimed:** the learner completed live hunts in this walkthrough.

## Can they understand what to do?

1. **What challenge?** Home START still points at Direct Prompt Injection as the primary lab. Mastery Check is secondary after labs. Nav: Mastery Check sits after Capstone, before Search. INTRO explains it is not a certificate.
2. **Security question?** Each challenge card leads with it.
3. **Where to search?** Path A: Open Splunk Search. Starter: `index=agentsec_telemetry sourcetype=otel:agentic:json`.
4. **What to type?** Quoted `agentsec.run.id` when a specimen is given. Path A does not paste the final SPL.
5. **Hint?** Hint 1 then Hint 2 on the same card.
6. **Solution?** Path B on the same card. Studio 10.2 cannot hide it. INTRO states that honestly.
7. **What is proven?** SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT lists.
8. **What is next?** Each card has Next challenge. Last card points at RUBRIC.

## Friction (P0/P1)

- Beginners may open Mastery Check before any lab. INTRO tells them to start at Home / Direct Prompt Injection. Not a P0 if they follow INTRO.
- Path B is visible without an attempt. Product limit. Disclosed. Not solved with custom JavaScript.
- REPLAY UUIDs appear on practitioner cards. Necessary for Search. Labeled REPLAY so they are not mistaken for a launch the learner minted.
- Advanced tab is long (four challenges). Tabs still named by competency, not phase numbers.

No remaining P0/P1 learning blocker for “what do I do next?” after 17A packaging.

## What we did not expand

Studio cannot gate Path B. No progress backend. No instructor login. 768 remains diagnostic if still out of academy contract.
