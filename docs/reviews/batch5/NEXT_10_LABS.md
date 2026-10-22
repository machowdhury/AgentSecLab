# The ten most valuable missing hands-on exercises

Scored 1–5 on **impact** (what a learner can do afterwards that they could not before), **relevance** (how often this
is the real-world failure), and **ease** (5 = least effort). Priority = impact + relevance + ease; ties go to the one
that unlocks others. The table is already sorted by that score. Effort uses what exists today: the Loan Desk loop (real model proposes, `policy.decide`, handlers,
closed event schema, two-posture control, Splunk view, mission shell, verification bridge) is reusable, which is why
most of these are cheaper than building a lab from nothing. None of this is an estimate in days; it is a rank.

| # | Exercise (hands-on, LIVE, real model unless stated) | Fills (matrix row) | Impact | Relev. | Ease | Score | Why now |
|---|---|---|---|---|---|---|---|
| 1 | **Detection against a live attack.** Learner writes a Splunk detection for the Loan Desk planted-note run, then measures true and false positives across benign and attack runs (the benchmark scripts already produce both populations). | DETECTION-ENGINEERING (REPLAY, simulated positives); vision #16, #17 | 5 | 5 | 4 | **14** | The platform's whole pitch is Splunk, and no lab fires a detection on a live run. Needs no new agent code. |
| 2 | **Human approval that can be fooled.** Loan Desk gains an `issue_loan_offer` that requires approval. Attack: approval fatigue, approving a summary rather than the action, replaying an old approval. Defense: approval bound to a hash of the exact action and arguments, single use. | HITL (CONTENT-ONLY, simulated); vision #14 | 5 | 5 | 3 | **13** | Only content-only topic with a real production incident pattern. Reuses the Loan Desk policy and event schema. Replaces the simulated approval packet with a live one. |
| 3 | **Model-driven indirect injection through retrieval.** Put the Loan Desk agent in front of a small document store; attacker edits a document; agent follows it. Defense: provenance-tagged retrieval + the existing tool PDP. | RAG-CONTEXT (PARTIAL, observe-only, scripted); vision #1, #7 | 5 | 5 | 3 | **13** | RAG is the most common real entry point and the current lab has no model choosing anything. |
| 4 | **Data exfiltration through an allowed output.** The agent's allowed note or summary tool carries sensitive fields out (rendered link, copied PII from a profile). Defense: output constraint plus a Splunk detection for field-level egress. | PRIVACY (PARTIAL); vision #10 (MISSING) | 5 | 5 | 3 | **13** | The only vision subject with no exercise at all, and the natural next step after the planted-note idea. |
| 5 | **Excessive agency and least privilege.** Learner widens the agent's granted scopes until a bad outcome happens, then narrows them and measures what legitimate work breaks. | MCP-001 deterministic; vision #13 | 4 | 5 | 4 | **13** | Teaches the usability cost of a control, which the hardened-run copy already needs. Mostly a policy parameter plus UI. |
| 6 | **Same attack, three models.** Run the planted-note attack and the hardened control across the installed models; read why results differ; learn that a defense must not depend on model behaviour. | Loan Desk; benchmark scripts exist | 4 | 4 | 5 | **13** | The measurement code exists; it turns a limitation (one model) into a lesson. Needs no new control. |
| 7 | **Secrets in tool results and logs.** A canary credential appears in a handler result; learner finds where it leaked (model context, event body, index) and adds redaction. | CREDENTIAL-LIFETIME (CONTENT-ONLY); vision #11 (MISSING live) | 4 | 5 | 3 | **12** | Uses Splunk to find the leak, which is the part only this platform can teach. |
| 8 | **Poisoned tool description, model picks the tool.** A tool's catalog text is altered; the real model selects the wrong tool. Defense: pin and diff the catalog, require approval on change. | MCP-CATALOG (REPLAY, observe-only); vision #12 | 4 | 4 | 3 | **11** | MCP is central to the product; today it is replay with no runtime. |
| 9 | **Memory poisoning across sessions with a real model.** Write in session 1, trigger in session 2. Defense: memory write provenance and isolation per applicant. | MEMORY-001 (PARTIAL, observe-only); vision #8; RECALL-ISOLATION (CONTENT-ONLY) | 4 | 4 | 3 | **11** | Persistence is what makes agent attacks different from chat attacks. |
| 10 | **Agent-to-agent delegation with two real agents.** Intake agent hands a task to a credit agent with a forged claim of authority; defense is a verified, audience-bound grant. | A2A-AUTH (CONTENT-ONLY), DELEGATION (PARTIAL); vision #4, #6 | 5 | 4 | 1 | **10** | Biggest conceptual gap, biggest effort; do it last, after 1 and 2 have made the loop and the detection pattern routine. |

## Suggested order
Build in table order. Rank 1 (detection against a live attack) needs no new agent behaviour and makes the Splunk half of
the platform earn its place; if only one exercise is built, build it. Ranks 2–6 tie at 13 and can be sequenced by
audience need (rank 2, human approval, is the most requested real-world failure). Rank 10 (two real agents) is last
because it is the largest piece of work and benefits from the earlier ones making the loop routine.

## What I did not rank and why
- New attack techniques for their own sake (adversarial suffixes, jailbreak libraries): they teach attacks, not system design.
- Multitenancy, app packaging, a second framework (LangGraph etc.): out of scope for Batch 5, and none changes what a learner learns.
- Anything needing a model larger than a laptop can hold.
