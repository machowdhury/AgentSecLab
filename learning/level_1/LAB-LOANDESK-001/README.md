# LAB-LOANDESK-001 — Loan Desk: when the agent writes for the underwriter

This lab teaches one idea: **a valid, in-scope action can still carry an attacker's content, so authorization must also constrain what an allowed tool may carry.**

A real local model (Ollama, `llama3.2:latest`) reviews a synthetic loan application and files a note in the human underwriter queue through `submit_for_underwriter_review`. In the lab's BASELINE posture the note is free text. An applicant who hides an instruction in their notes can make the agent file the attacker's words, under the agent's authority. CTRL-LOANDESK-001 ALLOWs the call, because the tool, scope and applicant are all valid.

## What you do (ten steps, in the Academy)

Understand, Explore, Predict, Attack, Observe, Investigate, Defend, Retest, Compare, Explain. Open it from the Academy home page (Loan Desk Mission). Everything is LIVE: a real model proposes, CTRL-LOANDESK-001 decides, handlers run only after ALLOW, and every event carries one `agentsec.run.id`.

## The control

- **CTRL-LOANDESK-001** decides each proposed action: known tool, granted scope, resource bound to the run's applicant, budgets, and (HARDENED posture) the review note must be one of `READY_FOR_REVIEW`, `NEEDS_DOCUMENTS`, `CREDIT_CONCERN`, `INCOME_CONCERN`.
- The posture is a per-run closed setting recorded as `agentsec.defense.posture`. BASELINE is a deliberate lab weakness.
- The cross-customer denial `resource_not_bound_to_run` already existed and is not the fix for this attack.

## Evidence

- Events use the separate `agentsec.loan_desk_event` schema (1.0.0, or 1.1.0 when the run's model identity was recorded: see docs/MODEL_IDENTITY.md) (`schemas/loan_desk_event.schema.json`). `security_event` 1.9.0 is unchanged.
- The Splunk view `ws_lab_loandesk_001` separates model-proposed actions, policy decisions, executed actions, denied actions, evidence availability and business task completion.
- AcmeBank cannot reach Splunk. The page shows SPLUNK-VERIFIED only after the host verifier has checked the run through the signed bridge; otherwise it says NOT VERIFIED and why.

## Learning objectives

1. Distinguish a model's proposal, a policy decision and an executed handler as three separate facts.
2. Explain why ALLOW is not "safe": scope and applicant were valid while the content was never checked.
3. Reproduce a prompt-injection that plants attacker text in a human work queue, and prove it from recorded events.
4. Apply argument-level authorization, retest the same attack, and separate "attack blocked" from "business task completed".
5. Separate local evidence from Splunk-verified evidence.

## Limits

Synthetic data only. The model's prose is advisory and unverified. Model output varies run to run, so one run is an illustration; see an unpublished internal record for repeated runs. This is not a production control.
