# LAB-LOANDESK-001 searches

Each search takes one run.id (`__RUN_ID__`). Fields are wrapped in `mvindex(mvdedup(...),0)` because `otel:agentic:json` stores every body field more than once (see `docs/reviews/batch4/SEQUENCE_DUPLICATION.md`). The searches work unchanged if that duplication is later removed.

- Q-LOANDESK-PROPOSED: what the model proposed (real inference, or a labelled test double).
- Q-LOANDESK-DECISIONS: what CTRL-LOANDESK-001 decided and why.
- Q-LOANDESK-EXECUTED: whether a handler began (`agentsec.mcp.started`) and finished.
- Q-LOANDESK-DENIED: denied actions, and whether any handler started anyway.
- Q-LOANDESK-EVIDENCE: whether the run's events are all indexed (start, end, no sequence gaps).
- Q-LOANDESK-BUSINESS: business task completion versus the security outcome.
- Q-LOANDESK-QUEUE: what was actually filed in the underwriter queue.

A search that returns no rows means "no events found", not "nothing happened".
