# AgentSec mastery rubric

**Status:** IMPLEMENTED on Mastery Check RUBRIC tab (Phase 17A). Not a numeric score. Not certification.

Self-assess each dimension as **NEEDS REVIEW**, **DEMONSTRATED**, or **ADVANCED**. Nothing is stored.

## TRUST BOUNDARY REASONING

- NEEDS REVIEW — Mixes data, claims, and grants. Cannot name where untrusted input meets a control.
- DEMONSTRATED — Names the boundary and what the attacker does not control.
- ADVANCED — Separates multiple planes (input, context, identity, goal) without collapsing them into prompt injection.

## AUTHORITY REASONING

- NEEDS REVIEW — Treats OBSERVE as ALLOW, claims as authentication, or retrieved text as a grant.
- DEMONSTRATED — Names the actual PDP and says REQUEST != GRANT.
- ADVANCED — Explains why a granted tool can still be the wrong goal, and why identity OBSERVE is not authentication.

## SPLUNK INVESTIGATION

- NEEDS REVIEW — Searches `index=*` or pastes Path B first.
- DEMONSTRATED — Uses quoted `run.id`, `sequence`, and `event.name` in Search.
- ADVANCED — Chooses the right existing Q-* hunt without treating Studio tables as a fresh LIVE launch.

## EXECUTION RECONSTRUCTION

- NEEDS REVIEW — Reads ALLOW as execution or missing rows as prevention.
- DEMONSTRATED — Cites runtime handler/LLM count as authoritative where the lab defines it; Splunk as corroboration.
- ADVANCED — States completeness limits (local vs `dc(_raw)`; HEC 200 is not searchable evidence).

## ATTACK / RETEST COMPARISON

- NEEDS REVIEW — Compares different payloads or calls RETEST universal security.
- DEMONSTRATED — Same adversarial bytes; different server-owned configuration; different decision/execution.
- ADVANCED — Names what the experiment still cannot prove.

## EVIDENCE QUALITY

- NEEDS REVIEW — One field proves the whole outcome. Empty dashboard = SAFE.
- DEMONSTRATED — Classifies SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT.
- ADVANCED — Rewrites false SOC sentences into defensible claims.

## SECURITY COMMUNICATION

- NEEDS REVIEW — Says Splunk blocked, the agent authenticated, or RAG was trusted.
- DEMONSTRATED — Uses AgentSec vocabulary without overclaiming.
- ADVANCED — Explains the same incident to a peer without repository jargon.

There is no weighted total. A learner can be DEMONSTRATED on Splunk and NEEDS REVIEW on authority in the same sitting.
