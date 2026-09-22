# Changelog

Product notes for AgentSec **v1.0.0-rc1**. Telemetry schema remains **1.9.0**.

RC1 is a release candidate plus external-validation pack (`docs/releases/`). It does not add attack domains or detectors.

## Academy

Splunk Dashboard Studio curriculum: Home (default), Foundations, Context Security, Agent Intent, Capstone, Mastery Check. Search is the investigation notebook.

## LIVE labs

Direct Prompt Injection, Tool Authorization, RAG / Retrieved Context, Persistent Memory, Goal / Instruction Integrity, Agent Identity / Delegation, Capstone (Lending Assistant Investigation).

## REPLAY labs

Scope Escalation, Parameter / Resource Authorization, Tool Result Trust, Tool Catalog, Scanner + Runtime Evidence, Confused Deputy.

## Splunk investigation

Path A (construct hunts in Search) and Path B (review keys). Packaged hunts include saved searches `Q-RUN`, `Q-DENY`, and Studio-embedded Q-* families. Completeness is local event count vs `dc(_raw)` when measured.

## Attack / Retest

Closed Attack Service launch contract. ATTACK and RETEST are server-owned specimen overlays. Browser cannot submit grants, tools, or arbitrary SPL.

## Capstone / Mastery

Integrated LIVE capstone. Mastery Check is unscored and is not a certificate.

## Security boundaries

Educational vulnerable profiles. Localhost unauthenticated Attack Service. Splunk observes; it does not authorize.

## Known limitations

See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).
