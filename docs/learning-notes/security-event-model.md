# Security Event Model (learning note)

**Superseded for Phase 1B (schema 1.0.0).**

The first-lab event contract is now:

- `docs/SECURITY_EVENT_MODEL.md`
- `docs/EVIDENCE_MODEL.md`
- `docs/learning-notes/security-telemetry-101.md`
- `schemas/security_event.schema.json`

Do not learn the withdrawn names (`agentsec.normal_request`, `agentsec.prompt_attack`, tool/A2A/memory/RAG/chain events) as the first-lab vocabulary.

Do not treat `testbed.mode=LIVE` as valid. Do not treat Splunk absence of `llm.*` as DENY proof. Do not treat `llm.failed` as non-execution.
