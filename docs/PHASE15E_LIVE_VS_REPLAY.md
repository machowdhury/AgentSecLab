# Phase 15E — LIVE vs REPLAY

**LIVE:** fresh Attack Service experiment. New `run.id`. Investigate in Splunk Search.

**REPLAY:** canonical Phase 12C Splunk specimens bound in Dashboard Studio Investigate specimen:

- BASELINE `b419465c-84d8-4639-8449-34dd99841ba9`
- ATTACK `f846be88-1f9d-4dde-ac80-193c01b47660`
- RETEST `271695f5-4739-44f2-8bf4-0749d04f4b03`

Do not present REPLAY output as the learner's new LIVE experiment.

Studio tokens are not auto-bound to a fresh run.id.

12C packs were indexed as schema 1.8.0. LIVE 15E emitters are schema 1.9.0. The hunt is version-agnostic. Completeness is local event count vs Splunk `dc(_raw)`.
