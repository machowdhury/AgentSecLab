# Known limitations (v1.0.0-rc3)

These remain visible on purpose. The RC3 candidate does not remove them. The RC1 reproducibility note remains a historical record. A later clean-room section in the RC3 release notes is the measurement for this candidate.

- Screen-reader coverage was not tested in the RC3 gate. This is not a WCAG conformance claim.
- Dashboard Studio tabs use an inset box-shadow for keyboard focus. On the Change Bounds and Tool Authorization views, `outline` computed to `none` and a blue inset ring was present on the focused tab. That ring is the Splunk control.
- Workshops with many tabs, such as A2A Authentication and Delegation, put the tab list in a horizontally scrolling strip. At 1024px the last tabs start past the viewport until the strip is scrolled or the tab is focused. They were not covered by the Splunk favorite toolbar in the RC3 measurement. At 200% CSS zoom on a 1024px window, the Tool Authorization page scroll width doubled and the last tab extended about 2px past the viewport while remaining hittable.

- Early LIVE mission cards may state the expected ATTACK outcome before the learner investigates
- Path B is visible pedagogical guidance, not access control
- Splunk practice still begins with a pasted `run.id`. The move to independent search at L6 is abrupt
- Two evidence vocabularies remain: how evidence was obtained, and how strong a claim is
- `ollama/ollama:latest` is not pinned. A clean-room `ollama pull llama3.2:1b` on this host failed with `x509: certificate signed by unknown authority` while contacting `registry.ollama.ai`. That is a host TLS observation, not a measured image digest. Until a model is present, AcmeBank `/health` reports `ollama_reachable: false` and `status: degraded`.
- The garak pin license line is not closed external validation (`docs/EXTERNAL_VALIDATION_BACKLOG.md`)
- The GitHub default branch remains `main` (RC1). The current candidate is `develop`. Tag `v1.0.0-rc2` is the previous candidate.
- External findings do not authorize tool execution
- Production delegation, production IAM, human approval, and cryptographic identity are not modeled
- Empty or negative search results are not proof of safety

- Educational localhost Attack Service (unauthenticated)
- Not production authentication or multi-tenant isolation
- Studio Path B is often visible without a reveal control
- Dashboard Studio layout/platform constraints
- CTRL-INPUT-001 is regex-class educational inspection, not a general LLM firewall
- RAG uses exact-id fixtures, not a production retriever
- Memory is in-process; not a durable vector store
- Identity authentication is not modeled (no OAuth/OIDC/SPIFFE)
- No real A2A protocol implementation
- Splunk indexing delay; HEC health ≠ searchable events
- LIVE vs REPLAY must not be collapsed
- Missing event is not prevention
- One RETEST is not universal security
- No learner progress persistence
- No certification
- DET-MCP-001 is packaged disabled; no DET-CAPSTONE / DET-RAG / DET-MEMORY / DET-GOAL
- ATLAS labels require revalidation (educational, not verified MITRE mappings)
- Hardware minimums NOT BENCHMARKED
- Clean-room install for this candidate is recorded in the RC3 release notes. The RC1 note is historical.
