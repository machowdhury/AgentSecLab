# Changelog

## v1.1.0

Current educational release. Telemetry schema remains **1.9.0**. ExternalEvidence remains **1.0.0**. Tag `v1.0.0` and tags `v1.0.0-rc1`, `v1.0.0-rc2`, and `v1.0.0-rc3` were not moved.

Package metadata is `1.1.0`. The Splunk app version is `1.1.0`. Those strings are the product version. They are not the schema version and not the external-evidence contract version.

This release does not add a new LIVE attack, a new detector, or an authorization change. DET-MCP-001 stays disabled. CTRL-MCP-001 remains the tool policy decision point. Splunk remains the investigation workbench.

### Since v1.0.0

- Remote learner navigation stays on the host in the browser address bar.
- Install and preflight notes say what they do not prove.
- Attack Service session history labels the last client state and does not call it a Splunk verdict.
- The ATTACK versus RETEST comparison for the same lab rebuilds after reload.
- The launcher does not print the expected decision before launch.
- Academy Home shows a bounded AgentSec mark. The Splunk app has an app icon. The Attack Service favicon is a simplified mark.
- Dashboard Studio native tab focus is a Splunk 10.2 platform limitation. AgentSec does not inject a stylesheet into Studio.
- Runtime handler counts are taken from the request that entered the handler. A process-wide counter remains a diagnostic and is not request evidence. CTRL-MCP-001 is unchanged.

SCREEN READER: NOT TESTED. No WCAG claim. Physical keyboard traversal of Studio tabs: NOT MEASURED. True browser 200% zoom: NOT MEASURED.

## v1.0.0

Final educational release promoted from the qualified `v1.0.0-rc3` tree. Telemetry schema remains **1.9.0**. ExternalEvidence remains **1.0.0**. Tags `v1.0.0-rc1`, `v1.0.0-rc2`, and `v1.0.0-rc3` were not moved.

Package metadata is `1.0.0`. The Splunk app version is `1.0.0`. Those strings are the product version. They are not the schema version and not the external-evidence contract version.

This promotion does not add a lab, workshop, attack, detector, or authorization change. DET-MCP-001 stays disabled. CTRL-MCP-001 remains the tool policy decision point. Splunk remains the investigation workbench.

SCREEN READER: NOT TESTED. No WCAG claim. The Ollama model pull inside `ollama/ollama:latest` remains a documented external TLS dependency. A missing model leaves LIVE generation degraded. That is not a PASS.

## v1.0.0-rc3

Release candidate after the bounded REPLAY workshops. Telemetry schema remains **1.9.0**. ExternalEvidence remains **1.0.0**. This is not final `v1.0.0`. Tag `v1.0.0-rc2` was not moved. `main` was not merged.

Package metadata is `1.0.0rc3`. The Splunk app version is `1.0.0-rc3`. Those strings are the product version. They are not the schema version and not the external-evidence contract version.

### Since RC2

- REPLAY workshops for human approval binding, credential lifetime, RAG purpose, memory isolation, asset inventory, component provenance, code-agent bounds, and change bounds. Each packet is SIMULATED or REPLAYED. None of them is a second tool PDP. CTRL-MCP-001 remains the only tool authorization decision point.
- Studio browser titles are the view labels, so a missing definition title does not render as `undefined | Splunk`.
- DET-MCP-001 stays disabled. Learner text does not call that disabled search an enabled operational detection.
- `ollama/ollama:latest` stays unpinned. No digest was invented.
- Garak license, probe fidelity, Cisco AI-BOM compatibility, and framework mappings stay on the external-validation backlog.

## v1.0.0-rc2

Release candidate for the L0–L10 Agentic Security Academy. Telemetry schema remains **1.9.0**. ExternalEvidence remains **1.0.0**. This is not final `v1.0.0`.

RC1 (`v1.0.0-rc1`, commit `e6115b6d1c03a1672b4364e84748c7840671fbfc`) is the earlier academy through the L5 LIVE Capstone and Mastery Check. RC2 adds the later learning path and aligns the learner entry with that path. It does not add a new attack, detector, PDP, schema, or external-evidence contract.

### Since RC1

- Learner entry now names L0–L10, LIVE versus REPLAY, and the difference between the L5 Capstone, the L10 Advanced Capstone, and Mastery Check.
- RAG, memory, goal integrity, and identity/delegation remain LIVE labs. They do not mint tool grants. CTRL-MCP-001 remains the tool PDP.
- External security evidence: Cisco mcp-scanner (Cisco AI Defense) and garak (NVIDIA) stay adjacent evidence. A finding is not a DENY. A pass is not safe.
- Blue-team investigation, threat modeling, privacy, the L9 multi-stage incident, and the L10 mastery case are REPLAY or static reasoning. They are not new LIVE launchers.
- The seven LIVE labs are unchanged.
- DET-MCP-001 stays disabled. Candidate searches are not installed detectors.
- Clean-room installation, screen-reader coverage, and the garak license backlog remain unclosed.

## v1.0.0-rc1

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
