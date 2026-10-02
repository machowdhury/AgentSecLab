# AgentSec v1.0.0 — release notes

AgentSec v1.0.0 is a local educational agentic-security academy. It is not a production security product.

Package **1.0.0**. Splunk app **1.0.0**. Schema **1.9.0**. ExternalEvidence **1.0.0**. Product version, schema version, and the external-evidence contract are independent.

Splunk does not authorize tools. CTRL-MCP-001 is the tool policy decision point. DET-MCP-001 stays disabled.

This release promotes the qualified commit `4c2f7929a7dd0d6d14b06de35c0b5383af11ed52`. That qualification tree still reported package `1.0.0rc3`. The promotion changes the product identity to `1.0.0`. It does not add a lab, attack, detector, or authorization change, and it does not re-measure the clean-room.

## What a learner can treat as what

| Label | Meaning in this academy |
|-------|-------------------------|
| LIVE | A lab the Attack Service can launch against AcmeBank. On the qualification host, LIVE generation was degraded until `llama3.2:1b` is listed by Ollama. |
| REPLAY | A workshop or lab whose evidence packet is replayed. It is not a new runtime enforcement. |
| SIMULATED | A teaching record, including synthetic credential and approval references. It is not a real credential. |
| MEASURED | A result from a command that was actually run, such as the clean-room clocks and the test counts below. |
| NOT TESTED | Screen reader. No WCAG claim. |
| NOT MODELED | Production IAM, OAuth, PKI, real A2A, and real cloud or GitHub credentials. |
| NOT PROVEN | An empty Splunk search, a garak pass, a scanner finding, a listed model name, or one RETEST. None of those is universal safety. |

## Since RC3

- Product identity moved from `1.0.0rc3` / `1.0.0-rc3` to `1.0.0`.
- Preflight states that LIVE generation requires `llama3.2:1b`, prints the pull command, and warns when the running container does not list the model.
- `lab-ready` separates SERVICE READY from `MODEL ABSENT` / `DEGRADED, not PASS`.
- The Ollama entrypoint says a certificate failure must be fixed at the trust layer. It does not disable verification.

## Clean-room (2026-10-02)

Fresh Compose project, new volumes, `.env` from `.env.example`. Measured on the qualification tree, before this version string changed.

- First containers running: 22s
- Splunk healthy: 3m 20s
- Service ready and Home sentence confirmed: 6m 7s
- AcmeBank: `1.0.0rc3`, `degraded`, `ollama_reachable` false
- Attack Service: `1.0.0rc3`, schema `1.9.0`, healthy
- Splunk app on that run: `1.0.0-rc3`

The model pull inside the container failed TLS verification. Host `curl` to the same registry URL returned HTTP 200. That difference is a documented external dependency, not a PASS for LIVE generation. Degraded was not recorded as healthy.

## Tests

Qualification: ten offline suites, each `1065 passed, 3 deselected`. The promotion suite is recorded in `docs/releases/V1_0_0_VALIDATION.md`. Screen reader: NOT TESTED.

## Known limitations

See `docs/KNOWN_LIMITATIONS.md`. In particular: unpinned `ollama/ollama:latest`, container TLS failure for the model pull, Splunk tab-strip scrolling, no screen reader test, and external mappings that are educational rather than certified.

SCREEN READER: NOT TESTED. No WCAG claim.
