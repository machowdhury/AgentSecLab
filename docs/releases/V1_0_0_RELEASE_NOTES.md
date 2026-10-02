# AgentSec v1.0.0 — release notes (prepared, not tagged)

These notes are the qualification text for final `v1.0.0`. The git tag was not created. `main` was not updated. Package metadata remains `1.0.0rc3` and the Splunk app version remains `1.0.0-rc3` until an authorized tag changes them.

Schema **1.9.0**. ExternalEvidence **1.0.0**. Those contracts were not bumped to match a product version.

AgentSec is a local educational academy. It is not a production security product. Splunk does not authorize tools. CTRL-MCP-001 is the tool policy decision point. DET-MCP-001 stays disabled.

## What a learner can treat as what

| Label | Meaning in this academy |
|-------|-------------------------|
| LIVE | A lab the Attack Service can launch against AcmeBank. On this host, LIVE generation is degraded until `llama3.2:1b` is listed by Ollama. |
| REPLAY | A workshop or lab whose evidence packet is replayed. It is not a new runtime enforcement. |
| SIMULATED | A teaching record, including synthetic credential and approval references. It is not a real credential. |
| MEASURED | A result from a command that was actually run, such as the clean-room clocks and the test counts below. |
| NOT TESTED | Screen reader. No WCAG claim. |
| NOT MODELED | Production IAM, OAuth, PKI, real A2A, and real cloud or GitHub credentials. |
| NOT PROVEN | An empty Splunk search, a garak pass, a scanner finding, a listed model name, or one RETEST. None of those is universal safety. |

## Since RC3

- Preflight states that LIVE generation requires `llama3.2:1b`, prints the pull command, and warns when the running container does not list the model.
- Preflight treats the lab's own OTel port range as an already-running AgentSec publish instead of a foreign listener.
- `lab-ready` separates SERVICE READY from `MODEL ABSENT` / `DEGRADED, not PASS`.
- The Ollama entrypoint says a certificate failure must be fixed at the trust layer. It does not disable verification.

## Clean-room (2026-10-02)

Fresh Compose project, new volumes, `.env` from `.env.example`.

- First containers running: 22s
- Splunk healthy: 3m 20s
- Service ready and Home sentence confirmed: 6m 7s
- AcmeBank: `1.0.0rc3`, `degraded`, `ollama_reachable` false
- Attack Service: `1.0.0rc3`, schema `1.9.0`, healthy
- Splunk app: `1.0.0-rc3`

The model pull inside the container failed TLS verification. Host `curl` to the same registry URL returned HTTP 200. That difference is documented external dependency, not a PASS for LIVE generation.

## Tests

Ten offline suites: each `1065 passed, 3 deselected`. Wheel `agentsec-1.0.0rc3` built. Screen reader: NOT TESTED.

## Known limitations

See `docs/KNOWN_LIMITATIONS.md`. In particular: unpinned `ollama/ollama:latest`, container TLS failure for the model pull, Splunk tab-strip scrolling, no screen reader test, and external mappings that are educational rather than certified.
