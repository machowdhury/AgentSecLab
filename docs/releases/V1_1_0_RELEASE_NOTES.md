# AgentSec v1.1.0 — release notes

AgentSec v1.1.0 is a local educational agentic-security academy. It is not a production security product.

Package **1.1.0**. Splunk app **1.1.0**. Schema **1.9.0**. ExternalEvidence **1.0.0**. Product version, schema version, and the external-evidence contract are independent.

Splunk does not authorize tools. CTRL-MCP-001 is the tool policy decision point. DET-MCP-001 stays disabled.

This release promotes the reviewed candidate `9aaab66ce9d7f72c00439de9af94487389f4e0ac` after the version strings and these release records. It does not add a LIVE attack, a detector, or an authorization change.

Tag `v1.0.0` stays on its original commit. Tags `v1.0.0-rc1`, `v1.0.0-rc2`, and `v1.0.0-rc3` were not moved.

## What a learner can treat as what

| Label | Meaning in this academy |
|-------|-------------------------|
| LIVE | A lab the Attack Service can launch against AcmeBank. A listed model name is not proof of generation quality. |
| REPLAY | A workshop whose evidence packet is replayed. It is not a new runtime enforcement. |
| SIMULATED | A teaching record. It is not a real credential, approval, or cloud action. |
| MEASURED | A result from a command or browser check that was actually run. |
| NOT TESTED | Screen reader. No WCAG claim. |
| NOT MEASURED | Physical keyboard traversal of Studio tabs. True browser 200% zoom. |
| NOT MODELED | Production IAM, OAuth, PKI, real A2A, and real cloud or GitHub credentials. |
| NOT PROVEN | An empty Splunk search, one RETEST, or a completed_allowed terminal. None of those is universal safety or a measured resource impact. |
| PLATFORM LIMITATION | Dashboard Studio native tab focus on Splunk 10.2. AgentSec cannot load an app stylesheet into that page. |

## Since v1.0.0

- Remote deployment keeps Academy, Search, and Attack Service on the host in the browser address bar.
- Prerequisite, preflight, and lab-ready notes say what they do not prove.
- Attack Service session history keeps the run id and labels the last client state. That label is not a Splunk verdict.
- The ATTACK versus RETEST comparison for the same lab rebuilds after reload. A different lab is not paired.
- The launcher does not print the expected decision or reason before launch.
- Academy Home renders a bounded AgentSec mark. The Splunk app ships an app icon. The Attack Service favicon is a simplified mark.
- Ollama is described as the local LLM runtime for LIVE labs. It is not part of Splunk. REPLAY workshops do not require it.
- Handler-start counts on a launch response belong to that request. `ToolRegistry.invoke_counts` stays a process-wide diagnostic. It is not request evidence. This does not change CTRL-MCP-001.

## Known limitations

See `docs/KNOWN_LIMITATIONS.md`.

Dashboard Studio native tab focus: PLATFORM LIMITATION — SPLUNK 10.2. Visible focus was not rendered. Physical keyboard: NOT MEASURED. Screen reader: NOT TESTED. No WCAG claim.

Installation time is NOT BENCHMARKED for v1.1.0. The 2026-10-02 clean-room in the v1.0.0 notes is a historical measurement. It is not a promise for this release.

ALLOW is not execution. Execution is not a measured downstream resource change.
