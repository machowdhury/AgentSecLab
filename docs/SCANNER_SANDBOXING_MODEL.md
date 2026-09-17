# Scanner sandboxing model

**Status:** Phase 9A DESIGN. Phase **9B** implemented the smallest host wrapper: isolated venv, static input, timeout, output cap, secret-stripped env, no target execution. Container/cgroup/network-namespace isolation was **not** implemented. Network disable is **not** claimed.  
**Parent:** `docs/SCANNER_THREAT_MODEL.md`.

---

## Goal

When Phase 9B runs a scanner, the process must not become a second runtime with extra authority, network, or secrets.

Prefer **static artifact scanning** over live MCP connect.

---

## Recommended execution boundary (future)

| Control | Default for first integration (Cisco mcp-scanner YARA static) |
|---------|---------------------------------------------------------------|
| Input | Read-only mount of exported `tools[].json` AgentSec generated |
| Output | Ephemeral writable dir; copied into `artifacts/<run-id>/scanner/` after |
| User | Non-root |
| Network | **None** for YARA-only |
| Secrets | Not mounted (no `.env`, no HEC token, no Ollama key) |
| CPU / memory / time | Hard limits (cgroup or `timeout`); fail closed to `ERROR` evidence, not ALLOW |
| Filesystem | No Docker socket; no `/var/run`; no workspace write except output dir |
| Version | Pinned release + recorded SHA-256 of the installed artifact |
| Workspace | Ephemeral; destroyed after copy-out |

Container isolation is preferred when Docker is already the lab substrate. A local venv is acceptable **only** for YARA-static against files we wrote, still with no network and no secrets.

---

## Mode matrix

| Mode | Allowed in core 9B? | Network | Executes target? |
|------|---------------------|---------|------------------|
| Cisco mcp-scanner `static --tools` + `--analyzers yara` | **YES — first** | No | No |
| Same + LLM analyzer | Optional overlay later | Likely yes | No code exec of MCP, but LLM API |
| Same + Cisco inspect API | Teach-mode overlay | Yes | No |
| mcp-scanner live stdio/HTTP | **NO** for core | Yes | **Yes** (connect) |
| Snyk Agent Scan default connect | Second wave, after static export path | Maybe | **May start MCP** |
| Snyk `--dangerously-run-mcp-servers` | **NO** unless dedicated isolated lab | Yes | **Yes** |
| DefenseClaw MCP set/block | **NO** | N/A | Admission gateway |

---

## Pinning

Record in the evidence manifest (future):

- scanner package name + version
- git commit if built from source
- SHA-256 of wheel or container image digest (`sha256:…`)
- YARA ruleset identity if separable
- command line argv (no secrets)

Do not float to `latest`.

---

## Failure policy

| Failure | Evidence | Runtime effect |
|---------|----------|----------------|
| Timeout | `OBSERVED_SCANNER` with outcome ERROR | None |
| Non-zero exit | Capture stderr (size-capped) | None |
| Parse failure | Do not index garbage as findings | None |
| Hash mismatch vs expected fixture | Uncorrelated; do not join | None |

Scanner crash ≠ AgentSec DENY. Scanner crash ≠ safe catalog.

---

## What not to build yet

- A general MCP sandbox product
- Kubernetes jobs
- Nested VMs
- Network policy mesh

The smallest useful 9B sandbox is: **container or timed process, read-only input, no network, pinned binary, captured JSON.**
