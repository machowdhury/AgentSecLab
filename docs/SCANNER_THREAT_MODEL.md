# Scanner threat model

**Status:** Phase 9A DESIGN ONLY. No scanner installed or executed.  
**Parents:** `docs/SCANNER_INTEGRATION_ARCHITECTURE.md`, `docs/SCANNER_SANDBOXING_MODEL.md`, `.cursor/rules/20-security.mdc`.

A scanner is itself an **untrusted evidence producer**. Treating it as a security oracle recreates the catalog-poisoning lesson at one layer up.

---

## Assets

| Asset | Why it matters |
|-------|----------------|
| AgentSec runtime authorization | Must stay independent of scanner output |
| Catalog fixtures (NORMAL / MALICIOUS) | Teaching ground truth for LAB-MCP-CATALOG |
| Lab secrets (HEC token, Ollama, `.env`) | Must never be mounted into a scanner sandbox |
| Splunk index integrity | Malicious findings could pollute investigation |
| Learner conclusions | False “scanner blocked it” teaching |
| Host filesystem / network | Scanner or MCP stdio may execute code |

---

## Threats

### T-SCAN-001 Scanner executes a malicious MCP server

**Threat:** Dynamic scan starts stdio MCP (`uvx`, `npx`, local binary). The server runs attacker code.  
**Applies to:** Snyk Agent Scan (`--dangerously-run-mcp-servers` warning, [scanning.md](https://github.com/snyk/agent-scan/blob/main/docs/scanning.md)); Cisco mcp-scanner **live** modes.  
**Does not apply to:** Cisco mcp-scanner `static --tools` against a JSON file AgentSec wrote.  
**Invariant:** INV-008 fail-safe — missing sandbox context must not become “just run it.”  
**Mitigation (design):** Phase 9B first path is **static artifacts only**.

### T-SCAN-002 Scanner retrieves remote code or models

**Threat:** LLM analyzer, inspect API, or package fetch pulls untrusted content. Network exfiltration of catalog text (may include secrets if a learner pasted one).  
**Mitigation:** YARA-offline default; no API keys in core; restricted network in sandbox.

### T-SCAN-003 Dependency compromise of the scanner

**Threat:** PyPI/npm supply-chain on `cisco-ai-mcp-scanner`, `snyk-agent-scan`, or transitive deps.  
**Mitigation:** Pin version + record SHA-256 of wheel/sdist; do not `pip install` from HEAD in CI without a pin.

### T-SCAN-004 Malicious scanner output

**Threat:** Oversized JSON, nested bombs, path traversal in fields (`../../../etc/passwd`), ANSI/control characters in `description` echoed into terminals or Studio markdown, prompt injection inside finding text that a later LLM hunt-assist reads.  
**Mitigation:** Size limits; parse with a strict schema; never concatenate finding text into a privileged prompt; sanitize for display; treat finding body as **untrusted data** (INV-002).

### T-SCAN-005 Malicious SARIF / JSON as a gadget

**Threat:** Unexpected keys, huge `regions`, XSS if rendered as HTML, Splunk extraction DoS.  
**Mitigation:** Store raw; normalize only allow-listed fields; Studio must not `|` raw HTML from findings.

### T-SCAN-006 LLM-based scanner manipulation

**Threat:** Poisoned tool description causes the scanner’s LLM analyzer to under-report or to emit attacker-controlled JSON.  
**Mitigation:** Default 9B path is **YARA-only**. If LLM analyzer is used later, label `llm_involved=true` and treat results as non-deterministic.

### T-SCAN-007 Scanner version drift

**Threat:** 9B result cannot be reproduced; rules changed; “PASS” last month is “FAIL” this month without artifact change.  
**Mitigation:** Pin scanner version; hash ruleset if shipped; record in provenance.

### T-SCAN-008 TOCTOU between scan and execution

**Threat:** Scan file A; runtime loads file B; learner concludes “scanner approved this run.”  
**Mitigation:** Correlate **only** when SHA-256 matches. Hash mismatch = uncorrelated experiments.

### T-SCAN-009 Findings used as authorization

**Threat:** Operator or future code maps HIGH → DENY. DefenseClaw already does this for OpenClaw MCP set ([docs](https://cisco-ai-defense.github.io/docs/defenseclaw/cli/commands/mcp)).  
**Mitigation:** Architectural lock. Tests in 9B must assert runtime does not read finding files. No `cisco_*=FAIL` on `security_event`.

### T-SCAN-010 Secrets in scanner config

**Threat:** `SNYK_TOKEN`, Cisco inspect API keys, cloud endpoints in repo or screenshots.  
**Mitigation:** Workspace hardcoded-credential rule. Core lab must run with **zero** scanner cloud credentials.

### T-SCAN-011 Path traversal / workspace write

**Threat:** Scanner or adapter writes outside the ephemeral workspace.  
**Mitigation:** Read-only input mount; writable only `/tmp/scan-out`; non-root.

---

## Security invariants (mapped)

| Invariant | Scanner implication |
|-----------|---------------------|
| INV-001 | Scanner cannot grant the agent more tools |
| INV-002 | Scanner finding text cannot authorize privileged actions; catalog descriptions remain data |
| INV-004 | Privileged MCP actions still attributed to AgentSec control path |
| INV-007 | Scanner packs must be complete enough to reconstruct *what was scanned* |
| INV-008 | Missing scanner ≠ ALLOW; missing sandbox ≠ execute live MCP |

---

## Trust boundary

```text
[untrusted catalog JSON]
        ↓
[scanner process / optional LLM / optional API]   ← untrusted producer
        ↓
[raw finding file]                                ← untrusted data
        ↓
[AgentSec adapter]                                ← trusted to label, not to authorize
        ↓
[evidence bundle / future sourcetype]
        ↓
[Splunk]                                          ← investigation
        ✕  does not enter
[CTRL-MCP-001 / CTRL-MCP-METADATA-001 / handler]
```

---

## Residual risk

Even a static YARA scan can **miss** (FN) or **over-flag** (FP). That is expected teaching material, not a reason to unsandbox the scanner or to wire it into DENY.
