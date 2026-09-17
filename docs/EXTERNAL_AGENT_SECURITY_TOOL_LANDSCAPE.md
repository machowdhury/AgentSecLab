# External agent-security tool landscape

**Status:** Phase 9A RESEARCH. Inspected **2026-09-16** (GitHub API + project READMEs).  
**Not an implementation plan.** Architecture: `docs/SCANNER_INTEGRATION_ARCHITECTURE.md`.  
**Do not execute these tools from this document.**

This is a snapshot. Re-verify before Phase 9B wire-up.

Star counts and `pushed_at` are GitHub API **MEASURED** at fetch time, not a quality ranking. Every factual claim has a source.

---

## Core principle

**SCANNER FINDING ≠ AUTHORIZATION DECISION.**

A scanner may discover, inspect, classify, flag, score, fingerprint, or report. It must not become CTRL-MCP-001, CTRL-MCP-METADATA-001, an AllowTicket issuer, IAM, an execution gate, or proof that a handler ran or did not run.

Scanner PASS ≠ trusted. Scanner FAIL ≠ DENY. Scanner silence ≠ safe.

---

## Taxonomy (classes)

| Class | Meaning in AgentSec |
|-------|---------------------|
| STATIC SCANNER | Inspects files/exports without connecting to a live MCP/agent |
| DYNAMIC SCANNER | Connects to a live server, stdio process, or running agent |
| RED-TEAM TOOL | Generates or scores attacks against a model/agent |
| AI BOM / INVENTORY | Lists models, tools, packages, or components |
| MCP CATALOG INSPECTOR | Reads tool/prompt/resource metadata |
| PROMPT-INJECTION TESTER | Probes models for injection success |
| SUPPLY-CHAIN ANALYZER | Package, pickle, model, or lockfile integrity |
| RUNTIME SECURITY TOOL | Intercepts or gates live execution |
| POLICY ENGINE | Issues ALLOW/BLOCK/admission decisions |
| IDENTITY / AUTHORIZATION TOOL | Principals, tickets, IAM |
| OBSERVABILITY / TELEMETRY PRODUCER | Emits traces/logs/metrics |
| COMPLIANCE EVIDENCE PRODUCER | Attestation / audit artifacts |

A project may have more than one class. AgentSec records the **dominant** class for integration risk.

---

## Cisco AI Defense OSS (`github.com/cisco-ai-defense`)

Public org: **17** repos ([org page](https://github.com/cisco-ai-defense), 2026-09-16). There is **no** separately named GitHub repo `mcpscanner`. The Python module for mcp-scanner is `mcpscanner` ([README](https://github.com/cisco-ai-defense/mcp-scanner)).

| Repo | Stars | Last push (API) | License | Class | AgentSec strategy |
|------|------:|-----------------|---------|-------|-------------------|
| **skill-scanner** | 2525 | 2026-09-05 | Other / NOASSERTION | STATIC SCANNER (agent skills) | DEFER until a skill lab exists |
| **mcp-scanner** | 1074 | 2026-09-16 | Apache-2.0 | MCP CATALOG INSPECTOR / STATIC+DYNAMIC | **FIRST INTEGRATE** (static `--tools`) |
| **defenseclaw** | 843 | 2026-09-16 | Apache-2.0 | POLICY ENGINE / RUNTIME SECURITY | DROP from core; REFERENCE overlay only |
| **a2a-scanner** | 166 | 2026-04-16 | Apache-2.0 | STATIC/DYNAMIC SCANNER (A2A) | DEFER until A2A lab |
| **aibom** | 109 | 2026-09-01 | Apache-2.0 | AI BOM / INVENTORY | LATER INTEGRATE as inventory, not authz |
| **model-provenance-kit** | 102 | 2026-09-01 | Apache-2.0 | SUPPLY-CHAIN ANALYZER | DEFER until model-artifact lab |
| **ai-defense-python-sdk** | 35 | 2026-08-03 | Apache-2.0 | POLICY ENGINE (commercial API) | DEFER; not core |
| **securebert2** | 42 | 2025-11-19 | Apache-2.0 | EVALUATION / MODEL | DROP for scanner integration |
| **pickle-fuzzer** | 17 | 2026-08-03 | Apache-2.0 | RED-TEAM / SUPPLY-CHAIN | DEFER until pickle lab |
| **adversarial-hubness-detector** | 17 | 2026-03-17 | Other | STATIC SCANNER (RAG) | DEFER until RAG |
| **ai-defense-langchain-middleware** | 13 | 2026-07-14 | Apache-2.0 | POLICY ENGINE | DROP (AgentSec is not LangChain) |
| **ai-defense-hybrid** | 7 | 2026-07-29 | Apache-2.0 | UNCLEAR | REFERENCE ONLY |
| **ai-defense-google-adk** | 3 | 2026-04-21 | Apache-2.0 | POLICY ENGINE | DROP (not ADK) |
| **fpr-model-calibration** | 2 | 2026-09-09 | Apache-2.0 | DETECTION SUPPORT | REFERENCE ONLY |
| **litellm** (fork) | 2 | 2026-08-21 | Other | LLM GATEWAY | DROP |
| **ai-defense-cli** | 0 | 2026-08-13 | Apache-2.0 | SCANNER BUNDLE CLI | OPTIONAL operator path later |
| **.github** | 0 | 2026-05-01 | — | org files | Ignore |

### mcp-scanner (capability, not marketing)

Source: [cisco-ai-defense/mcp-scanner README](https://github.com/cisco-ai-defense/mcp-scanner) fetched 2026-09-16.

**Measures:** MCP tools, prompts, resources, server instructions. Engines: YARA, optional LLM analysis, optional Cisco AI Defense inspect API. Threat names include TOOL POISONING and PROMPT INJECTION ([mcp-threats-taxonomy.md](https://github.com/cisco-ai-defense/mcp-scanner)). Prompt Defense analyzer is README-documented as regex and default.

**Does not measure:** whether AgentSec CTRL-MCP-001 ALLOW/DENY occurred; whether a handler ran; two-epoch catalog pin (rug-pull) as an AgentSec-grade integrity check — **not verified** as a pin-over-time feature.

**Static path (VERIFIED in README):** `mcp-scanner --analyzers yara static --tools /path/to/tools-list.json`. Expected JSON is a `tools[]` array with `name`, `description`, `inputSchema`. No live server required. YARA-only needs no API key.

**Output:** `--format raw` JSON; also summary/detailed tables.

**Executes target?** Live/stdio/HTTP modes can connect to MCP servers. **Static mode does not require that.** Phase 9B must use static files.

**LLM?** Optional. Default lab path: YARA-only.

**Offline?** YARA static: yes if rules are local. API/LLM analyzers: no.

**Deterministic?** YARA-only: expected yes for the same rules + same bytes. LLM analyzers: no.

### DefenseClaw (do not embed)

Source: [cisco-ai-defense/defenseclaw](https://github.com/cisco-ai-defense/defenseclaw) README + [mcp scan CLI docs](https://cisco-ai-defense.github.io/docs/defenseclaw/cli/commands/mcp).

It **does** treat scanner HIGH/CRITICAL as admission/block for OpenClaw MCP `set`. That is a production gateway pattern. AgentSec must **not** copy that into AcmeBank. Using DefenseClaw as the bank would collapse the teaching boundary SCANNER FINDING ≠ AUTHORIZATION.

### aibom

Source: [cisco-ai-defense/aibom](https://github.com/cisco-ai-defense/aibom). Inventory of AI components. Inventory ≠ authorization. Useful later as a BOM artifact to fingerprint, not as Phase 9B.

### a2a-scanner

Source: [cisco-ai-defense/a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner). Last push **2026-04-16** — stale relative to mcp-scanner/defenseclaw. DEFER until an A2A lab exists. Do not begin A2A from Phase 9A.

### skill-scanner

Source: [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner). Agent-skill files, not MCP tool catalogs. DEFER until AgentSec has a skill-file lab.

---

## Invariant Labs lineage / Snyk Agent Scan

| Item | Verified 2026-09-16 |
|------|---------------------|
| Historical product | Invariant Labs **MCP-Scan** ([blog 2025-04-11](https://invariantlabs.ai/blog/introducing-mcp-scan); tool poisoning / rug-pull research) |
| GitHub `invariantlabs-ai/mcp-scan` | **Redirects to `snyk/agent-scan`** |
| Current repo | https://github.com/snyk/agent-scan — Apache-2.0, **3052** stars, `pushed_at` 2026-09-15 |
| CLI | `snyk-agent-scan` via `uvx`; Snyk CLI extension is `--experimental` |
| Output | `--json`; v0.5.x issue codes (deprecating); v0.6+ risk-based `2026-07-10` analysis API ([README](https://github.com/snyk/agent-scan)) |
| Retrieves tool descriptions | **VERIFIED** — connects to MCP servers |
| Executes stdio MCP | **VERIFIED warning** — CI requires `--dangerously-run-mcp-servers` in trusted environments ([scanning.md](https://github.com/snyk/agent-scan/blob/main/docs/scanning.md)) |
| Cloud | v0.6 analysis API; optional Snyk Evo upload. Default AgentSec core must not require `SNYK_TOKEN` |
| Rug-pull pin | Original Invariant **blog** named pinning. Current Agent Scan README signatures/API — **not** verified here as AgentSec two-epoch catalog pin |

**Best AgentSec use:** SECOND integration, comparison against the same catalog fixture after a safe export path exists. Do not auto-start untrusted stdio.

When docs say “Invariant mcp-scan,” AgentSec means: the TPA research **plus** the scanner lineage now published as Snyk Agent Scan. Do not invent a frozen `mcp-scan` CLI at the old URL.

---

## Other active OSS (credible, not forced)

| Project | Home | Last push (API) | License | Class | Strategy |
|---------|------|-----------------|---------|-------|----------|
| **Garak** | `NVIDIA/garak` | 2026-09-09 | Apache-2.0 | RED-TEAM / PROMPT-INJECTION TESTER | DEFER; LLM probe fixture, not catalog scan |
| **PyRIT** | `microsoft/PyRIT` | 2026-09-15 | MIT | RED-TEAM TOOL | DEFER; attack fixture later. **Do not use `Azure/PyRIT`** (archived stub 2026-03-25) |
| **Promptfoo** | `promptfoo/promptfoo` | 2026-09-16 | MIT | EVALUATION / RED-TEAM | DEFER; test oracle for CTRL-INPUT-001 |
| **LlamaFirewall** | PurpleLlama / `llamafirewall` | active docs | (package) | POLICY ENGINE / RUNTIME SECURITY | REFERENCE; comparison lab only |
| **g0** | `guard0-ai/g0` | README inspected | (see repo) | MIXED SCANNER + COMPLIANCE | REFERENCE ONLY — OpenClaw-heavy, platform upsell; not first-wave |
| **OWASP Agent Memory Guard** | OWASP project page | roadmap 2026 | — | RUNTIME SECURITY (ASI06) | DEFER until memory lab |

Sources: GitHub API 2026-09-16 for Garak/PyRIT/Promptfoo; [protectai/llm-guard](https://github.com/protectai/llm-guard) archived 2026-07-09; Azure/PyRIT archived stub.

### Archived / do not integrate as live scanners

| Project | Status | Source |
|---------|--------|--------|
| **protectai/llm-guard** | **Archived** 2026-07-09 (GitHub API `archived: true`; README warning) | https://github.com/protectai/llm-guard |
| **Azure/PyRIT** | **Archived** stub; real project is `microsoft/PyRIT` | GitHub API 2026-09-16 |

---

## Foundation AI / Antares (not AI Defense org)

| Project | Actual purpose | Strategy |
|---------|----------------|----------|
| **Foundation-Sec-8B** (+ Instruct / Reasoning) | Open-weight cybersecurity LLM (`fdtn-ai` on Hugging Face; Cisco Foundation AI) | WRAP optional hunt-assist. Never authorization. |
| **Antares-350M / 1B / 3B** | Agentic **vulnerability localization in codebases** ([antares site](https://cisco-foundation-ai.github.io/antares/)) | DROP from scanner integration. Wrong problem. |

---

## Frameworks (not scanners)

| Name | Use |
|------|-----|
| OWASP LLM Top 10 / Agentic (ASI) 2026 | Mapping source. REFERENCE. |
| MITRE ATLAS | Mapping source. Revalidate IDs. |
| NIST AI RMF / GenAI profiles | Mapping source. REFERENCE. |
| MCP specification | Protocol. AgentSec already implements a teaching subset. |
| Cisco AI threat taxonomy (mcp-scanner docs) | Scanner finding classes. Do not copy into AgentSec `control.reason`. |

---

## What AgentSec should not force in

- Commercial inspect APIs as a core lab dependency
- OpenClaw-only gateways as the bank
- Code-vuln locators as SOC tools
- Archived prompt-guard libraries as “the scanner”
- LiteLLM / LangChain / ADK middleware (wrong application stack)
- Any scanner as CTRL-MCP-001

Full comparison table: `docs/PHASE9A_SCANNER_RESEARCH.md`.
