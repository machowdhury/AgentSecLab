# Phase 9A — external scanner research

**Status:** RESEARCH / DESIGN ONLY. Inspected **2026-09-16**.  
**Verdict target:** ACCEPT — RESEARCH / DESIGN ONLY.  
**Do not execute scanners. Do not start Phase 9B from this file.**

Parents: `docs/EXTERNAL_AGENT_SECURITY_TOOL_LANDSCAPE.md`, `docs/SCANNER_INTEGRATION_ARCHITECTURE.md`.

---

## Method

| Step | Source |
|------|--------|
| Cisco AI Defense org repo list | GitHub org https://github.com/cisco-ai-defense (17 public repos) |
| Per-repo stars, license, `pushed_at` | GitHub API 2026-09-16 |
| mcp-scanner capabilities | README + taxonomy at cisco-ai-defense/mcp-scanner |
| Snyk / Invariant lineage | GitHub redirect invariantlabs-ai/mcp-scan → snyk/agent-scan; README; docs/scanning.md; Invariant blog 2025-04-11 |
| Other OSS | GitHub API for NVIDIA/garak, microsoft/PyRIT, promptfoo/promptfoo, protectai/llm-guard, Azure/PyRIT |
| Foundation / Antares | Hugging Face fdtn-ai; https://cisco-foundation-ai.github.io/antares/ |
| AgentSec constraints | LAB-MCP-CATALOG 8C–8E complete; schema 1.5.0; scanners NOT STARTED |

Prior AgentSec docs (`AGENTSEC_OPEN_SOURCE_SECURITY_ECOSYSTEM.md`, `MCP_CATALOG_POISONING_SCANNER_INTEGRATION.md`) were **re-checked**, not copied as the only source.

Limitations: READMEs are DOCUMENTED_EXTERNAL. No scanner binary was installed or run. Star counts are not quality. `pushed_at` is activity, not security assurance.

---

## First integration recommendation

**Cisco mcp-scanner**, **static** ` --tools` JSON, **YARA-only**.

| Criterion | Assessment | Source |
|-----------|------------|--------|
| Open source | Apache-2.0 | GitHub API |
| Actively maintained | `pushed_at` 2026-09-16; 1074★ | GitHub API |
| Relevant | MCP tools/descriptions; TOOL POISONING in taxonomy | README |
| Safe to execute in lab | Static file mode; no live server; no API key for YARA | README |
| Machine-readable | `--format raw` JSON | README |
| Works with MCP-CATALOG artifacts | Expected `tools[{name,description,inputSchema}]` — **exportable** from AgentSec fixtures | README vs `src/agentsec/mcp/fixtures.py` (export not implemented in 9A) |
| Educational | Scan-predict vs runtime-observe | AgentSec 8E workshop already teaches INV-002 |
| Splunk correlation | Description SHA-256 already indexed | 8D field contract |
| Integration complexity | Adapter + sandbox + pack; no runtime change | This design |
| Strategic Cisco relevance | **Noted, not decisive** | Selection holds on static/YARA/JSON even if the maintainer were different |

Not selected merely because it is Cisco. Snyk Agent Scan is more famous on stars (3052) and owns the Invariant TPA lineage, but its **default path connects to MCP and may execute stdio**. That fails the “safe to execute in lab” and “static files” criteria for the **first** wire-up.

---

## Second integration recommendation

**Snyk Agent Scan** (`snyk/agent-scan`), as a **comparison** scanner against the **same** exported catalog artifact after the static path is proven.

Use for: cross-tool disagreement teaching; TPA issue-code / risk-name vocabulary.  
Do not use for: authorization; `--dangerously-run-mcp-servers` in core; requiring `SNYK_TOKEN`.

If Agent Scan cannot consume a static tools JSON (not verified in this pass as a first-class flag equivalent to mcp-scanner `--tools`), 9B must **STOP** on that path and record TELEMETRY/INTERFACE GAP rather than start untrusted stdio.

---

## Defer

| Tool | Until |
|------|--------|
| skill-scanner | Agent skill file lab |
| aibom | Inventory lab; fingerprint BOMs |
| a2a-scanner | A2A lab (not started; last push 2026-04-16) |
| Garak / PyRIT / Promptfoo | Attack-fixture / CTRL-INPUT-001 oracle track |
| Foundation-Sec-8B | Optional hunt-assist WRAP |
| model-provenance-kit / pickle-fuzzer | Model artifact lab |
| adversarial-hubness-detector | RAG lab |
| Cisco inspect API / ai-defense-python-sdk | Teach-mode overlay with credentials out of core |
| CDTSM / AI Toolkit | After event-derived **metrics** exist |
| LlamaFirewall | Comparison runtime-rails lab, not scanner ingest |

---

## Drop (from scanner integration / core)

| Tool | Why |
|------|-----|
| DefenseClaw as AcmeBank | Admission gateway maps scanner HIGH → block; collapses SCANNER ≠ AUTHZ |
| Azure/PyRIT | Archived stub; use microsoft/PyRIT if red-team later |
| protectai/llm-guard as live target | Archived 2026-07-09 |
| cisco-ai-defense/litellm fork | Wrong stack |
| LangChain / Google ADK middleware | AgentSec is not those apps |
| Antares as SOC / scanner | Code vulnerability localization |
| g0 as first-wave | OpenClaw-heavy commercial upsell; REFERENCE only |
| Rebuilding YARA/LLM engines inside AgentSec | Mature upstream exists |

---

## What AgentSec should BUILD

- Scanner adapter + provenance manifest
- SHA-256 artifact identity (catalog export + raw output)
- Evidence-class labeling (OBSERVED_SCANNER vs OBSERVED_RUNTIME)
- Correlation design with METADATA-001 hashes
- Splunk sourcetype contract **after** ingest (not in 9A)
- Workshop teaching: predicted vs happened
- Sandbox wrapper (9B)
- Tests that runtime does not read findings

---

## Tool comparison table

Last verified: **2026-09-16**. Activity = GitHub `pushed_at`. MCP/A2A = protocol support claimed in docs, not AgentSec tested.

| Project | Maintainer | License | Last verified | Activity | Primary purpose | MCP support | A2A support | Static/dynamic | Executes target? | Machine-readable output | LLM dependency | Best AgentSec use | Integration risk | Recommendation |
|---------|------------|---------|---------------|----------|-----------------|-------------|-------------|----------------|------------------|-------------------------|----------------|-------------------|------------------|----------------|
| mcp-scanner | cisco-ai-defense | Apache-2.0 | 2026-09-16 | 2026-09-16 | MCP tool/prompt/resource inspection | Yes | No | Both; **static `--tools`** | Live modes can connect; **static no** | JSON (`--format raw`) | Optional | First catalog scan | Low if YARA-static | **INTEGRATE FIRST** |
| Agent Scan | Snyk (Invariant lineage) | Apache-2.0 | 2026-09-16 | 2026-09-15 | Agent/MCP security scan | Yes | Not primary | Dynamic-leaning; may start servers | **Yes if stdio** | `--json` | Cloud/API analysis v0.6 | Second comparison | Medium–high | **INTEGRATE SECOND** |
| skill-scanner | cisco-ai-defense | Other / NOASSERTION | 2026-09-16 | 2026-09-05 | Agent skill scanning | Skills, not MCP catalog | No | Static files | No if files only | Check README at 9B | Unknown | Later skill lab | License clarity | DEFER |
| aibom | cisco-ai-defense | Apache-2.0 | 2026-09-16 | 2026-09-01 | AI BOM inventory | Indirect | No | Static/inventory | No | JSON BOM | No (inventory) | Inventory fingerprint | Low | DEFER / later INTEGRATE |
| defenseclaw | cisco-ai-defense | Apache-2.0 | 2026-09-16 | 2026-09-16 | OpenClaw governance / MCP admission | Wraps mcp-scanner | — | Runtime gateway | Can block MCP set | CLI/config | Uses scanners | REFERENCE overlay only | **High** (becomes authz) | **DROP from core** |
| a2a-scanner | cisco-ai-defense | Apache-2.0 | 2026-09-16 | 2026-04-16 | A2A scanning | No | Yes | Mixed | Unknown live | Check at A2A phase | Unknown | After A2A lab | Stale vs siblings | DEFER |
| Garak | NVIDIA | Apache-2.0 | 2026-09-16 | 2026-09-09 | LLM vulnerability probing | Not MCP catalog | No | Dynamic vs model | Hits the **model**, not MCP stdio catalog | JSON reports | Uses target LLM | PI fixture later | Medium (model calls) | DEFER |
| PyRIT | Microsoft | MIT | 2026-09-16 | 2026-09-15 | Generative red team | Not MCP catalog | No | Dynamic | Orchestrates attacks | JSON/memory | Yes | Attack fixtures | Medium | DEFER |
| Promptfoo | promptfoo | MIT | 2026-09-16 | 2026-09-16 | Eval + red team | MCP eval extras exist; not AgentSec catalog | No | Eval harness | May call models | JSON | Often | CTRL-INPUT-001 oracle | Medium | DEFER |
| llm-guard | Protect AI | MIT | 2026-09-16 | archived 2026-07-09 | Prompt/output scanning | No | No | Library | No | API | Classifiers | None as live target | Archived | **DROP** |
| Azure/PyRIT | Azure | — | 2026-09-16 | archived 2026-03-25 | Stub | — | — | — | — | — | — | Do not use | Wrong repo | **DROP** |
| Foundation-Sec-8B | Cisco Foundation AI / fdtn-ai | model license | 2026-09-16 | HF models | Cyber LLM | No | No | Model | N/A | N/A | Is an LLM | Hunt-assist WRAP | High if used as authz | DEFER WRAP |
| Antares | Cisco Foundation AI | model | 2026-09-16 | project site | Code vuln localization | No | No | Agent over code | May run tools on repos | Reports | Yes | Not this problem | Wrong fit | **DROP** |
| LlamaFirewall | Meta PurpleLlama | (package) | docs | active docs | Runtime rails | Possible MCP hooks in product docs | No | Runtime | Intercepts | Config | Optional | Comparison lab | High if embedded as bank | REFERENCE |
| g0 | guard0-ai | (see repo) | README | README | Mixed platform scanner | Claims MCP | — | Mixed | Unknown | Unknown | Likely | Not first-wave | Commercial/OpenClaw | REFERENCE ONLY |

Sources for rows: GitHub API 2026-09-16; project READMEs cited in `docs/EXTERNAL_AGENT_SECURITY_TOOL_LANDSCAPE.md`; Invariant blog; llm-guard archive flag.

---

## Framework mapping (defensible only)

| Framework item | Relation to scanner integration | Status |
|----------------|--------------------------------|--------|
| OWASP LLM01 Prompt Injection | Tool-description PI is a **related** content class scanners try to flag | RELATED |
| OWASP Agentic ASI02 / ASI04 (interface / malicious server) | Catalog poisoning lab already RELATED; scanners may flag descriptions | RELATED |
| OWASP ASI06 Memory | Memory Guard project — not this phase | UNMAPPED (this phase) |
| MITRE ATLAS | Do not copy ATK ids onto scanner rules without revalidation | REQUIRES REVALIDATION |
| NIST AI RMF / GenAI | Govern/map/measure/manage — evidence packs support **measure**; scanners are not the RMF | RELATED |
| MCP specification | Catalog is protocol metadata; scanners inspect it; AgentSec runtime still authorizes | RELATED |
| Cisco mcp-scanner threat taxonomy | Finding vocabulary for **scanner** evidence only | RELATED (scanner-native) |
| INV-002 Data cannot grant authority | Core AgentSec property; scanners do not implement it | SUPPORTED (AgentSec runtime, not scanners) |

Do not map “YARA hit = ASI02 violation proven.”

---

## AgentSec differentiation (evidence-based)

| Claim | Evidence in this repo | Not a uniqueness claim for |
|-------|----------------------|----------------------------|
| Controlled vulnerable vs defended runtime | LAB-MCP-CATALOG ATTACK overlay vs RETEST DENY; pytest + 8D LIVE IDs | Being an MCP scanner |
| Runtime non-execution proof | `executed` / `mcp.started` honesty; DET-MCP-001 sequence | Scanner FAIL |
| Authorization invariants INV-001–008 | Coded CTRL-* before handler | Vendor severity |
| Evidence bundles | `artifacts/<run-id>/` | SARIF as a format |
| OTel + closed schema 1.5.0 | emitters + schema tests | Generic OTel GenAI |
| Splunk SOC investigation | Q-MCP-* + workshops | Red-team leaderboards |
| Scanner vs runtime correlation | **Designed** in 9A; **not yet measured** | Do not claim it is implemented |
| Learner workshops | `ws_lab_mcp_catalog` 8E | Scanner UIs |
| Positive controls | SIMULATED DET-MCP-001 fixtures | Production detections |
| ATTACK/RETEST equivalence | Same MALICIOUS hash 8D | Scanner reproducibility (untested) |
| Evidence-class discipline | research-integrity rule + 8D SIMULATED ≠ OBSERVED | Marketing “AI SOC” |
| Knowledge-object engineering | inventory + 33-splunk-agent-skills | CIM coverage |
| Cross-tool comparison | Planned first vs second scanner | Product bake-off UI |

**Supported combination:** reproducible agent attacks **and** reference controls **and** honest telemetry **and** Splunk investigation **and** workshops that refuse zero-rows=safe. Individual scanners do not provide that combination. AgentSec does **not** uniquely invent MCP scanning.

---

## Explicit non-starts from this document

No scanner install/execute. No runtime/schema/SPL/detector/Studio. No rug-pull. No A2A. No Phase 9B automatic start.
