# MCP catalog poisoning — scanner integration (design)

**Status:** Phase 8B DESIGN. **Scanners not executed, not integrated.**  
**Inspected:** 2026-09-16.

---

## Boundary (mandatory)

```text
MCP catalog snapshot
        ↓
optional scanner CLI          → findings JSON → separate evidence / sourcetype → Splunk
        ↓
(runtime does not read findings)

agent / lab interpreter
        ↓
CTRL-MCP-METADATA-001
        ↓
CTRL-MCP-001
        ↓
handler
```

| Claim | Truth |
|-------|--------|
| Scanner FAIL / FINDING | Evidence. **Not** runtime DENY. |
| Scanner PASS | Not proof the tool is safe. |
| Scanner silence | Not trusted metadata. |
| Runtime ALLOW | Not “scanner approved.” |
| `mcp.started` | Execution began, not success. |

Core lab must run with **zero** scanner binaries.

---

## Cisco AI Defense mcp-scanner

| Item | Verified |
|------|----------|
| Repo | https://github.com/cisco-ai-defense/mcp-scanner |
| Default branch `main` SHA | `be87b90d88bca2527a6e2075769a7608decd8f27` (2026-09-16T00:18:57Z) — **this commit only added CodeQL workflow**; capability claims are from README/`docs/mcp-threats-taxonomy.md` at fetch time |
| PyPI / CLI | `cisco-ai-mcp-scanner`; module `mcpscanner` |
| Engines | YARA, LLM-based analysis, optional Cisco AI Defense inspect API |

**VERIFIED capabilities (docs):**

| Target | Docs say |
|--------|----------|
| MCP **tools** | Yes — including `static --tools` JSON (CI / no live server) |
| Prompts, resources, **server instructions** | Yes |
| LLM threat names include **TOOL POISONING**, PROMPT INJECTION, TOOL SHADOWING | Yes (`mcp-threats-taxonomy.md`) |
| YARA: prompt injection, code execution, credential harvesting, etc. | Yes |
| Behavioural code / PyPI / VirusTotal | Yes (broader than 8B) |

**NOT VERIFIED / not claimed as first-class in README:**

| Topic | Status |
|-------|--------|
| Rug-pull (description changed after approval) | **Not verified** as a pin-over-time feature. Taxonomy “modifying” is a finding class, not a two-time-point integrity check. |
| Tool-definition **diff** / hash pin | **Not verified** in this pass. |
| Using findings as AgentSec DENY | **Must not.** |

**8C/optional strategy:** CALL EXTERNALLY `mcp-scanner static --tools <exported snapshot.json>` (YARA-only default for air-gapped lab). IMPORT OUTPUT labeled OBSERVED-cli. No inspect API in core.

---

## Invariant mcp-scan / current successor

| Item | Verified 2026-09-16 |
|------|---------------------|
| Historical product | Invariant Labs **MCP-Scan** (blog 2025-04-11; TPA blog 2025-04-01) |
| GitHub `invariantlabs-ai/mcp-scan` | **Redirects to `snyk/agent-scan`** (Agent Scan). Stars ~3052. Pushed 2026-09-15. |
| Current CLI | `snyk-agent-scan` (`uvx`); output **experimental** (v0.5.x deprecating; v0.6+ risk names) |
| Retrieves tool descriptions | **VERIFIED** (README: connects to servers / starts stdio to list tools) |
| Prompt injection in tool descriptions | **VERIFIED** v0.6 risk `prompt_injection_tool_desc`; v0.5 issue **Tool Poisoning** |
| Dangerous / destructive capability wording | **VERIFIED** v0.6 `dangerous_words`, `destructive_capabilities` |
| Rug-pull / pinning | **Original Invariant blog VERIFIED** as a named MCP issue and **recommended client pin**. Current Agent Scan README mentions config **signatures** sent to API — **not** verified here as AgentSec-grade two-epoch pin. **Phase 9.** |
| Executes stdio MCP servers | **VERIFIED security warning.** Lab must export **static JSON** or a stub; do not auto-exec untrusted commands. |

**8C/optional strategy:** CALL EXTERNALLY only against the **lab fixture** (prefer static/export). IMPORT OUTPUT. Do not require `SNYK_TOKEN` for core. Treat CLI field names as unstable.

When docs say “Invariant mcp-scan,” AgentSec means: **the TPA research + the scanner lineage now published as Snyk Agent Scan**. Do not invent a frozen `mcp-scan` CLI that no longer lives at that URL.

---

## Comparison (for the lab, not a bake-off UI)

| | Cisco mcp-scanner | Invariant lineage / Agent Scan |
|--|-------------------|--------------------------------|
| Description / TPA-shaped findings | LLM **TOOL POISONING**; YARA prompt injection | **prompt_injection_tool_desc** / Tool Poisoning codes |
| Static JSON | **VERIFIED** `static --tools` | Prefer not to start stdio in the lab |
| Rug-pull pin | Not verified | Blog recommends pinning; product pin **deferred to Phase 9** |
| Runtime authz | Never | Never |

Do **not** rebuild either scanner. Educational gap is AgentSec’s **INV-002 overlay + evidence**, not another YARA engine.
