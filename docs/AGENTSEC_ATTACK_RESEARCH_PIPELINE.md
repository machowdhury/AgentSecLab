# AgentSec attack research pipeline

**Status:** Phase 8A DESIGN. Not implemented.  
**Purpose:** Teach how a new agent-security idea becomes defensible SOC evidence — not only how to replay ATK-002.

Parents: `docs/AGENTSEC_EXPANSION_ARCHITECTURE.md`, `.cursor/rules/50-research-integrity.mdc`, `.cursor/rules/20-security.mdc`.

---

## Two teaching tracks

| Track | What the learner practices | Rule |
|-------|----------------------------|------|
| **A. Established classes** | Direct prompt injection, unauthorized tool, scope/resource abuse, result-as-authority, confused deputy | Map only to frameworks that actually describe the property. Label ESTABLISHED. |
| **B. Emerging / research** | Tool-description poisoning, A2A spoofing, memory poisoning, rug-pull MCP servers | Label EMERGING or EXPERIMENTAL. An AgentSec-only idea is **AGENTSEC HYPOTHESIS** until reproduced. |

Never present an AgentSec hypothesis as an industry-established technique.

---

## Repeatable pipeline

```text
DISCOVER
→ SOURCE
→ REPRODUCE
→ MINIMIZE
→ MODEL SECURITY PROPERTY
→ BUILD SAFE FIXTURE
→ INSTRUMENT
→ ATTACK
→ OBSERVE
→ HUNT
→ DEFEND
→ RETEST
→ DETECTION ANALYSIS
→ TEACH
```

| Step | Meaning in AgentSec | Stop if |
|------|---------------------|---------|
| DISCOVER | Paper, blog, CVE, scanner finding, SOC question | Source is rumor only |
| SOURCE | URL, authors, date, license | Cannot cite |
| REPRODUCE | Recreate the property in a **safe** lab (no real RCE, no real customer data) | Reproduction needs production credentials or unconstrained shell |
| MINIMIZE | Smallest fixture that still shows the property | Fixture still needs the internet by default |
| MODEL SECURITY PROPERTY | Name invariant, trust boundary, attacker-controlled input, dangerous operation | Cannot state the property in one sentence |
| BUILD SAFE FIXTURE | Deterministic tool/RAG/A2A stub | Fixture is a live third-party MCP server |
| INSTRUMENT | Events before/after the control; evidence pack | Would require inventing fields |
| ATTACK | `testbed.mode=ATTACK`, profile `vulnerable` then `defended` | Attack is only a dashboard story |
| OBSERVE | Runtime facts: decision, attempted, executed, outcome | |
| HUNT | Splunk question after field discovery | TELEMETRY GAP — QUERY NOT DEFENSIBLE |
| DEFEND | Control change, same payload | Defense is “don’t look at Splunk” |
| RETEST | Same payload, `RETEST` | |
| DETECTION ANALYSIS | Hunt vs detection gate | Do not publish DET-* because the phase number exists |
| TEACH | Workshop LEARN→PROVE; SIMULATED labeled | |

Evidence classes on every artifact: OBSERVED / MEASURED / DOCUMENTED / INFERRED / SIMULATED / REPLAYED.

---

## Technique record (required fields)

For every AgentSec technique:

| Field | Rule |
|-------|------|
| AgentSec technique ID | Stable lab id (`ATK-002`, `MCP-006`, future `MCP-CATALOG-001`, …) |
| External framework mapping | Only if the framework text matches. Else `UNMAPPED` + reason |
| OWASP | LLM 2026 and/or ASI 2026 ids when applicable |
| MITRE ATLAS | Current ATLAS id after revalidation. Do not copy stale ids |
| CWE / CAPEC | Only when the weakness is actually that CWE |
| Source / research reference | URL or paper |
| Attack maturity | ESTABLISHED / EMERGING / EXPERIMENTAL / AGENTSEC HYPOTHESIS |
| Evidence class used in the lab | SIMULATED / OBSERVED / MEASURED |

### Current AgentSec techniques (as implemented)

| ID | Property | OWASP (honest) | ATLAS | CWE | Maturity | Evidence |
|----|----------|----------------|-------|-----|----------|----------|
| ATK-001 | Benign loan | — | — | — | ESTABLISHED (benign) | MEASURED |
| ATK-002 | Direct prompt injection vs CTRL-INPUT-001 | LLM01:2026; ASI01 (goal hijack via prompt) | Historically coded `AML.T0054`. **Revalidate:** public 2026 ATLAS materials list **AML.T0051** as LLM Prompt Injection (`.000` Direct). Do not silently remap in 8A. | CWE-74-like injection teaching only; do not claim a CVE | ESTABLISHED | MEASURED (runtime) |
| MCP-001 | Authorized tool | ASI02 (authorized use) | Unmapped until ATLAS tool-use id is confirmed | — | ESTABLISHED | MEASURED |
| MCP-002 | Unauthorized tool | ASI02 / LLM03:2026 Excessive Agency (over-grant in vulnerable profile) | Historically `AML.T0050`. **Revalidate:** AML.T0050 is Command and Scripting Interpreter in current materials — **not** MCP allow-list. Treat existing mapping as **stale / needs review**. | CWE-863 Incorrect Authorization (legitimate) | ESTABLISHED | MEASURED |
| MCP-003 | Scope escalation | ASI03 / INV-001 | Same stale `AML.T0050` note | CWE-863 | ESTABLISHED | MEASURED |
| MCP-004 | Resource / parameter authorization | ASI03 | Same note | CWE-863 | ESTABLISHED | MEASURED |
| MCP-005 | Result-derived authority | LLM01 indirect-ish; **ASI01/ASI02**; INV-002 | Unmapped (no honest “tool result is grant” ATLAS id confirmed here) | — | ESTABLISHED (property); lab fixture is AgentSec-specific | MEASURED |
| MCP-006 | Confused deputy / ambient authority | ASI03 Identity and Privilege Abuse | CAPEC-59 / CWE-441 Unintended Proxy/Confused Deputy are legitimate **analogies**. No ATLAS confused-deputy id confirmed in this pass. | CWE-441 | ESTABLISHED class; AgentSec hop is a teaching model | MEASURED |

Do not invent ATLAS ids for MCP-005/006.

### Candidate future techniques (not labs yet)

| Working name | Maturity | Likely OWASP | Source to reproduce | Safe fixture idea |
|--------------|----------|--------------|---------------------|-------------------|
| MCP tool-description poisoning | EMERGING | ASI02 (interface poison) or ASI04 if the server is malicious at source | Invariant Labs MCP-scan / tool poisoning writeups; Cisco mcp-scanner taxonomy | Coded malicious `description` string in a fixture catalog; no network |
| MCP rug-pull (description hash change) | EMERGING | ASI04 | Invariant tool pinning | Two catalog versions, same tool name |
| Indirect PI via retrieved doc | ESTABLISHED class | LLM01; ASI01; ASI06 if stored | Classic indirect injection papers | RAG fixture file, not the public web |
| Memory poisoning | EMERGING as agent-memory | ASI06 | OWASP ASI06 | Trust-tagged store |
| A2A Agent Card spoof | EMERGING | ASI07 | a2aproject spec 1.0.0 | Fake Agent Card JSON, coded identity check |
| Package/model pickle | ESTABLISHED (ML supply chain) | LLM04:2026 | Cisco pickle-fuzzer / ModelScan | Harmless pickle that *would* exec; do not execute untrusted pickle in core |

---

## Framework honesty

OWASP LLM Top 10 **2026** (verified from genai.owasp.org PDF): LLM01 Prompt Injection … LLM10 Improper Output Handling. Excessive Agency is **LLM03:2026**.

OWASP Agentic (ASI) **2026**: ASI01 Goal Hijack, ASI02 Tool Misuse, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.

ATLAS pages `atlas.mitre.org/techniques/AML.T0051` returned **404** in this research pass. Mappings that depend on ATLAS must be re-fetched from the current ATLAS navigator before a workshop teaches an id. Secondary 2026.07 reproductions were used only to **flag** AgentSec’s existing T0054/T0050 codes for review — not to rewrite `experiment.py` in 8A.

---

## Detection analysis (end of pipeline)

A reproduced attack is a **hunt** first.

Publish a detection only after `.cursor/rules/33-splunk-agent-skills.mdc` detection gate. Otherwise:

`DETECTION ANALYZED — DO NOT PUBLISH`  
or  
`DETECTION BLOCKED BY TELEMETRY GAP`
