# AgentSec build vs integrate

**Status:** Phase 8A DESIGN.

Parents: `docs/AGENTSEC_OPEN_SOURCE_SECURITY_ECOSYSTEM.md`, `docs/AGENTSEC_EXPANSION_ARCHITECTURE.md`.

AgentSec original engineering stays on:

- security-property modeling
- safe reproducible labs
- control placement (decision **before** dangerous op)
- telemetry and evidence
- investigation / detection reasoning
- learning experience

Rebuild a scanner, eval harness, or BOM tool only if AgentSec would add a **security or research** property the upstream project lacks.

---

## Matrix

| Capability | Build or integrate? | Strategy | Notes |
|------------|---------------------|----------|-------|
| Reference controls (CTRL-*) | **BUILD** | — | Teaching placement. Do not replace with DefenseClaw/LlamaFirewall as the bank. |
| Safe MCP/LLM fixtures | **BUILD** | — | No real RCE, no live third-party MCP in core. |
| Schema / OTel export / evidence packs | **BUILD** | — | Closed schema; honesty labels. |
| Splunk hunts / workshops | **BUILD** | — | After field contract. |
| MCP tool/server scanning | **INTEGRATE** | CALL EXTERNALLY + IMPORT OUTPUT | Cisco mcp-scanner and/or Invariant mcp-scan. Compare outputs as evidence, not as competing products in a UI. |
| Agent skill scanning | **INTEGRATE** | CALL EXTERNALLY | skill-scanner when a skill lab exists. |
| AI BOM | **INTEGRATE** | IMPORT OUTPUT | cisco-aibom. Inventory ≠ authorization. |
| DefenseClaw gateway | **DO NOT** embed | REFERENCE / optional overlay later | Would collapse AgentSec into OpenClaw ops. |
| Foundation-Sec | **WRAP** optional | Optional Ollama model | Hunt-assist copy. Not a control. |
| Antares | **DO NOT** | REFERENCE | Code vuln localization. |
| Garak / PyRIT / Promptfoo | **INTEGRATE** as oracles/fixtures | CALL EXTERNALLY / USE AS TEST ORACLE | Map hits to invariants; do not auto-DENY. |
| NeMo / Guardrails AI / LlamaFirewall | **REFERENCE** then optional WRAP | Comparison lab | Second control in `teach` mode only after tests. |
| A2A protocol | **INTEGRATE** protocol, **BUILD** lab | Later | Use a2aproject spec; build identity check + telemetry. |
| a2a-scanner | **INTEGRATE** | CALL EXTERNALLY after A2A lab | |
| RAG / memory stores | **BUILD** tiny fixtures | — | Do not import a vector DB platform. |
| Hubness detector | **INTEGRATE** | When RAG exists | |
| Pickle/model provenance | **INTEGRATE** | pickle-fuzzer / model-provenance-kit | |
| Splunk AI Toolkit / CDTSM | **OPTIONAL ENTERPRISE** | CALL EXTERNALLY in Splunk | After metrics exist. |
| ES notables | **OPTIONAL ENTERPRISE** | — | Never required. |
| LiteLLM / LangChain / ADK | **DO NOT** | — | Wrong application stack. |

---

## Differentiation (evidence-based, not marketing)

| Theme | Common in OSS | AgentSec combination | Current gap | Future opportunity |
|-------|---------------|----------------------|-------------|--------------------|
| Attack reproduction | Garak, PyRIT, Promptfoo, AgentDojo | **Runtime control + spy-proven DENY-before-op** | Few generator integrations | Import fixtures into Attack Service without becoming a scanner UI |
| Defense | Guardrails, LlamaFirewall, DefenseClaw | **Labeled vulnerable vs defended profiles** | Teaching regex/allow-list only | Optional WRAP comparison |
| Runtime authorization | MCP gateways, DefenseClaw | **Coded CTRL-* with attempted/executed/outcome honesty** | Not production IAM | Keep teaching; don’t fake IAM |
| Telemetry | OTel GenAI, MCP SDK spans | **Closed security_event schema + completeness vs events.jsonl** | One sourcetype | Scanner sourcetype; A2A events |
| SOC investigation | Sparse in red-team tools | **Splunk-first hunts, no-data semantics, Studio workshops** | One detector | Hunt library + gated detections |
| Evidence bundles | Rare | **artifacts/<run-id>/** with expected vs actual | No scanner packs | Attach imported JSON with class labels |
| Learning progression | Eval leaderboards | **Ten-step workshop per property** | Levels 2–8 empty | Catalog poisoning next |
| Enterprise observability | Cisco/Splunk commercial | **Optional overlay; core independent** | Overlay not built | Teach-mode only |
| Behavioral analytics | CDTSM, MLTK | **Not started (correct)** | No metrics | After event-derived counters |

**Differentiating combination (supported by this repo):** reproducible agent attacks **and** reference controls **and** honest telemetry **and** Splunk investigation **and** evidence packs **and** a workshop that refuses “zero rows = safe.”

That combination is uncommon. Individual pieces (Garak, mcp-scanner, OTel) are common. Do not claim uniqueness for scanning or for prompt injection as a class.

---

## Anti-patterns

- A page of buttons that open GitHub READMEs
- `cisco_*=FAIL` in events when no scanner ran
- Rebuilding mcp-scanner inside AcmeBank
- Using Antares or Foundation-Sec as the authorization oracle
- Promoting every hunt to DET-MCP-00N
