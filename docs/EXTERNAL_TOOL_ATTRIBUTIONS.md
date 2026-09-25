# External tool attribution

AgentSec is an independent learning range. Inclusion here does not imply
affiliation, sponsorship, certification, or endorsement by an external project.

## Cisco mcp-scanner

| Field | Attribution |
|---|---|
| TOOL | Cisco AI Defense MCP Scanner (`cisco-ai-mcp-scanner`) |
| OFFICIAL REPOSITORY (PIN METADATA) | https://github.com/cisco-ai-defense/mcp-scanner |
| CLASSIFICATION | STATIC / CATALOG SECURITY FINDING |
| VERSION PINNED | 4.8.4 |
| HOW AGENTSEC USES IT | Runs a bounded local static YARA scan over an exported teaching catalog, preserves native output, normalizes class `finding`, and sends pack-derived events to Splunk |
| BUILT BY AGENTSEC | ExternalEvidence contract, adapter, pack/HEC integration, searches, and learning content |
| INTEGRATED BY AGENTSEC | The pinned external scanner CLI and its native output |
| TAUGHT / REFERENCED BY AGENTSEC | Upstream project identity, analyzer behavior, native result fields, and license metadata |
| LIMITATIONS | Static result for defined catalog bytes and analyzer configuration; not exploitation, authorization, execution, causality, or safety |
| EXTERNAL STATUS | `NEEDS_EXTERNAL_VALIDATION` for current upstream license and native JSON format stability |

## garak

| Field | Attribution |
|---|---|
| TOOL | garak |
| PROJECT | garak — Generative AI Red-teaming & Assessment Kit / “the LLM vulnerability scanner” |
| OFFICIAL REPOSITORY | https://github.com/NVIDIA/garak |
| VERSION TESTED | 0.17.0 |
| LICENSE | Repository metadata records Apache-2.0; current upstream license remains `NEEDS_EXTERNAL_VALIDATION` |
| PURPOSE | Probe generative-AI systems and evaluate model responses with garak’s native probes and detectors |
| HOW AGENTSEC USES IT | Runs one bounded probe against a local Ollama model, preserves the native JSONL report, normalizes one `evaluation` record, and sends that record to Splunk for investigation |
| INTEGRATION CLASS | External adversarial evaluation |
| LIMITATIONS | One local model, one DAN probe, one generation, one detector; no universal safety, exploit, runtime-tool, or authorization conclusion |

**Project credit:** garak is the work of its creators, maintainers, and
contributors. Installed package metadata for 0.17.0 identifies Leon Derczynski,
Subho Majumdar, Erick Galinkin, and Jeffrey Martin as maintainer contacts and
credits the broader contributor community. Current authors and contributors are
maintained by the project at https://github.com/NVIDIA/garak.

### Responsibility boundary

- **INTEGRATED BY AGENTSEC:** isolated installation instructions, adapter,
  evidence pack, HEC event, Splunk searches, and Tool Lab.
- **BUILT BY AGENTSEC:** `ExternalEvidence` 1.0.0 and AgentSec learning content.
- **REFERENCED / TAUGHT BY AGENTSEC:** garak’s native probe, detector, report,
  result, tags, and independent CLI workflow.
- **NOT BUILT BY AGENTSEC:** garak itself, the DAN probe, the DAN detector, the
  Ollama generator plugin, and garak’s scoring/reporting logic.

AgentSec does not rename garak behavior as AgentSec functionality.
