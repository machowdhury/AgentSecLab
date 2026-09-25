# External tool attribution

AgentSec is an independent learning range. Inclusion here does not imply
affiliation, sponsorship, certification, or endorsement by an external project.

## garak

| Field | Attribution |
|---|---|
| TOOL | garak |
| PROJECT | garak — Generative AI Red-teaming & Assessment Kit / “the LLM vulnerability scanner” |
| OFFICIAL REPOSITORY | https://github.com/NVIDIA/garak |
| VERSION TESTED | 0.17.0 |
| LICENSE | Apache License 2.0 — https://github.com/NVIDIA/garak/blob/main/LICENSE |
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
