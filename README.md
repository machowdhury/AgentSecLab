# AgentSec Lab

AgentSec is an **agentic security academy**: a local, hands-on lab for learning agentic security, security fundamentals, Splunk investigation, blue-team reasoning, threat modeling, privacy, and evidence-based analysis.

You run controlled experiments against an educational agent, then investigate the evidence in Splunk. AcmeBank is where reference controls run. The Attack Service is a closed educational launcher on localhost. Splunk is the investigation workbench. Splunk does **not** authorize tools.

## Who it is for

Technically capable learners, instructors, SOC analysts, and security architects who want a **local** lab. Some security background helps. You do not need to already know agents, RAG, or Splunk search language. The early labs teach those ideas on purpose.

## What you will learn

The Academy on this branch runs from orientation through an advanced investigation:

```text
Orientation and foundations
        ↓
Controlled security labs (input and tool authority)
        ↓
RAG, memory, goal, and identity
        ↓
External security evidence
        ↓
Blue-team investigation
        ↓
Threat modeling
        ↓
Privacy and data governance
        ↓
Multi-stage incident investigation
        ↓
Advanced Capstone, then an optional Mastery Check
```

Level names and what each one asks you to do are in [Academy L0-L10](#academy-l0-l10). The exercise table is [docs/AGENTSEC_RELEASE_LAB_MATRIX.md](docs/AGENTSEC_RELEASE_LAB_MATRIX.md).

## Current repository and release status

Two git refs matter. They are not the same product snapshot.

| Ref | What it is |
|-----|------------|
| `main` and annotated tag `v1.0.0-rc1` | Earlier RC1 baseline. The tag peels to commit `e6115b6d1c03a1672b4364e84748c7840671fbfc`. That snapshot does **not** contain the L6–L10 academy. |
| annotated tag `v1.0.0-rc2` | Previous L0–L10 candidate. It stays on its original commit. |
| `develop` | Current release candidate, v1.0.0-rc3. This is the L0–L10 academy plus the bounded REPLAY workshops after RC2. |

`develop` is the v1.0.0-rc3 candidate, not final `v1.0.0`. Annotated tag `v1.0.0-rc2` was not moved.

Package metadata is `1.0.0rc3` in `pyproject.toml`. The Splunk app version is `1.0.0-rc3`. Those strings name this candidate. They do not mean `main` moved.

Telemetry schema remains **1.9.0**. The external-evidence contract remains **1.0.0**.

A default `git clone` follows `origin/HEAD`, which is `main` (RC1). To study the academy described here, check out `develop`. Tag `v1.0.0-rc2` is the previous candidate. Tag `v1.0.0-rc3` is created only when this candidate's release gate passes.

Clean-room installation has **not** been proven. The commands below are the documented path. They have been used on existing lab machines. That is not a measurement that a new machine with empty volumes succeeds.

## Prerequisites

Docker (Compose v2), Git, and a browser. Hardware minimums are **NOT BENCHMARKED**. Copy [`.env.example`](.env.example) to `.env` once. Never commit `.env`.

Details: [docs/AGENTSEC_PREREQUISITES.md](docs/AGENTSEC_PREREQUISITES.md).

## Quick start

From the repository root, on `develop`:

```bash
./scripts/lab-preflight.sh
cp .env.example .env          # once; do not commit .env
./scripts/lab-up.sh           # first Splunk boot can take 10–20 minutes
./scripts/lab-ready.sh        # service health; MODEL ABSENT means LIVE is degraded
```

The Ollama container tries to pull `llama3.2:1b` on startup. If that pull fails, AcmeBank health stays degraded. REPLAY workshops do not need the model. A certificate error has to be fixed at the trust layer. Do not disable certificate verification.

Linear detail: [docs/QUICKSTART.md](docs/QUICKSTART.md). Short pointer: [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md).

Service health means the services answer. It does not mean a `run.id` is searchable, and it does not mean the Ollama model is present. An HEC HTTP 200 is not indexed evidence. `MODEL ABSENT` means LIVE generation is degraded.

| URL | What it is |
|-----|------------|
| http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home | Academy Home (start here) |
| http://127.0.0.1:8000 | Splunk login (`admin`; password from `.env`) |
| http://127.0.0.1:5001 | Attack Service (LIVE launch only) |
| http://127.0.0.1:5000/health | AcmeBank health |

Do not publish these ports to untrusted networks. Attack Service is unauthenticated by design.

The commands above start the **local Docker lab**. **External Splunk** is not started by `lab-up.sh`. Details: [docs/LOCAL_DOCKER_LAB.md](docs/LOCAL_DOCKER_LAB.md).

## First lab

1. Open Academy Home. Read orientation. Confirm you are on the L0–L10 path, not a shorter RC1 description.
2. Open **Direct Prompt Injection** (L1). Predict before you launch.
3. On Attack Service, launch that lab in **ATTACK** mode with execution **live**.
4. Copy the fresh `run.id` from **this** launch.
5. In Splunk Search, investigate that id (Path A). A starter constraint is in the quickstart.
6. Read the lab’s ATTACK and RETEST comparison as a controlled pair, not as proof the system is safe or fully compromised.
7. Continue in Academy order. Do not stop at the L5 Capstone. Complete the Splunk Defender Bridge, then L6 through L10 and the optional Mastery Check.

Workshop pages may show canonical specimen ids. Those are REPLAY or reference evidence. They are not the launch you just executed. Use the `run.id` Attack Service minted for this session.

## LIVE, REPLAY, static reasoning, and simulated data

**LIVE.** A fresh supported execution is launched and produces new runtime evidence, including a new `run.id`. Seven labs can be launched. The count comes from the Attack Service allowlist, not from the number of Academy pages.

**REPLAY.** You investigate previously captured or canonical evidence. A REPLAY page is not proof that you just ran that attack.

**Static / reasoning.** You analyze architecture, controls, privacy, or a threat model without claiming a fresh attack. L0 orientation and L4 investigation craft are this kind of work. L7 is architecture reasoning and does not launch an attack.

**Simulated.** Several LIVE labs use fixture-backed or in-process data (retrieved documents, memory, identity claims) to teach a bounded idea. A fixture is not a production system, and it is not proof of a real customer incident.

Full note: [docs/LIVE_VS_REPLAY.md](docs/LIVE_VS_REPLAY.md).

## Academy L0-L10

Names below are the curriculum titles. Menus use shorter collection labels. “Capstone” in the menu is **L5 only**.

| Level | Curriculum title | What you do | Launch? |
|-------|------------------|-------------|---------|
| L0 | Orientation | Learn what AgentSec is, what LIVE means, and what Splunk does not do. | No. This is Academy Home. |
| L1 | Input and tool authority | See that untrusted input can influence an agent, and that a tool request is not a grant. | Yes for Direct Prompt Injection and Tool Authorization. Scope and parameter workshops are REPLAY. |
| L2 | Context and evidence are data | See that retrieved content, memory, scanner findings, and model evaluations inform an investigation and do not mint grants. | Yes for RAG and Memory. Tool result, catalog, scanner, and garak workshops are REPLAY. |
| L3 | Intent and identity | Separate an authorized tool from an authorized goal, and an identity claim from authentication. | Yes for Goal and Identity. Confused Deputy is REPLAY. |
| L4 | Investigation craft | Practice hunt versus detection and evidence quality on LIVE Path A. Zero rows is not safe. | No separate workshop. |
| L5 | Integrated purple team | **L5 Capstone:** Lending Assistant Investigation. Reconstruct a chain you launch. | Yes. Last LIVE launcher. |
| Checkpoint | Splunk Defender Bridge | Investigate tool-authorization evidence without a supplied run identifier. Then continue to L6. | No. REPLAY / static. Not an eighth LIVE lab. |
| L6 | Blue-team investigation and threat hunting | Investigate AcmeBank Incident AI-2026-001 from incomplete evidence. | No. REPLAY. |
| L7 | Threat modeling and security architecture | Model an unfamiliar agentic system and state residual risk. | No. Reasoning. No fresh attack. |
| L8 | Privacy, data protection and agentic data governance | Separate an authorized action from an appropriate use of data. | No. REPLAY investigation. |
| L9 | Multi-stage agentic attack, investigation and defense | Investigate Acme Bank Incident AGENT-2026-009. | No. REPLAY. |
| L10 | Advanced capstone and mastery | **Advanced Capstone:** Acme Bank Capstone MASTER-2026-001. Investigate without starting from a run id. | No. REPLAY. |

**Mastery Check** is a separate, unscored self-check (`ws_agentsec_mastery`). It is not the L5 Capstone and not the L10 Advanced Capstone. It does not certify you.

The seven LIVE labs, and only these, are on the Attack Service allowlist:

`LAB-PI-001`, `LAB-MCP-001`, `LAB-RAG-CONTEXT`, `LAB-MEMORY-001`, `LAB-AGENT-GOAL-INTEGRITY-001`, `LAB-AGENT-DELEGATION-001`, `LAB-AGENTSEC-CAPSTONE-001`.

## Splunk’s role

Splunk is where you search, correlate, reconstruct, compare, investigate, hunt, and practice detection thinking.

Splunk is not CTRL-MCP-001. It is not the tool authorization decision point. Zero rows do not prove an event never happened and do not prove safety. HEC acceptance does not prove the evidence set is complete.

## External security evidence

Cisco **mcp-scanner** (Cisco AI Defense) and **garak** (NVIDIA) are third-party tools. AgentSec did not build them. The lab imports their output as adjacent evidence:

```text
external tool → adapter → ExternalEvidence → Splunk → learner investigation
```

A scanner finding does not authorize or deny a tool. A HIGH finding is not a DENY. Zero findings are not safe. A garak pass is not proof the runtime is safe. Detail: [docs/EXTERNAL_SECURITY_EVIDENCE.md](docs/EXTERNAL_SECURITY_EVIDENCE.md).

## Security semantics

These words are bounded on purpose.

| Word | Meaning here | What it does not mean |
|------|----------------|------------------------|
| ATTACK | A vulnerable or attack-condition experiment | Universal compromise |
| RETEST | A controlled defended comparison | The system is universally safe |
| BASELINE | An expected or legitimate comparison | Trusted forever, or the absence of risk |
| OBSERVE | A control recorded what it saw | Authorization, or the same thing as ALLOW |
| ALLOW | A control permitted a requested action in this lab | The action succeeded, or the outcome was safe |
| DENY | A control refused a request it is responsible for | The whole system is safe |

CTRL-MCP-001 is the tool policy decision point. RAG and memory observations do not mint tool grants. External evidence does not mint tool grants. Goal control can refuse a task expansion; that refusal is not itself a tool grant.

Two evidence vocabularies answer different questions. **MEASURED, OBSERVED, TESTED, DOCUMENTED, REPLAYED, SIMULATED** describe how evidence was obtained. **PROVEN, SUPPORTED, INFERRED, NOT OBSERVED, NOT MODELED, NOT PROVEN, REFUTED** describe how strongly an investigative claim is supported. Correlation is not causation.

Deeper picture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md).

## What AgentSec is not

AgentSec is not evidence of production security effectiveness, complete AI governance, compliance certification, production IAM, production non-human identity, production agent-to-agent identity, cryptographic delegation, universal attack prevention, or complete privacy compliance.

Path B is visible. It is pedagogical guidance, not access control. Early mission cards may state an expected outcome; that is a known learning-design limit, not a hidden answer key behind a lock.

Boundaries: [docs/AGENTSEC_V1_PRODUCT_BOUNDARY.md](docs/AGENTSEC_V1_PRODUCT_BOUNDARY.md).

## Known limitations

- Path B is intentionally learner-accessible. Studio does not hide it.
- This academy is not a certification. Mastery Check is unscored. L10 does not certify you.
- Clean-room installation is not proven.
- Screen-reader coverage is partial and not fully tested. That is not a WCAG conformance claim.
- Production authentication and cryptographic delegation are not modeled.
- One RETEST does not prove universal effectiveness.
- A missing Splunk row is not automatically “the attack was blocked.”

List: [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

## Stop and reset

| Intent | Command |
|--------|---------|
| Soft stop (keep evidence) | `./scripts/lab-down.sh` |
| Start again | `./scripts/lab-up.sh` |
| Rebuild app images | `./scripts/lab-up.sh --build` |
| Restage Splunk XML | `./scripts/lab-up.sh --refresh-app` |
| Full reset (destroys volumes) | explicit `docker compose … down -v` — see [docs/OPERATIONS.md](docs/OPERATIONS.md) |

Troubleshooting: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Deeper documentation

| Doc | Use |
|-----|-----|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Linear first run |
| [docs/AGENTSEC_RELEASE_LAB_MATRIX.md](docs/AGENTSEC_RELEASE_LAB_MATRIX.md) | Exercise modes and outcomes |
| [docs/AGENTSEC_V1_PRODUCT_BOUNDARY.md](docs/AGENTSEC_V1_PRODUCT_BOUNDARY.md) | What the lab is and is not |
| [docs/INSTRUCTOR_GUIDE.md](docs/INSTRUCTOR_GUIDE.md) | Workshop preparation |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Learner vs developer workflow |
| [CHANGELOG.md](CHANGELOG.md) | Product changelog |
| [docs/releases/V1_0_0_RC2_RELEASE_NOTES.md](docs/releases/V1_0_0_RC2_RELEASE_NOTES.md) | Current candidate notes |
| [docs/releases/V1_0_0_RC1_RELEASE_NOTES.md](docs/releases/V1_0_0_RC1_RELEASE_NOTES.md) | Historical RC1 notes for the tagged baseline |
| [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) | Historical phase provenance |

Developer tests are optional and are not required to learn:

```bash
uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
```
