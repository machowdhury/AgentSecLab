# AgentSec Lab

AgentSec is a **hands-on agentic-security learning range**. You run controlled experiments against a vulnerable or defended educational agent, then investigate the evidence in Splunk.

Splunk is the investigation workbench. AcmeBank is where authorization and reference controls run. The Attack Service is a closed educational launcher on localhost. Splunk does **not** become the policy decision point because events are indexed there.

**Release status:** v1.0.0-rc1 candidate (product version). Telemetry schema remains **1.9.0**. This is not a production security product.

## Who is it for

Technically capable learners, instructors, SOC analysts, and security architects who want a **local** lab—not a production AI-security product.

## Getting started

Follow [docs/QUICKSTART.md](docs/QUICKSTART.md) (also [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)). Curriculum: [docs/AGENTSEC_RELEASE_LAB_MATRIX.md](docs/AGENTSEC_RELEASE_LAB_MATRIX.md). After start, open Academy Home: http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home

## Why it exists

Agentic systems mix untrusted text, tools, retrieved documents, memory, and delegated work. AgentSec teaches you to reconstruct what happened, name the trust boundary, and distinguish:

- request vs grant
- classification vs authorization
- authorization vs execution
- LIVE evidence vs REPLAY specimens
- a missing Splunk row vs a blocked action

## What you will learn

A published Academy curriculum: Direct Prompt Injection, MCP tool authorization, RAG/memory context, goal integrity, identity/delegation, REPLAY workshops, an integrated Capstone, and a Mastery Check. Details: [docs/AGENTSEC_RELEASE_LAB_MATRIX.md](docs/AGENTSEC_RELEASE_LAB_MATRIX.md).

## Architecture (actual v1.0)

```text
Learner
    ↓
Splunk Dashboard Studio Academy
    ↓
Attack Service (closed launch contract, localhost)
    ↓
AcmeBank runtime (controls / PDP)
    ↓
OpenTelemetry → collector → Splunk HEC
    ↓
Splunk Search / evidence reconstruction
```

Full picture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Security limits: [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md).

## What you need

Docker (Compose v2), Git, a browser, this repository. Hardware minimums are **NOT BENCHMARKED**. Copy [`.env.example`](.env.example) to `.env` once. Never commit `.env`.

See [docs/QUICKSTART.md](docs/QUICKSTART.md) and [docs/AGENTSEC_PREREQUISITES.md](docs/AGENTSEC_PREREQUISITES.md).

## How to start

From the repository root:

```bash
./scripts/lab-preflight.sh
cp .env.example .env          # once; do not commit .env
./scripts/lab-up.sh           # first Splunk boot can take 10–20 minutes
./scripts/lab-ready.sh        # SERVICE HEALTH, not searchable evidence
```

After READY:

| URL | What it is |
|-----|------------|
| http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home | AgentSec Academy Home (start here) |
| http://127.0.0.1:5001 | Attack Service (LIVE launch) |
| http://127.0.0.1:5000/health | AcmeBank health |

Do not publish these ports to untrusted networks. Attack Service is unauthenticated by design.

## Local Docker lab vs External Splunk

The commands above start the **local Docker lab**. **External Splunk** is not started by `lab-up.sh`; you would supply HEC yourself. Details: [docs/LOCAL_DOCKER_LAB.md](docs/LOCAL_DOCKER_LAB.md).

## After startup

1. Open Academy Home. Read ORIENT. Understand **LIVE** vs **REPLAY**.
2. Open **Direct Prompt Injection**. Predict, then launch ATTACK from Attack Service.
3. Copy the fresh `run.id`. Investigate in Splunk Search (Path A). Path B is an answer key.
4. DEFEND / RETEST / COMPARE / PROVE as the lab teaches.
5. Continue the curriculum to Capstone and Mastery Check.

## LIVE vs REPLAY

**LIVE** means the runtime executed now and minted a new `run.id`. **REPLAY** is a canonical historical specimen used for teaching. A REPLAY dashboard is not proof that you just executed that attack. [docs/LIVE_VS_REPLAY.md](docs/LIVE_VS_REPLAY.md).

## Stop and reset

| Intent | Command |
|--------|---------|
| Soft stop (keep evidence) | `./scripts/lab-down.sh` |
| Start again | `./scripts/lab-up.sh` |
| Rebuild app images | `./scripts/lab-up.sh --build` |
| Restage Splunk XML | `./scripts/lab-up.sh --refresh-app` |
| Full reset (destroys volumes) | explicit `docker compose … down -v` — see [docs/OPERATIONS.md](docs/OPERATIONS.md) |

## Troubleshooting

[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). A missing Splunk row is not automatically “the attack was blocked.”

## Security limitations

AgentSec **intentionally contains vulnerable educational behavior**. It is for controlled local learning. It is not a production gateway, PDP, SIEM content pack, identity platform, or certification program. [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Deeper docs

| Doc | Use |
|-----|-----|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Linear first run |
| [docs/AGENTSEC_V1_PRODUCT_BOUNDARY.md](docs/AGENTSEC_V1_PRODUCT_BOUNDARY.md) | What v1.0 is / is not |
| [docs/INSTRUCTOR_GUIDE.md](docs/INSTRUCTOR_GUIDE.md) | Workshop preparation |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Learner vs developer workflow |
| [CHANGELOG.md](CHANGELOG.md) | Product changelog |
| [docs/releases/V1_0_0_RC1_RELEASE_NOTES.md](docs/releases/V1_0_0_RC1_RELEASE_NOTES.md) | RC1 notes |
| [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) | Historical phase provenance |

Developer tests (optional; not required to learn):

```bash
uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
```
