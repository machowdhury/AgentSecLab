# AgentSecLab

**A hands-on lab for learning how AI agents fail, how to investigate them in Splunk, and how to turn the evidence into an evaluation, a risk assessment and a governance record.**

AgentSecLab runs a small, deliberately simple bank assistant (AcmeBank) that you attack in controlled experiments, then investigate with real telemetry. Nothing in it is a production system. Everything it shows says whether it was run live, replayed from a committed recording, simulated, or only documented.

## Who it is for

Security learners, instructors running a workshop, SOC analysts and security architects who want a local, reproducible place to practise agentic AI security. You do not need to know agents or Splunk search first.

## What you can do

| Step | Where | What it is |
|------|-------|-----------|
| Learn and practice | `/learn` (32 labs) | Guided experiences on prompt injection, tool authorization (MCP), RAG, memory, identity and delegation, scanner and model evaluations, Splunk investigation, threat modeling and privacy |
| Attack | Attack Service (port 5001) | A closed launcher that runs educational attacks against AcmeBank |
| Investigate | Splunk (port 8000) | Dashboards and searches over the telemetry each run produces |
| Evaluate | `/learn/evals` | Recorded and simulated experiments, test cases, findings, comparisons and a report export |
| Assess risk | `/learn/risk` | Source-backed risks you assess yourself, with a qualitative method and a browser-local draft |
| Map controls | `/learn/governance` | Framework relationships, controls, evidence and gaps, with an export |
| Prove | each page | Source files, SHA-256 hashes, limitations and verification status |

## Release status: read this first

- `main` (tag `v1.1.0`) is the released academy served from the original pages.
- The React Academy shell, the Security Assurance workshop, the EVAL Center, the Risk Center and the Governance Center are on the **`feature/academy-react-shell`** development branch. They are not on `main` yet.
- The browser experience of the deployed development branch has **not** been tested in a real browser by the maintainers. Tests ran in headless Chromium against a local build.

## Quick start

You need Docker Engine with Compose v2, Git, `python3`, `curl` and a browser. Podman is **not validated**. Windows is **not validated**. Hardware minimums are **NOT BENCHMARKED**. Details: [Quickstart](docs/QUICKSTART.md), [Getting started](docs/GETTING_STARTED.md), [Troubleshooting](docs/TROUBLESHOOTING.md).

```bash
git clone https://github.com/machowdhury/AgentSecLab.git
cd AgentSecLab
git checkout feature/academy-react-shell   # for the development-branch experiences; omit for main
cp .env.example .env
./scripts/lab-preflight.sh
./scripts/lab-up.sh
```

The commands above start the **local Docker lab**. **External Splunk** is not started by `lab-up.sh`; see [Local Docker lab](docs/LOCAL_DOCKER_LAB.md).

Open the Academy at <http://127.0.0.1:5001/learn> or Splunk Academy Home at http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home. Pause the lab with `./scripts/lab-down.sh` (it pauses; it does not delete data).

## LIVE and REPLAY

Ollama is the local LLM runtime AgentSec uses for LIVE labs. It is not part of Splunk. **LIVE** labs run a fresh attack. **REPLAY** labs investigate previously captured evidence and do not need Ollama; a REPLAY page is not proof you just ran that attack. See [LIVE vs REPLAY](docs/LIVE_VS_REPLAY.md).

Your first successful experience: open **LAB-MCP-003**, use the Practice tab to predict and reveal the three recorded runs, then follow the [Learner guide](docs/LEARNER_GUIDE.md) into the EVAL, Risk and Governance Centers.

## Documentation

[Documentation index](docs/README.md) · [Getting started](docs/GETTING_STARTED.md) · [Learner guide](docs/LEARNER_GUIDE.md) · [Instructor guide](docs/INSTRUCTOR_GUIDE.md) · [Architecture](docs/ARCHITECTURE_GUIDE.md) · [Evaluation and risk](docs/EVALUATION_AND_RISK_GUIDE.md) · [Governance](docs/GOVERNANCE_GUIDE.md) · [Contributing](CONTRIBUTING.md) · [Full project reference](docs/PROJECT_REFERENCE.md)

## Safety and limitations

- The lab is for **local, educational** use. It intentionally contains vulnerable agent profiles and contains deliberately vulnerable profiles. Do not expose it to the Internet. The default bind address is `127.0.0.1`; see [Remote access](docs/REMOTE_ACCESS.md) before changing it.
- Lab defaults in `.env.example` are not production secrets. Never commit `.env`.
- Recorded evidence shows what happened in one run. It is not a rate, a guarantee or an assessment of any real system.
- Framework relationships are educational links. AgentSecLab makes no compliance or certification claim.
- No run shown in the new Centers has an independent verifier receipt, so they are labelled `NOT_VERIFIED`.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under the Apache License 2.0; see [LICENSE](LICENSE).
